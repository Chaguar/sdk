/*
Copyright IBM Corp. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

// package fabrictest mimics a minimal Fabric or Fabric-X network for tests.
// It implements the orderer Broadcast API and the peer Deliver endpoint.
package fabrictest

import (
	"context"
	"fmt"
	"sync"

	"github.com/hyperledger/fabric-protos-go-apiv2/common"
	"github.com/hyperledger/fabric-x-common/protoutil"
	"google.golang.org/protobuf/proto"

	"github.com/hyperledger/fabric-x-sdk/blocks"
	"github.com/hyperledger/fabric-x-sdk/state"
)

// ledger represents the blockchain and world state. In this mock setup, the
// orderer appends validated blocks and write records. The peer subscribes to
// receive all new blocks and pushes them through its Deliver endpoint.
//
// Blocks are kept in memory only. The world state is in db, together with the
// header of every block, so a ledger on a stored db continues the chain where
// the previous one stopped; earlier blocks are then not available.
type ledger struct {
	mu        sync.Mutex
	blocks    []*common.Block     // the last len(blocks) blocks, ending at tip
	tip       *common.BlockHeader // header of the last committed block
	subs      []chan *common.Block
	db        *state.RevertibleDB
	parser    blocks.BlockParser
	validator *blocks.MVCCValidator
}

// The tip header is stored in the world state under a reserved key, written in
// the same db transaction as the block's writes. Reverting the db restores it too.
const (
	tipNamespace = "_fabrictest"
	tipKey       = "tip"
)

// newLedger opens a ledger on db. An empty db starts a new chain at the genesis
// block, as a real Fabric or Fabric-X channel does; otherwise the chain continues
// after the stored tip.
func newLedger(ctx context.Context, db *state.RevertibleDB, parser blocks.BlockParser, validator *blocks.MVCCValidator) (*ledger, error) {
	l := &ledger{
		db:        db,
		parser:    parser,
		validator: validator,
	}
	tip, err := l.storedTip()
	if err != nil {
		return nil, err
	}
	if tip != nil {
		l.tip = tip
		return l, nil
	}
	genesis := makeGenesisBlock()
	if err := l.store(ctx, blocks.Block{Number: 0}, genesis.Header); err != nil {
		return nil, err
	}
	l.blocks, l.tip = []*common.Block{genesis}, genesis.Header
	return l, nil
}

// store applies the block's writes and records header as the tip.
func (l *ledger) store(ctx context.Context, bl blocks.Block, header *common.BlockHeader) error {
	bl.Transactions = append(bl.Transactions, blocks.Transaction{
		ID:     "fabrictest-tip",
		Status: blocks.StatusCommitted,
		NsRWS: []blocks.NsReadWriteSet{{
			Namespace: tipNamespace,
			RWS:       blocks.ReadWriteSet{Writes: []blocks.KVWrite{{Key: tipKey, Value: protoutil.MarshalOrPanic(header)}}},
		}},
	})
	return l.db.UpdateWorldState(ctx, bl)
}

// storedTip returns the tip header in db, or nil if there is none.
func (l *ledger) storedTip() (*common.BlockHeader, error) {
	rec, err := l.db.Get(tipNamespace, tipKey)
	if err != nil || rec == nil {
		return nil, err
	}
	header := &common.BlockHeader{}
	if err := proto.Unmarshal(rec.Value, header); err != nil {
		return nil, fmt.Errorf("stored tip: %w", err)
	}
	return header, nil
}

// makeGenesisBlock creates block 0: a config block holding a single CONFIG envelope,
// mirroring the shape Fabric and Fabric-X networks start from. A real network stores
// the channel configuration in it; fabrictest uses an empty channel group with
// sequence zero so parsers can decode it like a real genesis configuration.
//
// Genesis chains onto nothing, so its PreviousHash is nil — as in Fabric, where a
// client walking the chain stops there rather than finding a hash of nothing.
func makeGenesisBlock() *common.Block {
	env := &common.Envelope{
		Payload: protoutil.MarshalOrPanic(&common.Payload{
			Header: &common.Header{
				ChannelHeader: protoutil.MarshalOrPanic(&common.ChannelHeader{
					Type: int32(common.HeaderType_CONFIG),
				}),
			},
			Data: protoutil.MarshalOrPanic(&common.ConfigEnvelope{
				Config: &common.Config{ChannelGroup: &common.ConfigGroup{}},
			}),
		}),
	}
	return makeBlock(0, nil, []*common.Envelope{env})
}

// process validates the batch of transactions and stores them in a block.
// Transactions are validated in order; a valid transaction's writes are recorded
// as pending so that later transactions in the same block can detect intra-block
// MVCC conflicts (first writer wins, matching real Fabric semantics).
func (l *ledger) process(ctx context.Context, env []*common.Envelope) error {
	// the number for the current block, and the header hash it chains onto
	// (process is only called synchronously).
	blockNum, prevHash := l.next()

	// create block in fabric format just so we can parse it again. The status code in txFilter will be updated later.
	fbl := makeBlock(blockNum, prevHash, env)

	// get the read/write set and transaction id. We don't care about the other fields.
	bl, err := l.parser.Parse(fbl)
	if err != nil {
		return err // should not happen
	}

	// Parse already set each tx.Number to its position in the block; don't renumber
	// by slice index, which drifts whenever Parse drops a config or malformed tx.

	// Validate all transactions; updates bl.Transactions[i].Status and returns txFilter.
	txFilter, err := l.validator.Validate(&bl)
	if err != nil {
		return err
	}

	// txFilter is indexed by position in bl.Transactions, which omits any transaction
	// Parse dropped, so scatter the statuses back to their block positions rather than
	// copying wholesale. Dropped positions keep their zero (unspecified) status.
	blockFilter := fbl.Metadata.Metadata[common.BlockMetadataIndex_TRANSACTIONS_FILTER]
	for i, status := range txFilter {
		blockFilter[bl.Transactions[i].Number] = status
	}

	// commit them to the ledger
	return l.commit(ctx, bl, fbl)
}

// makeBlock creates a minimal block that chains onto prevHash, which is the header
// hash of block blockNum-1 (nil for genesis).
//
// The header carries the same two hashes a real ledger computes, the way Fabric's own
// blockledger.CreateNextBlock does it: DataHash over the marshaled envelopes and
// PreviousHash over the preceding header. Clients that walk the chain or recompute a
// block hash therefore see a consistent chain rather than placeholders. Block metadata
// is deliberately outside DataHash in Fabric, so filling in the txFilter afterwards
// does not invalidate the header.
func makeBlock(blockNum uint64, prevHash []byte, envs []*common.Envelope) *common.Block {
	data := make([][]byte, len(envs))
	for i, env := range envs {
		b, _ := proto.Marshal(env)
		data[i] = b
	}
	blockData := &common.BlockData{Data: data}

	return &common.Block{
		Header: &common.BlockHeader{
			Number:       blockNum,
			PreviousHash: prevHash,
			// ComputeBlockDataHash rather than BlockDataHash: the latter first
			// insists the transactions are well formed, which rejects the empty
			// blocks cutBlock produces and fabrictest's placeholder signatures.
			DataHash: protoutil.ComputeBlockDataHash(blockData),
		},
		// Data contains the original transactions.
		Data: blockData,
		// Metadata: signatures, last_config [deprecated], transactions_filter.
		// Pre-allocate the txFilter so we can copy in the actual statuses later.
		Metadata: &common.BlockMetadata{Metadata: [][]byte{{}, {}, make([]byte, len(envs))}},
	}
}

// commit applies the block's writes to the world state and adds the block.
func (l *ledger) commit(ctx context.Context, bl blocks.Block, fbl *common.Block) error {
	if err := l.store(ctx, bl, fbl.Header); err != nil {
		return err
	}

	l.mu.Lock()
	defer l.mu.Unlock()

	l.blocks = append(l.blocks, fbl)
	l.tip = fbl.Header

	// Notify under the same lock as close(), so a commit racing with Stop()
	// either completes before subs is nilled and its channels closed, or sees
	// the post-close state (nil subs, zero iterations) — never a half-closed one.
	for _, ch := range l.subs {
		select {
		case ch <- fbl:
		default:
		}
	}
	return nil
}

// truncate drops every block after num, from the chain and the world state, so
// the next block takes number num+1. Other subscribers must rewind their own
// state. num may be before the blocks held since a restart: the db has every
// block's header.
func (l *ledger) truncate(num uint64) error {
	l.mu.Lock()
	defer l.mu.Unlock()
	if num > l.tip.Number {
		return fmt.Errorf("cannot revert to block %d: height is %d", num, l.tip.Number+1)
	}
	if err := l.db.RevertToBlock(num); err != nil {
		return err
	}
	tip, err := l.storedTip()
	if err != nil {
		return err
	}
	if first := l.first(); num+1 < first {
		l.blocks = nil
	} else {
		l.blocks = l.blocks[:num+1-first]
	}
	l.tip = tip
	return nil
}

// first is the number of the first block held, or of the next block if none
// are. Requires l.mu.
func (l *ledger) first() uint64 {
	return l.tip.Number + 1 - uint64(len(l.blocks))
}

// firstHeld is first, under the lock.
func (l *ledger) firstHeld() uint64 {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.first()
}

// subscribe is used by the peer to get blocks. It returns a snapshot of all
// blocks held, the number of the first one, and a channel for new blocks.
// All are taken atomically under the lock so no committed blocks are lost.
func (l *ledger) subscribe() ([]*common.Block, uint64, chan *common.Block) {
	l.mu.Lock()
	defer l.mu.Unlock()

	ch := make(chan *common.Block, 10)
	l.subs = append(l.subs, ch)

	existing := make([]*common.Block, len(l.blocks))
	copy(existing, l.blocks)

	return existing, l.first(), ch
}

// height is the block height. As in Fabric, the next block to be cut takes this number.
func (l *ledger) height() uint64 {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.tip.Number + 1
}

// next reports the number the next block takes and the header hash it must chain
// onto. Both come from one critical section so a block can never be numbered off
// one tip and chained onto another.
func (l *ledger) next() (uint64, []byte) {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.tip.Number + 1, protoutil.BlockHeaderHash(l.tip)
}

// chainInfo reports what a real ledger reports for the chain tip. PreviousBlockHash
// is empty while genesis is the tip.
func (l *ledger) chainInfo() *common.BlockchainInfo {
	l.mu.Lock()
	defer l.mu.Unlock()
	return &common.BlockchainInfo{
		Height:            l.tip.Number + 1,
		CurrentBlockHash:  protoutil.BlockHeaderHash(l.tip),
		PreviousBlockHash: l.tip.PreviousHash,
	}
}

// close shuts down the ledger by closing all subscriber channels (which causes
// goroutines blocked in Deliver to exit) and closing the world-state db.
func (l *ledger) close() {
	l.mu.Lock()
	defer l.mu.Unlock()
	for _, ch := range l.subs {
		close(ch)
	}
	l.subs = nil
	l.db.Close() //nolint:errcheck,gosec // Best-effort cleanup of the test ledger.
}
