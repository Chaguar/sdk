/*
Copyright IBM Corp. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package fabrictest

import (
	"context"
	"errors"
	"slices"
	"time"

	"github.com/hyperledger/fabric-protos-go-apiv2/common"
	"github.com/hyperledger/fabric-protos-go-apiv2/orderer"
	"github.com/hyperledger/fabric-protos-go-apiv2/peer"
	"github.com/hyperledger/fabric-x-common/api/applicationpb"
	"github.com/hyperledger/fabric-x-common/api/committerpb"
	"github.com/hyperledger/fabric-x-common/protoutil"
	"github.com/hyperledger/fabric-x-sdk/endorsement"
	"github.com/hyperledger/fabric-x-sdk/endorsement/fabric"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/emptypb"
)

func newTestPeer(ledger *ledger) *testPeer {
	return &testPeer{
		ledger:  ledger,
		builder: fabric.NewEndorsementBuilder(MockSigner{}),
	}
}

// testPeer serves Deliver, qscc GetChainInfo and parts of the Fabric-X sidecar.
// Anything else returns codes.Unimplemented.
type testPeer struct {
	peer.UnimplementedDeliverServer
	peer.UnimplementedEndorserServer
	committerpb.UnimplementedSidecarServiceServer
	ledger  *ledger
	builder endorsement.Builder
}

type startKind int

const (
	startOldest startKind = iota
	startSpecified
	startNewest
)

// parseStartBlock extracts the requested start position from the seek envelope.
// The number is only set for startSpecified. Parse errors count as startOldest.
func parseStartBlock(env *common.Envelope) (uint64, startKind) {
	pl := &common.Payload{}
	if err := proto.Unmarshal(env.Payload, pl); err != nil {
		return 0, startOldest
	}
	si := &orderer.SeekInfo{}
	if err := proto.Unmarshal(pl.Data, si); err != nil {
		return 0, startOldest
	}
	if si.Start == nil {
		return 0, startOldest
	}
	switch t := si.Start.Type.(type) {
	case *orderer.SeekPosition_Specified:
		return t.Specified.Number, startSpecified
	case *orderer.SeekPosition_Newest:
		return 0, startNewest
	default:
		return 0, startOldest
	}
}

// Deliver first requires an Envelope of type ab.DELIVER_SEEK_INFO with
// Payload data as a marshaled orderer.SeekInfo message,
// then a stream of block replies is received.
func (p *testPeer) Deliver(stream peer.Deliver_DeliverServer) error {
	env, err := stream.Recv()
	if err != nil {
		return err
	}

	startBlock, kind := parseStartBlock(env)

	// After a restart, blocks before the first one held are not available.
	if kind == startSpecified && startBlock < p.ledger.firstHeld() {
		return stream.Send(&peer.DeliverResponse{
			Type: &peer.DeliverResponse_Status{Status: common.Status_NOT_FOUND},
		})
	}

	// Register as a subscriber and get a snapshot of already-committed blocks.
	// Both happen under the ledger lock so no blocks are lost between the two.
	existing, first, sub := p.ledger.subscribe()

	// Oldest starts at 0, which the filter below turns into the first block held.
	if kind == startNewest {
		// The current tip, or the next block if none is held since a restart.
		startBlock = first
		if len(existing) > 0 {
			startBlock = existing[len(existing)-1].Header.Number
		}
	}

	// Replay historical blocks starting from startBlock.
	for _, block := range existing {
		if block.Header.Number < startBlock {
			continue
		}
		resp := &peer.DeliverResponse{
			Type: &peer.DeliverResponse_Block{Block: block},
		}
		if err := stream.Send(resp); err != nil {
			return err
		}
	}

	// Stream new blocks as they are committed.
	for block := range sub {
		if block.Header.Number < startBlock {
			continue
		}
		resp := &peer.DeliverResponse{
			Type: &peer.DeliverResponse_Block{Block: block},
		}
		if err := stream.Send(resp); err != nil {
			return err
		}
	}

	return nil
}

// -- Fabric

// ProcessProposal implements the Fabric Endorser API for processing proposals.
// It only handles qscc GetChainInfo requests to return blockchain height.
func (p *testPeer) ProcessProposal(ctx context.Context, prop *peer.SignedProposal) (*peer.ProposalResponse, error) {
	// Parse the proposal
	inv, err := fabric.Parse(prop, time.Now())
	if err != nil {
		return nil, err
	}

	// Check if this is a qscc GetChainInfo request
	if inv.Namespace != "qscc" || len(inv.Args) == 0 || string(inv.Args[0]) != "GetChainInfo" {
		return nil, errors.New("only qscc GetChainInfo is supported in fabrictest")
	}

	// Return ProposalResponse with the ledger height and the real chain-tip hashes as
	// payload, just as a Fabric peer would respond. The hashes are the ones in the
	// delivered blocks' headers, so a client can match this reply against them.
	return p.builder.Endorse(inv, endorsement.ExecutionResult{
		Status:  200,
		Payload: protoutil.MarshalOrPanic(p.ledger.chainInfo()),
	})
}

// Fabric-X

// GetBlockchainInfo implements the Fabric-X SidecarService for getting blockchain height
func (p *testPeer) GetBlockchainInfo(ctx context.Context, _ *emptypb.Empty) (*common.BlockchainInfo, error) {
	return p.ledger.chainInfo(), nil
}

// StreamBlocks implements the Fabric-X SidecarService's block feed: it streams a
// BlockEvent for every block committed after subscription, honoring
// StreamBlocksRequest's namespace (OR match) and status filters as well as the
// include_* flags. Like the real committer's sidecar, this is a real-time feed
// with no historical replay, and every block is sent, even when none of its
// transactions match the filters (the BlockEvent then has no events).
//
// Transactions are decoded as Fabric-X applicationpb.Tx; blocks from a "fabric"
// (classic) fabrictest network use a different channel header type and are
// naturally skipped rather than misinterpreted.
func (p *testPeer) StreamBlocks(req *committerpb.StreamBlocksRequest, stream committerpb.SidecarService_StreamBlocksServer) error {
	_, _, sub := p.ledger.subscribe()

	for block := range sub {
		if err := stream.Send(buildBlockEvent(block, req)); err != nil {
			return err
		}
	}

	return nil
}

// buildBlockEvent decodes block into a BlockEvent filtered per req.
// The BlockEvent is returned even if no events match the filters.
func buildBlockEvent(block *common.Block, req *committerpb.StreamBlocksRequest) *committerpb.BlockEvent {
	txFilter := block.Metadata.Metadata[common.BlockMetadataIndex_TRANSACTIONS_FILTER]

	var events []*committerpb.TxEvent
	for txNum, envBytes := range block.Data.Data {
		env := &common.Envelope{}
		if err := proto.Unmarshal(envBytes, env); err != nil {
			continue
		}
		pl := &common.Payload{}
		if err := proto.Unmarshal(env.Payload, pl); err != nil {
			continue
		}
		if pl.Header == nil {
			continue // malformed: a payload without a header carries no channel header
		}
		chdr := &common.ChannelHeader{}
		if err := proto.Unmarshal(pl.Header.ChannelHeader, chdr); err != nil {
			continue
		}
		if chdr.Type != int32(common.HeaderType_MESSAGE) {
			continue // config transaction, or a non-Fabric-X (classic fabric) transaction
		}
		ptx := &applicationpb.Tx{}
		if err := proto.Unmarshal(pl.Data, ptx); err != nil {
			continue
		}

		status := committerpb.Status(txFilter[txNum])
		if !statusMatches(status, req.FilterStatus) {
			continue
		}

		namespaces, touched := filterNamespaces(ptx.Namespaces, req.FilterNamespaces)
		if !touched {
			continue
		}

		event := &committerpb.TxEvent{
			Ref: &committerpb.TxRef{
				BlockNum: block.Header.Number,
				TxNum:    uint32(txNum),
				TxId:     chdr.TxId,
			},
			Status: status,
		}
		if req.IncludeReadWriteSets {
			event.Namespaces = namespaces
		}
		if req.IncludeEndorsements {
			event.Endorsements = ptx.Endorsements
		}
		if req.IncludeMetadata {
			event.Metadata = ptx.Metadata
		}

		events = append(events, event)
	}

	return &committerpb.BlockEvent{Header: block.Header, Events: events}
}

// statusMatches reports whether status passes filter (OR match). An empty filter matches everything.
func statusMatches(status committerpb.Status, filter []committerpb.Status) bool {
	if len(filter) == 0 {
		return true
	}
	return slices.Contains(filter, status)
}

// filterNamespaces returns the subset of all matching filter (OR match) along with whether
// the transaction touches any of them. An empty filter matches every namespace.
func filterNamespaces(all []*applicationpb.TxNamespace, filter []string) ([]*applicationpb.TxNamespace, bool) {
	if len(filter) == 0 {
		return all, true
	}
	set := make(map[string]struct{}, len(filter))
	for _, ns := range filter {
		set[ns] = struct{}{}
	}
	var matching []*applicationpb.TxNamespace
	for _, ns := range all {
		if _, ok := set[ns.NsId]; ok {
			matching = append(matching, ns)
		}
	}
	return matching, len(matching) > 0
}
