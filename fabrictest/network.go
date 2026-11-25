/*
Copyright IBM Corp. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package fabrictest

import (
	"cmp"
	"context"
	"errors"
	"fmt"
	"net"
	"strconv"
	"sync"
	"time"

	"github.com/hyperledger/fabric-protos-go-apiv2/orderer"
	"github.com/hyperledger/fabric-protos-go-apiv2/peer"
	"github.com/hyperledger/fabric-x-common/api/committerpb"
	sdk "github.com/hyperledger/fabric-x-sdk"
	"google.golang.org/grpc"

	"github.com/hyperledger/fabric-x-sdk/blocks"
	"github.com/hyperledger/fabric-x-sdk/blocks/fabric"
	"github.com/hyperledger/fabric-x-sdk/blocks/fabricx"
	"github.com/hyperledger/fabric-x-sdk/state"
)

// Config configures the network that Start runs: block cutting, ports and the world state db.
type Config struct {
	// BlockCutTime is the maximum time to wait before cutting a block (0 = cut immediately).
	BlockCutTime time.Duration
	// MaxTxPerBlock is the maximum number of transactions per block (0 = no limit).
	MaxTxPerBlock int
	// OrdererPort is the port of the orderer (0 = random)
	OrdererPort int
	// PeerPort is the port of the peer (0 = random)
	PeerPort int
	// DB is the SQLite connection string of the world state ("" = in memory).
	// With a stored db, a restarted network continues the chain where the last
	// one stopped. Blocks from before the restart are not available.
	DB string
}

// Network is a wrapper for a minimal mock Fabric.
// Embed Network in a test and use PeerPort and OrdererPort as endpoints on localhost.
type Network struct {
	PeerPort    int
	OrdererPort int
	oSrv        *grpc.Server
	pSrv        *grpc.Server
	orderer     *testOrderer
	ledger      *ledger
	stopOnce    sync.Once
}

// Start creates grpc servers for the peer and orderer on localhost, on the ports
// in cfg (random by default). The servers are stopped when ctx is cancelled.
func Start(ctx context.Context, networkType string, cfg Config) (*Network, error) {
	logger := sdk.NewStdLogger("fabrictest")

	// some specifics for either fabric or fabric-x
	var parser blocks.BlockParser
	var newValidator func(blocks.RecordGetter, sdk.Logger) *blocks.MVCCValidator

	switch networkType {
	case "fabric":
		parser, newValidator = fabric.NewBlockParser(logger), fabric.NewMVCCValidator
	case "fabric-x":
		parser, newValidator = fabricx.NewBlockParser(logger), fabricx.NewMVCCValidator
	default:
		return nil, errors.New("networkType must be fabric or fabric-x")
	}

	db, err := state.NewRevertibleDB("mychannel", cmp.Or(cfg.DB, ":memory:"))
	if err != nil {
		return nil, err
	}
	l, err := newLedger(ctx, db, parser, newValidator(db, logger))
	if err != nil {
		db.Close() //nolint:errcheck,gosec // Preserve the ledger error.
		return nil, err
	}

	ordererLis, oPort, err := listen(cfg.OrdererPort)
	if err != nil {
		l.close()
		return nil, err
	}
	peerLis, pPort, err := listen(cfg.PeerPort)
	if err != nil {
		ordererLis.Close() //nolint:errcheck,gosec // Preserve the listen error.
		l.close()
		return nil, err
	}

	n := &Network{
		OrdererPort: oPort,
		PeerPort:    pPort,
		oSrv:        grpc.NewServer(),
		pSrv:        grpc.NewServer(),
	}

	// ledger ties it together by storing blocks and the world state db
	n.ledger = l
	n.orderer = newTestOrderer(n.ledger, cfg)

	// grpc endpoints
	testPeer := newTestPeer(n.ledger)
	orderer.RegisterAtomicBroadcastServer(n.oSrv, n.orderer)
	peer.RegisterDeliverServer(n.pSrv, testPeer)
	peer.RegisterEndorserServer(n.pSrv, testPeer)
	committerpb.RegisterSidecarServiceServer(n.pSrv, testPeer)

	go func() {
		if err := n.oSrv.Serve(ordererLis); err != nil {
			logger.Errorf("orderer server stopped: %v", err)
		}
	}()
	go func() {
		if err := n.pSrv.Serve(peerLis); err != nil {
			logger.Errorf("peer server stopped: %v", err)
		}
	}()
	go func() {
		<-ctx.Done()
		n.Stop()
	}()

	return n, nil
}

func listen(port int) (net.Listener, int, error) {
	lis, err := net.Listen("tcp", fmt.Sprintf("127.0.0.1:%d", port))
	if err != nil {
		return nil, 0, err
	}
	_, actualPort, err := net.SplitHostPort(lis.Addr().String())
	if err != nil {
		lis.Close() //nolint:errcheck,gosec // Preserve the address parsing error.
		return nil, 0, err
	}
	p, err := strconv.Atoi(actualPort)
	if err != nil {
		lis.Close() //nolint:errcheck,gosec // Preserve the port parsing error.
		return nil, 0, err
	}
	return lis, p, nil
}

// CutBlock cuts a new block with no transactions, advancing block height by one.
func (n *Network) CutBlock(ctx context.Context) error {
	return n.orderer.cutBlock(ctx)
}

// Revert truncates the chain and world state so num is the last block; the next
// block cut takes number num+1. Pending transactions not yet in a block are
// dropped. Open Deliver streams continue with the new block num+1, so consumers
// must rewind their own state to num.
func (n *Network) Revert(ctx context.Context, num uint64) error {
	return n.orderer.revert(ctx, num)
}

// Stop shuts down the orderer and peer gRPC servers. It is safe to call more
// than once, e.g. explicitly and again when ctx is cancelled.
func (n *Network) Stop() {
	n.stopOnce.Do(func() {
		n.oSrv.Stop()
		n.pSrv.Stop()
		n.orderer.stop()
		n.ledger.close()
	})
}
