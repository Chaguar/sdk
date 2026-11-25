/*
Copyright IBM Corp. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package fabrictest

import (
	"bytes"
	"fmt"
	"net"
	"path/filepath"
	"strconv"
	"testing"
	"time"

	"github.com/hyperledger/fabric-protos-go-apiv2/common"
	"github.com/hyperledger/fabric-protos-go-apiv2/orderer"
	"github.com/hyperledger/fabric-protos-go-apiv2/peer"
	"github.com/hyperledger/fabric-x-common/api/committerpb"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/emptypb"

	"github.com/hyperledger/fabric-x-sdk/network/fabric"
)

func dial(t *testing.T, port int) *grpc.ClientConn {
	t.Helper()
	conn, err := grpc.NewClient(fmt.Sprintf("127.0.0.1:%d", port), grpc.WithTransportCredentials(insecure.NewCredentials()))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { conn.Close() }) //nolint:errcheck,gosec // Best-effort test cleanup.
	return conn
}

// sidecarInfo asks the peer for chain info the Fabric-X way.
func sidecarInfo(t *testing.T, n *Network) *common.BlockchainInfo {
	t.Helper()
	info, err := committerpb.NewSidecarServiceClient(dial(t, n.PeerPort)).GetBlockchainInfo(t.Context(), &emptypb.Empty{})
	if err != nil {
		t.Fatalf("GetBlockchainInfo: %v", err)
	}
	return info
}

// qsccInfo asks the peer for chain info the Fabric way.
func qsccInfo(t *testing.T, n *Network) *common.BlockchainInfo {
	t.Helper()
	prop, err := fabric.NewSignedProposal(MockSigner{}, "mychannel", "qscc", [][]byte{[]byte("GetChainInfo"), []byte("mychannel")})
	if err != nil {
		t.Fatal(err)
	}
	res, err := peer.NewEndorserClient(dial(t, n.PeerPort)).ProcessProposal(t.Context(), prop)
	if err != nil {
		t.Fatalf("ProcessProposal: %v", err)
	}
	info := &common.BlockchainInfo{}
	if err := proto.Unmarshal(res.Response.Payload, info); err != nil {
		t.Fatal(err)
	}
	return info
}

// submit broadcasts a transaction writing key k and waits for its block.
func submit(t *testing.T, n *Network, txID string) *common.Block {
	t.Helper()
	_, _, newBlocks := n.ledger.subscribe()
	stream, err := orderer.NewAtomicBroadcastClient(dial(t, n.OrdererPort)).Broadcast(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	if err := stream.Send(buildEnvelope(t, txID, common.HeaderType_MESSAGE, simpleTx("basic"))); err != nil {
		t.Fatal(err)
	}
	if _, err := stream.Recv(); err != nil {
		t.Fatal(err)
	}
	select {
	case bl := <-newBlocks:
		return bl
	case <-time.After(5 * time.Second):
		t.Fatal("timed out waiting for block")
		return nil
	}
}

func freePort(t *testing.T) int {
	t.Helper()
	lis, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer lis.Close() //nolint:errcheck // Only used to pick a port.
	_, p, _ := net.SplitHostPort(lis.Addr().String())
	port, _ := strconv.Atoi(p)
	return port
}

// restart runs a network on a stored db up to block 3, with a transaction in
// block 1, stops it and starts a new one on the same db and ports. It returns
// the new network and the chain info the old one reported last.
func restart(t *testing.T, networkType string) (*Network, *common.BlockchainInfo) {
	t.Helper()
	cfg := Config{
		OrdererPort: freePort(t),
		PeerPort:    freePort(t),
		DB:          filepath.Join(t.TempDir(), "state.db"),
	}

	a, err := Start(t.Context(), networkType, cfg)
	if err != nil {
		t.Fatalf("Start: %v", err)
	}
	if a.OrdererPort != cfg.OrdererPort || a.PeerPort != cfg.PeerPort {
		t.Fatalf("ports: got %d/%d, want %d/%d", a.OrdererPort, a.PeerPort, cfg.OrdererPort, cfg.PeerPort)
	}
	submit(t, a, "a")
	for range 2 {
		if err := a.CutBlock(t.Context()); err != nil {
			t.Fatal(err)
		}
	}
	info := qsccInfo(t, a)
	a.Stop()

	b, err := Start(t.Context(), networkType, cfg)
	if err != nil {
		t.Fatalf("restart: %v", err)
	}
	return b, info
}

func sameInfo(a, b *common.BlockchainInfo) bool {
	return a.Height == b.Height && bytes.Equal(a.CurrentBlockHash, b.CurrentBlockHash) &&
		bytes.Equal(a.PreviousBlockHash, b.PreviousBlockHash)
}

func TestRestart_ContinuesChainAndState(t *testing.T) {
	for _, networkType := range networkTypes {
		t.Run(networkType, func(t *testing.T) {
			n, before := restart(t, networkType)
			if before.Height != 4 {
				t.Fatalf("height before restart: got %d, want 4", before.Height)
			}
			if got := qsccInfo(t, n); !sameInfo(got, before) {
				t.Errorf("qscc after restart: got %v, want %v", got, before)
			}
			if got := sidecarInfo(t, n); !sameInfo(got, before) {
				t.Errorf("GetBlockchainInfo after restart: got %v, want %v", got, before)
			}
			// The test transaction is in Fabric-X format; classic Fabric skips it.
			if networkType == "fabric-x" {
				if w, err := n.ledger.db.Get("basic", "k"); err != nil || w == nil || w.TxID != "a" {
					t.Errorf("world state after restart: got %+v, %v; want the write of tx a", w, err)
				}
			}

			bl := submit(t, n, "b")
			if bl.Header.Number != 4 || !bytes.Equal(bl.Header.PreviousHash, before.CurrentBlockHash) {
				t.Errorf("first block after restart: number %d, PreviousHash %x; want 4, %x",
					bl.Header.Number, bl.Header.PreviousHash, before.CurrentBlockHash)
			}
		})
	}
}

func TestRestart_Deliver(t *testing.T) {
	n, _ := restart(t, "fabric-x")
	newest := openDeliver(t, n, &orderer.SeekPosition{Type: &orderer.SeekPosition_Newest{Newest: &orderer.SeekNewest{}}})
	if err := n.CutBlock(t.Context()); err != nil {
		t.Fatal(err)
	}
	if got := recvBlock(t, newest).Header.Number; got != 4 {
		t.Errorf("SeekNewest: got block %d, want 4", got)
	}

	oldest := openDeliver(t, n, &orderer.SeekPosition{Type: &orderer.SeekPosition_Oldest{Oldest: &orderer.SeekOldest{}}})
	if got := recvBlock(t, oldest).Header.Number; got != 4 {
		t.Errorf("SeekOldest: got block %d, want 4", got)
	}

	resp, err := openDeliver(t, n, seekSpecified(0)).Recv()
	if err != nil {
		t.Fatal(err)
	}
	if resp.GetStatus() != common.Status_NOT_FOUND {
		t.Errorf("Deliver from 0: got %v, want NOT_FOUND", resp)
	}
}

// Revert can go back before the restart point: the db holds every block's
// header, so the next block chains onto the right one.
func TestRestart_Revert(t *testing.T) {
	n, before := restart(t, "fabric-x")
	for range 2 {
		if err := n.CutBlock(t.Context()); err != nil {
			t.Fatal(err)
		}
	}
	if err := n.Revert(t.Context(), 3); err != nil {
		t.Fatalf("Revert to the restart point: %v", err)
	}
	if got := sidecarInfo(t, n); !sameInfo(got, before) {
		t.Errorf("chain info after Revert(3): got %v, want %v", got, before)
	}

	// before is the chain info at block 3, so its PreviousBlockHash is block 2's.
	if err := n.Revert(t.Context(), 2); err != nil {
		t.Fatalf("Revert before the restart point: %v", err)
	}
	if got := sidecarInfo(t, n); got.Height != 3 || !bytes.Equal(got.CurrentBlockHash, before.PreviousBlockHash) {
		t.Errorf("chain info after Revert(2): got %v, want height 3 and block 2's hash", got)
	}
	if err := n.CutBlock(t.Context()); err != nil {
		t.Fatal(err)
	}
	bl := recvBlock(t, openDeliver(t, n, seekSpecified(3)))
	if bl.Header.Number != 3 || !bytes.Equal(bl.Header.PreviousHash, before.PreviousBlockHash) {
		t.Errorf("block after Revert(2): number %d, PreviousHash %x; want 3, %x",
			bl.Header.Number, bl.Header.PreviousHash, before.PreviousBlockHash)
	}

	// Back to genesis also drops the restored world state.
	if err := n.Revert(t.Context(), 0); err != nil {
		t.Fatalf("Revert to genesis: %v", err)
	}
	if w, err := n.ledger.db.Get("basic", "k"); err != nil || w != nil {
		t.Errorf("world state after Revert(0): got %+v, %v; want nil", w, err)
	}
	if err := n.Revert(t.Context(), 5); err == nil {
		t.Error("Revert beyond the tip: want error")
	}
}
