/*
Copyright IBM Corp. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package fabrictest

import (
	"fmt"
	"testing"
	"time"

	"github.com/hyperledger/fabric-protos-go-apiv2/common"
	"github.com/hyperledger/fabric-protos-go-apiv2/orderer"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
)

func TestRevert_NextBlockReusesNumber(t *testing.T) {
	n, err := Start(t.Context(), "fabric-x", Config{})
	if err != nil {
		t.Fatalf("Start: %v", err)
	}
	for range 3 {
		if err := n.CutBlock(t.Context()); err != nil {
			t.Fatal(err)
		}
	}
	// blocks 0..3 exist; rewind to 1.
	_, _, newBlocks := n.ledger.subscribe()
	if err := n.Revert(t.Context(), 1); err != nil {
		t.Fatalf("Revert: %v", err)
	}
	if got := n.ledger.height(); got != 2 {
		t.Fatalf("height after Revert: got %d, want 2", got)
	}
	if err := n.CutBlock(t.Context()); err != nil {
		t.Fatal(err)
	}
	select {
	case bl := <-newBlocks:
		if bl.Header.Number != 2 {
			t.Errorf("block number after revert: got %d, want 2", bl.Header.Number)
		}
	case <-time.After(time.Second):
		t.Fatal("timed out waiting for the cut block")
	}

	if err := n.Revert(t.Context(), 5); err == nil {
		t.Error("Revert beyond height: want error")
	}
}

// A different transaction can take a reverted block's number, and the world
// state no longer holds the reverted block's writes.
func TestRevert_ReplacesBlockWithDifferentTx(t *testing.T) {
	n, err := Start(t.Context(), "fabric-x", Config{})
	if err != nil {
		t.Fatalf("Start: %v", err)
	}
	conn, err := grpc.NewClient(fmt.Sprintf("127.0.0.1:%d", n.OrdererPort), grpc.WithTransportCredentials(insecure.NewCredentials()))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { conn.Close() }) //nolint:errcheck,gosec // Best-effort test cleanup.
	client := orderer.NewAtomicBroadcastClient(conn)
	_, _, newBlocks := n.ledger.subscribe()

	commit := func(txID string) *common.Block {
		t.Helper()
		stream, err := client.Broadcast(t.Context())
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
		case <-time.After(time.Second):
			t.Fatal("timed out waiting for block")
			return nil
		}
	}

	if bl := commit("a"); bl.Header.Number != 1 {
		t.Fatalf("first block = %d, want 1", bl.Header.Number)
	}
	if err := n.Revert(t.Context(), 0); err != nil {
		t.Fatalf("Revert: %v", err)
	}
	if w, err := n.ledger.db.Get("basic", "k"); err != nil || w != nil {
		t.Fatalf("world state after revert: got %+v, %v; want nil", w, err)
	}
	if bl := commit("b"); bl.Header.Number != 1 {
		t.Fatalf("block after revert = %d, want 1", bl.Header.Number)
	}
	if w, err := n.ledger.db.Get("basic", "k"); err != nil || w == nil || w.TxID != "b" {
		t.Fatalf("world state after replacement: got %+v, %v; want tx b", w, err)
	}
}
