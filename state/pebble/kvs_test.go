/*
Copyright IBM Corp. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package pebble

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"math"
	"strings"
	"testing"

	sdk "github.com/hyperledger/fabric-x-sdk"
)

// update is a test-only entry point into commitBlock for a raw batch of
// writes, not carrying any guarantee of its own: production always goes
// through Handle, which calls commitBlock directly.
func (p *KVS) update(updates []keyValueVersion) error {
	if len(updates) == 0 {
		return nil
	}

	// Sanity check to prevent incorrectly written tests.
	blockNum := updates[0].BlockNum
	for i := range updates {
		if updates[i].BlockNum != blockNum {
			return fmt.Errorf(
				"pebble kvs: update batch spans multiple blocks (%d at index 0, %d at index %d); "+
					"writes must be grouped by block before committing",
				blockNum, updates[i].BlockNum, i)
		}
	}

	return p.commitBlock(blockNum, updates)
}

// TestPebbleUpdateRejectsMultiBlockBatch checks that update, the test-only batch
// primitive, rejects a batch spanning block numbers.
func TestPebbleUpdateRejectsMultiBlockBatch(t *testing.T) {
	kvs, err := Open(t.TempDir(), 8, sdk.NewTestLogger(t, "pebble"))
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	defer func() { _ = kvs.Close() }()

	err = kvs.update([]keyValueVersion{
		{Key: "ns1:a", BlockNum: 1, TxNum: 0, Value: []byte("a")},
		{Key: "ns1:b", BlockNum: 2, TxNum: 0, Value: []byte("b")},
	})
	if err == nil {
		t.Fatal("expected error for multi-block batch, got nil")
	}
	if !strings.Contains(err.Error(), "spans multiple blocks") {
		t.Errorf("error should mention 'spans multiple blocks', got: %v", err)
	}

	if n := mustBlockNumber(t, kvs); n != 0 {
		t.Errorf("expected block 0 (nothing committed), got %d", n)
	}
}

// TestDecodeRecordRejectsHugeLength feeds lengths too large for int: they must be
// reported as corrupt rather than wrap negative and panic on the slice.
func TestDecodeRecordRejectsHugeLength(t *testing.T) {
	huge := binary.AppendUvarint(nil, math.MaxUint64)
	header := []byte{flagValueNonNil, 1, 0, 0} // flags, block, tx, version

	txIDTooLong := append(append(bytes.Clone(header), huge...), 'x')
	if _, err := decodeRecord(txIDTooLong); err == nil {
		t.Error("expected error for an oversized txid length")
	}

	valueTooLong := append(append(append(bytes.Clone(header), 0), huge...), 'x') // empty txid
	if _, err := decodeRecord(valueTooLong); err == nil {
		t.Error("expected error for an oversized value length")
	}
}
