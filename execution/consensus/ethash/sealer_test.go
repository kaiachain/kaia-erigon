// Copyright 2018 The go-ethereum Authors
// (original work)
// Copyright 2024 The Erigon Authors
// (modifications)
// This file is part of Erigon.
//
// Erigon is free software: you can redistribute it and/or modify
// it under the terms of the GNU Lesser General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.
//
// Erigon is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
// GNU Lesser General Public License for more details.
//
// You should have received a copy of the GNU Lesser General Public License
// along with Erigon. If not, see <http://www.gnu.org/licenses/>.

package ethash

import (
	"io"
	"math/big"
	"net/http"
	"net/http/httptest"
	"strconv"
	"testing"
	"time"

	"github.com/goccy/go-json"

	"github.com/erigontech/erigon-lib/common"
	"github.com/erigontech/erigon-lib/log/v3"
	"github.com/erigontech/erigon-lib/testlog"
	"github.com/erigontech/erigon-lib/types"
	"github.com/erigontech/erigon/execution/consensus/ethash/ethashcfg"
)

// Tests whether remote HTTP servers are correctly notified of new work.
func TestRemoteNotify(t *testing.T) {
	// Start a simple web server to capture notifications.
	sink := make(chan [3]string)
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		blob, err := io.ReadAll(req.Body)
		if err != nil {
			t.Errorf("failed to read miner notification: %v", err)
		}
		var work [3]string
		if err := json.Unmarshal(blob, &work); err != nil {
			t.Errorf("failed to unmarshal miner notification: %v", err)
		}
		sink <- work
	}))
	defer server.Close()

	// Create the custom ethash engine.
	ethash := NewTester([]string{server.URL}, false)
	defer ethash.Close()

	// Stream a work task and ensure the notification bubbles out.
	header := &types.Header{Number: big.NewInt(1), Difficulty: big.NewInt(100)}
	block := types.NewBlockWithHeader(header)
	blockWithReceipts := &types.BlockWithReceipts{Block: block}

	if err := ethash.Seal(nil, blockWithReceipts, nil, nil); err != nil {
		t.Fatal(err)
	}
	select {
	case work := <-sink:
		if want := ethash.SealHash(header).Hex(); work[0] != want {
			t.Errorf("work packet hash mismatch: have %s, want %s", work[0], want)
		}
		if want := common.BytesToHash(SeedHash(header.Number.Uint64())).Hex(); work[1] != want {
			t.Errorf("work packet seed mismatch: have %s, want %s", work[1], want)
		}
		target := new(big.Int).Div(new(big.Int).Lsh(big.NewInt(1), 256), header.Difficulty)
		if want := common.BytesToHash(target.Bytes()).Hex(); work[2] != want {
			t.Errorf("work packet target mismatch: have %s, want %s", work[2], want)
		}
	case <-time.After(3 * time.Second):
		t.Fatalf("notification timed out")
	}
}

// Tests whether remote HTTP servers are correctly notified of new work. (Full pending block body / --miner.notify.full)
func TestRemoteNotifyFull(t *testing.T) {
	// Start a simple web server to capture notifications.
	sink := make(chan map[string]interface{})
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		blob, err := io.ReadAll(req.Body)
		if err != nil {
			t.Errorf("failed to read miner notification: %v", err)
		}
		var work map[string]interface{}
		if err := json.Unmarshal(blob, &work); err != nil {
			t.Errorf("failed to unmarshal miner notification: %v", err)
		}
		sink <- work
	}))
	defer server.Close()

	// Create the custom ethash engine.
	config := ethashcfg.Config{
		PowMode:    ethashcfg.ModeTest,
		NotifyFull: true,
		Log:        testlog.Logger(t, log.LvlWarn),
	}
	ethash := New(config, []string{server.URL}, false)
	defer ethash.Close()

	// Stream a work task and ensure the notification bubbles out.
	header := &types.Header{Number: big.NewInt(1), Difficulty: big.NewInt(100)}
	block := types.NewBlockWithHeader(header)
	blockWithReceipts := &types.BlockWithReceipts{Block: block}

	if err := ethash.Seal(nil, blockWithReceipts, nil, nil); err != nil {
		t.Fatal(err)
	}
	select {
	case work := <-sink:
		if want := "0x" + strconv.FormatUint(header.Number.Uint64(), 16); work["number"] != want {
			t.Errorf("pending block number mismatch: have %v, want %v", work["number"], want)
		}
		if want := "0x" + header.Difficulty.Text(16); work["difficulty"] != want {
			t.Errorf("pending block difficulty mismatch: have %s, want %s", work["difficulty"], want)
		}
	case <-time.After(3 * time.Second):
		t.Fatalf("notification timed out")
	}
}

// Tests that pushing work packages fast to the miner doesn't cause any data race
// issues in the notifications.
func TestRemoteMultiNotify(t *testing.T) {
	t.Skip("Often fails spuriously, needs to be investiaged")

	// Start a simple web server to capture notifications.
	sink := make(chan [3]string, 64)
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		blob, err := io.ReadAll(req.Body)
		if err != nil {
			t.Errorf("failed to read miner notification: %v", err)
		}
		var work [3]string
		if err := json.Unmarshal(blob, &work); err != nil {
			t.Errorf("failed to unmarshal miner notification: %v", err)
		}
		sink <- work
	}))
	defer server.Close()

	// Create the custom ethash engine.
	ethash := NewTester([]string{server.URL}, false)
	ethash.config.Log = testlog.Logger(t, log.LvlWarn)
	defer ethash.Close()

	// Provide a results reader.
	// Otherwise the unread results will be logged asynchronously
	// and this can happen after the test is finished, causing a panic.
	results := make(chan *types.BlockWithReceipts, cap(sink))

	// Stream a lot of work task and ensure all the notifications bubble out.
	for i := 0; i < cap(sink); i++ {
		header := &types.Header{Number: big.NewInt(int64(i)), Difficulty: big.NewInt(100)}
		block := types.NewBlockWithHeader(header)
		blockWithReceipts := &types.BlockWithReceipts{Block: block}
		err := ethash.Seal(nil, blockWithReceipts, results, nil)
		if err != nil {
			t.Fatal(err)
		}
	}

	for i := 0; i < cap(sink); i++ {
		select {
		case <-sink:
			<-results
		case <-time.After(10 * time.Second):
			t.Fatalf("notification %d timed out", i)
		}
	}
}

// Tests that pushing work packages fast to the miner doesn't cause any data race
// issues in the notifications. Full pending block body / --miner.notify.full)
func TestRemoteMultiNotifyFull(t *testing.T) {
	t.Skip("Often fails spuriously, needs to be investiaged")
	// Start a simple web server to capture notifications.
	sink := make(chan map[string]interface{}, 64)
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		blob, err := io.ReadAll(req.Body)
		if err != nil {
			t.Errorf("failed to read miner notification: %v", err)
		}
		var work map[string]interface{}
		if err := json.Unmarshal(blob, &work); err != nil {
			t.Errorf("failed to unmarshal miner notification: %v", err)
		}
		sink <- work
	}))
	defer server.Close()

	// Create the custom ethash engine.
	config := ethashcfg.Config{
		PowMode:    ethashcfg.ModeTest,
		NotifyFull: true,
		Log:        testlog.Logger(t, log.LvlWarn),
	}
	ethash := New(config, []string{server.URL}, false)
	defer ethash.Close()

	// Provide a results reader.
	// Otherwise the unread results will be logged asynchronously
	// and this can happen after the test is finished, causing a panic.
	results := make(chan *types.BlockWithReceipts, cap(sink))

	// Stream a lot of work task and ensure all the notifications bubble out.
	for i := 0; i < cap(sink); i++ {
		header := &types.Header{Number: big.NewInt(int64(i)), Difficulty: big.NewInt(100)}
		block := types.NewBlockWithHeader(header)
		blockWithReceipts := &types.BlockWithReceipts{Block: block}
		err := ethash.Seal(nil, blockWithReceipts, results, nil)
		if err != nil {
			t.Fatal(err)
		}
	}

	for i := 0; i < cap(sink); i++ {
		select {
		case <-sink:
			<-results
		case <-time.After(10 * time.Second):
			t.Fatalf("notification %d timed out", i)
		}
	}
}

// Tests whether stale solutions are correctly processed.
func TestStaleSubmission(t *testing.T) {
	ethash := NewTester(nil, true)
	defer ethash.Close()
	api := &API{ethash}

	fakeNonce, fakeDigest := types.BlockNonce{0x01, 0x02, 0x03}, common.HexToHash("deadbeef")

	testcases := []struct {
		headers     []*types.Header
		submitIndex int
		submitRes   bool
	}{
		// Case1: submit solution for the latest mining package
		{
			[]*types.Header{
				{ParentHash: common.BytesToHash([]byte{0xa}), Number: big.NewInt(1), Difficulty: big.NewInt(100000000)},
			},
			0,
			true,
		},
		// Case2: submit solution for the previous package but have same parent.
		{
			[]*types.Header{
				{ParentHash: common.BytesToHash([]byte{0xb}), Number: big.NewInt(2), Difficulty: big.NewInt(100000000)},
				{ParentHash: common.BytesToHash([]byte{0xb}), Number: big.NewInt(2), Difficulty: big.NewInt(100000001)},
			},
			0,
			true,
		},
		// Case3: submit stale but acceptable solution
		{
			[]*types.Header{
				{ParentHash: common.BytesToHash([]byte{0xc}), Number: big.NewInt(3), Difficulty: big.NewInt(100000000)},
				{ParentHash: common.BytesToHash([]byte{0xd}), Number: big.NewInt(9), Difficulty: big.NewInt(100000000)},
			},
			0,
			true,
		},
		// Case4: submit very old solution
		{
			[]*types.Header{
				{ParentHash: common.BytesToHash([]byte{0xe}), Number: big.NewInt(10), Difficulty: big.NewInt(100000000)},
				{ParentHash: common.BytesToHash([]byte{0xf}), Number: big.NewInt(17), Difficulty: big.NewInt(100000000)},
			},
			0,
			false,
		},
	}
	results := make(chan *types.BlockWithReceipts, 16)

	for id, c := range testcases {
		for _, h := range c.headers {
			blockWithReceipts := &types.BlockWithReceipts{Block: types.NewBlockWithHeader(h)}
			err := ethash.Seal(nil, blockWithReceipts, results, nil)
			if err != nil {
				t.Fatal(err)
			}
		}
		if res := api.SubmitWork(fakeNonce, ethash.SealHash(c.headers[c.submitIndex]), fakeDigest); res != c.submitRes {
			t.Errorf("case %d submit result mismatch, want %t, get %t", id+1, c.submitRes, res)
		}
		if !c.submitRes {
			continue
		}
		select {
		case resWithReceipts := <-results:
			res := resWithReceipts.Block
			if res.Nonce() != fakeNonce {
				t.Errorf("case %d block nonce mismatch, want %x, get %x", id+1, fakeNonce, res.Nonce())
			}
			if res.MixDigest() != fakeDigest {
				t.Errorf("case %d block digest mismatch, want %x, get %x", id+1, fakeDigest, res.MixDigest())
			}
			if res.Difficulty().Uint64() != c.headers[c.submitIndex].Difficulty.Uint64() {
				t.Errorf("case %d block difficulty mismatch, want %d, get %d", id+1, c.headers[c.submitIndex].Difficulty, res.Difficulty())
			}
			if res.NumberU64() != c.headers[c.submitIndex].Number.Uint64() {
				t.Errorf("case %d block number mismatch, want %d, get %d", id+1, c.headers[c.submitIndex].Number.Uint64(), res.NumberU64())
			}
			if res.ParentHash() != c.headers[c.submitIndex].ParentHash {
				t.Errorf("case %d block parent hash mismatch, want %s, get %s", id+1, c.headers[c.submitIndex].ParentHash.Hex(), res.ParentHash().Hex())
			}
		case <-time.NewTimer(time.Second).C:
			t.Errorf("case %d fetch ethash result timeout", id+1)
		}
	}
}
