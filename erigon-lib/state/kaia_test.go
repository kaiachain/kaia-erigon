// Copyright 2025 The Kaia Authors
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

package state

import (
	"context"
	"fmt"
	"os"
	"sync"
	"testing"

	"github.com/erigontech/erigon-lib/commitment"
	"github.com/erigontech/erigon-lib/common"
	"github.com/erigontech/erigon-lib/common/datadir"
	"github.com/erigontech/erigon-lib/common/hexutil"
	"github.com/erigontech/erigon-lib/kv"
	"github.com/erigontech/erigon-lib/kv/mdbx"
	"github.com/erigontech/erigon-lib/log/v3"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

type kaiaDBM struct {
	mu sync.Mutex

	dbOpen bool
	db     kv.RwDB
	agg    *Aggregator

	txOpen bool
	ac     *AggregatorRoTx
	tx     kv.RwTx
	sd     *SharedDomains
}

func OpenKaiaDBM(t *testing.T, dirs datadir.Dirs) *kaiaDBM {
	db, agg := openKaiaMdbx(t, dirs)
	return &kaiaDBM{
		db:     db,
		agg:    agg,
		dbOpen: true,
	}
}

func (k *kaiaDBM) Close() {
	k.mu.Lock()
	defer k.mu.Unlock()

	if k.txOpen {
		k.sd.Close()
		k.tx.Rollback()
		k.ac.Close()
	}
	if k.dbOpen {
		k.agg.Close()
		k.db.Close()
	}
}

func (k *kaiaDBM) WithTx(t *testing.T, f func(sd *SharedDomains) bool) {
	k.mu.Lock()
	defer k.mu.Unlock()

	sd := k.borrowMdbxTx(t)
	commit := f(sd)
	k.returnMdbxTx(t, commit)
}

func (k *kaiaDBM) borrowMdbxTx(t *testing.T) *SharedDomains {
	k.txOpen = true

	sd, tx, ac := openKaiaSharedDomain(t, k.db, k.agg)
	k.ac = ac
	k.tx = tx
	k.sd = sd
	return sd
}

func (k *kaiaDBM) returnMdbxTx(t *testing.T, commit bool) {
	if commit {
		require.NoError(t, k.sd.Flush(context.Background(), k.tx))
		k.sd.Close()
		require.NoError(t, k.tx.Commit())
		k.ac.Close()
	} else {
		k.sd.Close()
		k.tx.Rollback()
		k.ac.Close()
	}
	k.txOpen = false
}

func openKaiaMdbx(t *testing.T, dirs datadir.Dirs) (kv.RwDB, *Aggregator) {
	logger := log.New() // TODO-Kaia: use kaia logger

	db, err := mdbx.New(kv.ChainDB, logger).
		InMem(dirs.Chaindata). // path to persisted data
		GrowthStep(32 * 1024 * 1024).
		MapSize(2 * 1024 * 1024 * 1024).
		Open(context.Background())
	require.NoError(t, err)

	aggStep := uint64(10) // ??
	agg, err := NewAggregator2(context.Background(), dirs, aggStep, db, logger)
	require.NoError(t, err)
	err = agg.OpenFolder() // ??
	require.NoError(t, err)
	agg.DisableFsync() // ??

	return db, agg
}

func openKaiaSharedDomain(t *testing.T, db kv.RwDB, agg *Aggregator) (*SharedDomains, kv.RwTx, *AggregatorRoTx) {
	logger := log.New() // TODO-Kaia: use kaia logger

	tx, err := db.BeginRw(context.Background())
	require.NoError(t, err)

	aggCtx := agg.BeginFilesRo()
	wrappedTx := WrapTxWithCtx(tx, aggCtx)
	sd, err := NewSharedDomains(wrappedTx, logger)
	require.NoError(t, err)
	require.NotNil(t, sd)
	return sd, tx, aggCtx
}

func TestKaiaDBM(t *testing.T) {
	dirs := datadir.New(t.TempDir()) // TODO-Kaia: use $DATADIR/klay/chaindata/flattrie
	os.MkdirAll(dirs.Chaindata, 0755)
	fmt.Printf("dirs.Chaindata: %s\n", dirs.Chaindata)

	dbm := OpenKaiaDBM(t, dirs)
	defer dbm.Close()

	dbm.WithTx(t, func(sd *SharedDomains) bool {
		sd.DomainPut(kv.AccountsDomain, []byte("11"), nil, []byte("1111"), nil, 0)
		return true
	})

	dbm.WithTx(t, func(sd *SharedDomains) bool {
		sd.DomainPut(kv.AccountsDomain, []byte("22"), nil, []byte("2222"), nil, 0)
		return false
	})

	dbm.WithTx(t, func(sd *SharedDomains) bool {
		v, _, _ := sd.GetLatest(kv.AccountsDomain, []byte("11"))
		assert.Equal(t, v, []byte("1111"))
		v, _, _ = sd.GetLatest(kv.AccountsDomain, []byte("22"))
		assert.Equal(t, v, ([]byte)(nil))
		return false
	})
}

type kaiaPatriciaContext struct {
	sdc             *SharedDomainsCommitmentContext
	pendingAccounts map[string][]byte
	pendingBranches map[string][]byte
}

func (ctx *kaiaPatriciaContext) Branch(prefix []byte) ([]byte, uint64, error) {
	if ctx.pendingBranches != nil {
		if data, ok := ctx.pendingBranches[string(prefix)]; ok {
			return data, 0, nil
		}
	}
	return ctx.sdc.Branch(prefix)
}

func (ctx *kaiaPatriciaContext) PutBranch(prefix []byte, data []byte, prevData []byte, prevStep uint64) error {
	if ctx.pendingBranches != nil {
		ctx.pendingBranches[string(prefix)] = data
	}
	return nil
}

func (ctx *kaiaPatriciaContext) Account(plainKey []byte) (*commitment.Update, error) {
	if ctx.pendingAccounts != nil {
		if data, ok := ctx.pendingAccounts[string(plainKey)]; ok {
			rawBytes := make([]byte, len(data))
			copy(rawBytes, data)
			return &commitment.Update{
				CodeHash: commitment.EmptyCodeHashArray,
				Flags:    commitment.RawBytesUpdate,
				RawBytes: rawBytes,
			}, nil
		}
	}
	fmt.Println("Reading account from db")
	return ctx.sdc.Account(plainKey)
}

func (ctx *kaiaPatriciaContext) Storage(plainKey []byte) (*commitment.Update, error) {
	// TODO-Kaia: pendingStorage
	return ctx.sdc.Storage(plainKey)
}

type incrementalAccountsTC []struct {
	addressHex          string
	accountHex          string
	intermediateRootHex string
}

type kaiaTrie struct {
	dbm      *kaiaDBM
	root     common.Hash
	hphState []byte

	mu              sync.RWMutex
	pendingAccounts map[string][]byte
	pendingBranches map[string][]byte
}

func (trie *kaiaTrie) getInjectedTrie(sd *SharedDomains) (*SharedDomainsCommitmentContext, *commitment.HexPatriciaHashed) {
	sdCtx := sd.GetCommitmentContext()
	injectedCtx := &kaiaPatriciaContext{
		sdc:             sdCtx,
		pendingAccounts: trie.pendingAccounts,
		pendingBranches: trie.pendingBranches,
	}

	hph := sdCtx.Trie().(*commitment.HexPatriciaHashed)
	hph.ResetContext(injectedCtx)
	hph.SetState(trie.hphState)
	return sdCtx, hph
}

func (trie *kaiaTrie) getAccount(t *testing.T, key []byte) []byte {
	trie.mu.RLock()
	defer trie.mu.RUnlock()

	if val, ok := trie.pendingAccounts[string(key)]; ok {
		return val
	}

	var result []byte
	trie.dbm.WithTx(t, func(sd *SharedDomains) bool {
		val, _, err := sd.GetLatest(kv.AccountsDomain, key)
		if err == nil {
			result = val
		}
		return false
	})
	return result
}

func (trie *kaiaTrie) updateAccount(t *testing.T, key, val []byte) {
	trie.mu.Lock()
	defer trie.mu.Unlock()

	trie.pendingAccounts[string(key)] = val

	// TODO: defer hash calculation to trie.Hash() and trie.Commit().
	trie.dbm.WithTx(t, func(sd *SharedDomains) bool {
		sdCtx, hph := trie.getInjectedTrie(sd)
		sdCtx.TouchKey(kv.AccountsDomain, string(key), val)

		root, err := sd.ComputeCommitment(context.Background(), false, 0, "")
		require.NoError(t, err)

		trie.root = common.BytesToHash(root)
		trie.hphState, err = hph.EncodeCurrentState(nil)
		require.NoError(t, err)
		return false
	})
}

func (trie *kaiaTrie) Hash() common.Hash {
	trie.mu.RLock()
	defer trie.mu.RUnlock()

	return trie.root
}

func (trie *kaiaTrie) Commit(t *testing.T) { // TODO-Kaia: return hash, err
	trie.mu.Lock()
	defer trie.mu.Unlock()

	trie.dbm.WithTx(t, func(sd *SharedDomains) bool {
		for key, val := range trie.pendingAccounts {
			sd.DomainPut(kv.AccountsDomain, []byte(key), nil, val, nil, 0)
		}
		trie.pendingAccounts = make(map[string][]byte)
		for key, val := range trie.pendingBranches {
			sd.DomainPut(kv.CommitmentDomain, []byte(key), nil, val, nil, 0)
		}
		trie.pendingBranches = make(map[string][]byte)
		return true
	})
}

func TestKaiaTrie(t *testing.T) {
	commitment.CurrentAccountDeserialiseMode = commitment.AccountDeserialiseModeKaia

	dirs := datadir.New(t.TempDir()) // TODO-Kaia: use $DATADIR/klay/chaindata/flattrie
	os.MkdirAll(dirs.Chaindata, 0755)
	fmt.Printf("dirs.Chaindata: %s\n", dirs.Chaindata)

	dbm := OpenKaiaDBM(t, dirs)
	defer dbm.Close()

	// Kairos block #1 state, Kaia RLP encoding / incremental (3/3)
	tc := incrementalAccountsTC{
		{"0x0000000000000000000000000000000000000400", "0x02f849c580808003c0a056e81f171bcc55a6ff8345e692c0f86e5b48e01b996cadc001622fb5e363b421a06c39846f5ab402760078b7bfd16c99e687c75bcb5ec65ac8f3054bad18136f0980", "0xfbf14f63f97468e460a42b309bbad44fdc682ab3a7f95fa5d3508c9cf0009946"},
		{"0x4937a6f664630547f6b0c3c235c4f03a64ca36b1", "0x01da8095446c3b15f9926687d2c40534fdb5640000000000008001c0", "0xbe751ffacf5fcf9998d4f90b87164ff95166d55e445c8d27cfecbe0e67a032b6"},
		{"0xb74ff9dea397fe9e231df545eb53fe2adf776cb2", "0x01cd8088853a0d2313c000008001c0", "0x60e8f25e2fb479e625347c1f11e2f07c9cd7d0a5320013294d89281b6fceed4f"},
	}
	updateTC := func(trie *kaiaTrie, tc incrementalAccountsTC, i int) {
		account := tc[i]
		trie.updateAccount(t, hexutil.MustDecode(account.addressHex), hexutil.MustDecode(account.accountHex))
		assert.Equal(t, common.HexToHash(account.intermediateRootHex), trie.Hash(), account.addressHex)
	}
	getTC := func(trie *kaiaTrie, tc incrementalAccountsTC, i int) {
		account := tc[i]
		val := trie.getAccount(t, hexutil.MustDecode(account.addressHex))
		assert.Equal(t, val, hexutil.MustDecode(account.accountHex), account.addressHex)
	}

	// Open first trie
	trie1 := &kaiaTrie{
		dbm:             dbm,
		root:            common.BytesToHash(commitment.EmptyRootHash),
		pendingAccounts: make(map[string][]byte),
		pendingBranches: make(map[string][]byte),
	}

	updateTC(trie1, tc, 0)
	updateTC(trie1, tc, 1)
	getTC(trie1, tc, 0)
	getTC(trie1, tc, 1)

	trie1.Commit(t) // testing commit in the middle

	updateTC(trie1, tc, 2)
	getTC(trie1, tc, 0)
	getTC(trie1, tc, 1)
	getTC(trie1, tc, 2)

	trie1.Commit(t)

	// Open second trie
	trie2 := &kaiaTrie{
		dbm:             dbm,
		root:            common.BytesToHash(commitment.EmptyRootHash),
		pendingAccounts: make(map[string][]byte),
		pendingBranches: make(map[string][]byte),
	}

	getTC(trie2, tc, 0)
	getTC(trie2, tc, 1)
	getTC(trie2, tc, 2)
	updateTC(trie2, tc, 2)
}
