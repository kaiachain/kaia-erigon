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

package kaiatrie

import (
	"context"
	"errors"
	"fmt"
	"sync/atomic"

	lru "github.com/hashicorp/golang-lru/v2"

	"github.com/erigontech/erigon-lib/commitment"
	"github.com/erigontech/erigon-lib/crypto"
	"github.com/erigontech/erigon-lib/kv"
	"github.com/erigontech/erigon-lib/state"
	"github.com/erigontech/erigon-lib/types/accounts"
)

var (
	_ commitment.PatriciaContext = (*DeferredContext)(nil)

	keyHphState  = []byte("hphstate")
	errNotLatest = errors.New("cannot operate on non-latest commitment state")

	traceId atomic.Uint32 // To distinguish different instances of DeferredContext
)

type AccountMode uint8

const (
	ModeErigonV3 AccountMode = 0
	ModeRawBytes AccountMode = 1
)

type pendingBranch struct {
	data     []byte
	prevData []byte
	prevStep uint64
}

type DeferredContext struct {
	// Underlying database.
	dm *DomainsManager

	// Configuration.
	accountMode AccountMode
	readNum     uint64 // block number to read from
	writeNum    uint64 // block number to write to
	trace       bool
	traceId     uint32

	// Unhashed and uncommitted changes.
	pendingUpdates *commitment.Updates

	// Keeping the HPH's internal state across sync.Pool instances
	lastHphState        []byte
	lastStorageRootHash map[string][]byte

	// Uncommitted changes.
	pendingAccounts map[string][]byte        // addr[20] => SerialiseV3 (ModeErigonV3) or RawBytes (ModeRawBytes)
	pendingStorages map[string][]byte        // addr[20] || slot[32] => data[32]
	pendingBranches map[string]pendingBranch // prefix[] => data[], prevData[], prevStep

	// Committed to `writeNum` changes.
	committedAccounts map[string][]byte
	committedStorages map[string][]byte
	committedBranches map[string]pendingBranch

	// Cache before DomainsReader
	cachedAccounts *lru.Cache[string, []byte]
	cachedStorages *lru.Cache[string, []byte]
	cachedBranches *lru.Cache[string, pendingBranch]
}

func NewDeferredContext(dm *DomainsManager, tmpdir string, accountMode AccountMode, readNum, writeNum uint64) *DeferredContext {
	cachedAccounts, _ := lru.New[string, []byte](1024)
	cachedStorages, _ := lru.New[string, []byte](1024)
	cachedBranches, _ := lru.New[string, pendingBranch](1024)

	return &DeferredContext{
		dm: dm,

		accountMode: accountMode,
		readNum:     readNum,
		writeNum:    writeNum,
		traceId:     traceId.Add(1),

		pendingUpdates:      commitment.NewUpdates(commitment.ModeDirect, tmpdir, commitment.KeyToHexNibbleHash),
		lastStorageRootHash: make(map[string][]byte),

		pendingAccounts: make(map[string][]byte),
		pendingStorages: make(map[string][]byte),
		pendingBranches: make(map[string]pendingBranch),

		committedAccounts: make(map[string][]byte),
		committedStorages: make(map[string][]byte),
		committedBranches: make(map[string]pendingBranch),

		cachedAccounts: cachedAccounts,
		cachedStorages: cachedStorages,
		cachedBranches: cachedBranches,
	}
}

func (dc *DeferredContext) SetTrace(trace bool) {
	dc.trace = trace
}

func (dc *DeferredContext) SetReadNum(readNum uint64) {
	dc.readNum = readNum
}

func (c *DeferredContext) tracef(format string, args ...any) {
	if c.trace {
		msg := fmt.Sprintf(format, args...)
		fmt.Printf("[%10d] %s", c.traceId, msg)
	}
}

// Deferred Put and Get functions.

func (c *DeferredContext) PutAccount(plainKey []byte, encAccount []byte) {
	c.pendingUpdates.TouchPlainKey(string(plainKey), encAccount, c.pendingUpdates.TouchAccount)
	c.pendingAccounts[string(plainKey)] = encAccount
	c.tracef("ctx.PutAccount %x: %x (#%d)\n", plainKey, encAccount, c.pendingUpdates.Size())
}

func (c *DeferredContext) PutStorage(plainKey []byte, encStorage []byte) {
	c.pendingUpdates.TouchPlainKey(string(plainKey), encStorage, c.pendingUpdates.TouchStorage)
	c.pendingStorages[string(plainKey)] = encStorage
	c.tracef("ctx.PutStorage %x: %x (#%d)\n", plainKey, encStorage, c.pendingUpdates.Size())
}

func (c *DeferredContext) putBranch(prefix []byte, data []byte, prevData []byte, prevStep uint64) error {
	c.tracef("ctx.PutBranch %x: %x, %d\n", prefix, data, prevStep)
	c.pendingBranches[string(prefix)] = pendingBranch{
		data:     data,
		prevData: prevData,
		prevStep: prevStep,
	}
	return nil
}

func (c *DeferredContext) GetAccount(addr []byte) ([]byte, error) {
	if data, ok := c.pendingAccounts[string(addr)]; ok {
		c.tracef("ctx.GetAccount(pending) %x: %x\n", addr, data)
		return data, nil
	}
	if data, ok := c.committedAccounts[string(addr)]; ok {
		c.tracef("ctx.GetAccount(committed) %x: %x\n", addr, data)
		return data, nil
	}
	if c.cachedAccounts != nil {
		if data, ok := c.cachedAccounts.Get(string(addr)); ok {
			c.tracef("ctx.GetAccount(cached) %x: %x\n", addr, data)
			return data, nil
		}
	}

	var data []byte
	err := c.dm.WithReader(func(reader DomainsReader) error {
		if v, err := reader.DomainGetAsOf(kv.AccountsDomain, addr, c.readNum); err != nil {
			return err
		} else {
			data = v
			c.tracef("ctx.GetAccount(db) %x: %x\n", addr, data)
			return nil
		}
	})

	if err == nil && c.cachedAccounts != nil {
		c.cachedAccounts.Add(string(addr), data)
	}
	return data, err
}

func (c *DeferredContext) GetStorage(key []byte) ([]byte, error) {
	if data, ok := c.pendingStorages[string(key)]; ok {
		c.tracef("ctx.GetStorage(pending) %x: %x\n", key, data)
		return data, nil
	}
	if data, ok := c.committedStorages[string(key)]; ok {
		c.tracef("ctx.GetStorage(committed) %x: %x\n", key, data)
		return data, nil
	}
	if c.cachedStorages != nil {
		if data, ok := c.cachedStorages.Get(string(key)); ok {
			c.tracef("ctx.GetStorage(cached) %x: %x\n", key, data)
			return data, nil
		}
	}

	var data []byte
	err := c.dm.WithReader(func(reader DomainsReader) error {
		if v, err := reader.DomainGetAsOf(kv.StorageDomain, key, c.readNum); err != nil {
			return err
		} else {
			data = v
			c.tracef("ctx.GetStorage(db) %x: %x\n", key, data)
			return nil
		}
	})

	if err == nil && c.cachedStorages != nil {
		c.cachedStorages.Add(string(key), data)
	}
	return data, err
}

func (c *DeferredContext) GetBranch(prefix []byte) ([]byte, uint64, error) {
	if br, ok := c.pendingBranches[string(prefix)]; ok {
		c.tracef("ctx.GetBranch(pending) %x: %x\n", prefix, br.data)
		return br.data, br.prevStep, nil
	}
	if br, ok := c.committedBranches[string(prefix)]; ok {
		c.tracef("ctx.GetBranch(committed) %x: %x\n", prefix, br.data)
		return br.data, br.prevStep, nil
	}
	if c.cachedBranches != nil {
		if br, ok := c.cachedBranches.Get(string(prefix)); ok {
			c.tracef("ctx.GetBranch(cached) %x: %x\n", prefix, br.data)
			return br.data, br.prevStep, nil
		}
	}

	var br pendingBranch
	err := c.dm.WithReader(func(reader DomainsReader) error {
		if v, err := reader.DomainGetAsOf(kv.CommitmentDomain, prefix, c.readNum); err != nil {
			return err
		} else {
			br = pendingBranch{
				data:     v,
				prevStep: calcTxNum(c.readNum) / c.dm.StepSize(),
			}
			c.tracef("ctx.GetBranch(db) %x: %x\n", prefix, br.data)
			return nil
		}
	})

	if err == nil && c.cachedBranches != nil {
		c.cachedBranches.Add(string(prefix), br)
	}
	return br.data, br.prevStep, err
}

// PatriciaContext compatibility.

func (c *DeferredContext) Account(addr []byte) (*commitment.Update, error) {
	encAccount, err := c.GetAccount(addr)
	if err != nil {
		return nil, err
	}

	u := &commitment.Update{CodeHash: commitment.EmptyCodeHashArray} // default to empty code hash
	if len(encAccount) == 0 {
		u.Flags = commitment.DeleteUpdate
		return u, nil
	}

	if c.accountMode == ModeRawBytes {
		u.Flags = commitment.RawBytesUpdate
		u.RawBytes = make([]byte, len(encAccount))
		copy(u.RawBytes, encAccount)
		return u, nil
	}

	if c.accountMode == ModeErigonV3 {
		acc := new(accounts.Account)
		if err := accounts.DeserialiseV3(acc, encAccount); err != nil {
			return nil, err
		}

		u.Flags |= commitment.NonceUpdate
		u.Nonce = acc.Nonce

		u.Flags |= commitment.BalanceUpdate
		u.Balance.Set(&acc.Balance)

		if ch := acc.CodeHash.Bytes(); len(ch) > 0 { // if code hash is not empty
			u.Flags |= commitment.CodeUpdate
			copy(u.CodeHash[:], ch)
		}
		return u, nil
	}

	return nil, fmt.Errorf("invalid account mode: %d", c.accountMode)
}

func (c *DeferredContext) Storage(plainKey []byte) (*commitment.Update, error) {
	encData, err := c.GetStorage(plainKey)
	if err != nil {
		return nil, err
	}

	// Wrap it into Update. See SharedDomainsCommitmentContext.Storage().
	if len(encData) == 0 {
		return &commitment.Update{Flags: commitment.DeleteUpdate}, nil
	}

	u := &commitment.Update{
		Flags:      commitment.StorageUpdate,
		StorageLen: len(encData),
	}
	copy(u.Storage[:u.StorageLen], encData)
	return u, nil
}

func (c *DeferredContext) PutBranch(prefix []byte, data []byte, prevData []byte, prevStep uint64) error {
	return c.putBranch(prefix, data, prevData, prevStep)
}

func (c *DeferredContext) Branch(prefix []byte) ([]byte, uint64, error) {
	return c.GetBranch(prefix)
}

// Merkle patricia hash calculation.

func (c *DeferredContext) getHphState() ([]byte, error) {
	if len(c.lastHphState) > 0 {
		return c.lastHphState, nil
	}

	var cs []byte
	err := c.dm.WithReader(func(reader DomainsReader) error {
		if v, _, err := reader.DomainGetLatest(CustomDomain, keyHphState); err != nil {
			return err
		} else {
			cs = v
			return nil
		}
	})
	if err != nil {
		return nil, err
	}

	// Database is empty. e.g. before committing the genesis block.
	if len(cs) == 0 {
		c.tracef("ctx.GetHphState(db) %x\n", cs)
		return nil, nil
	}

	// Thre will be always only one Branch and HphState at the latest block.
	// Make sure we are not attempting to calculate hash at a previous block.
	_, blockNum, hphState, err := state.DecodeCommitmentState(cs)
	if err != nil {
		return nil, err
	}
	if blockNum != c.readNum {
		return nil, fmt.Errorf("%w: requested=%d stored=%d", errNotLatest, c.readNum, blockNum)
	}
	return hphState, nil
}

func (c *DeferredContext) hash(storageRootAddr []byte) ([]byte, error) {
	hphState, err := c.getHphState()
	if err != nil {
		return nil, err
	}

	if len(storageRootAddr) > 0 {
		c.tracef("ctx.Hash Begin len(updates)=%d addr=%x hash(hphState)=%x\n", c.pendingUpdates.Size(), storageRootAddr, crypto.Keccak256(hphState))
	} else {
		c.tracef("ctx.Hash Begin len(updates)=%d hash(hphState)=%x\n", c.pendingUpdates.Size(), crypto.Keccak256(hphState))
	}

	trie := c.dm.GetHph()
	defer c.dm.ReturnHph(trie)
	trie.ResetContext(c)
	trie.SetLastStorageRootHashCache(c.lastStorageRootHash)
	if err := trie.SetState(hphState); err != nil {
		return nil, err
	}

	// Note: c.pendingUpdates will be reset inside Process(), no need to Reset here.
	// See HexPatriciaHashed.Process() > updates.HashSort() > clear(t.keys)
	rootHash, err := trie.Process(context.Background(), c.pendingUpdates, "")
	if err != nil {
		return nil, err
	}

	hphState, err = trie.EncodeCurrentState(nil)
	if err != nil {
		return nil, err
	}
	c.lastHphState = hphState

	if len(storageRootAddr) > 0 {
		storageRootHash := c.lastStorageRootHash[string(storageRootAddr)]
		c.tracef("ctx.Hash End rootHash=%x addr=%x storageRootHash=%x hash(hphState)=%x\n", rootHash, storageRootAddr, storageRootHash, crypto.Keccak256(c.lastHphState))
		return storageRootHash, nil
	} else {
		c.tracef("ctx.Hash End rootHash=%x hash(hphState)=%x\n", rootHash, crypto.Keccak256(c.lastHphState))
		return rootHash, nil
	}
}

func (c *DeferredContext) Hash() ([]byte, error) {
	return c.hash(nil)
}

func (c *DeferredContext) StorageRootHash(storageRootAddr []byte) ([]byte, error) {
	return c.hash(storageRootAddr)
}

// Deferred hash and commit.

func (c *DeferredContext) Commit() error {
	err := c.dm.WithWriter(c.writeNum, func(writer DomainsWriter) error {
		c.tracef("ctx.Commit writeNum=%d accounts=%d storages=%d branches=%d hash(hphState)=%x\n", c.writeNum, len(c.pendingAccounts), len(c.pendingStorages), len(c.pendingBranches), crypto.Keccak256(c.lastHphState))

		for addr, data := range c.pendingAccounts {
			if err := writer.DomainPutOrDel(kv.AccountsDomain, []byte(addr), data); err != nil {
				return err
			}
		}
		for key, data := range c.pendingStorages {
			if err := writer.DomainPutOrDel(kv.StorageDomain, []byte(key), data); err != nil {
				return err
			}
		}
		for prefix, br := range c.pendingBranches {
			if err := writer.DomainPutOrDel(kv.CommitmentDomain, []byte(prefix), br.data); err != nil {
				return err
			}
		}
		cs, err := state.EncodeCommitmentState(calcTxNum(c.writeNum), c.writeNum, c.lastHphState)
		if err != nil {
			return err
		}
		writer.DomainPutOrDel(CustomDomain, keyHphState, cs)

		c.committedAccounts = c.pendingAccounts
		c.committedStorages = c.pendingStorages
		c.committedBranches = c.pendingBranches
		c.pendingAccounts = make(map[string][]byte)
		c.pendingStorages = make(map[string][]byte)
		c.pendingBranches = make(map[string]pendingBranch)

		return nil
	})
	return err
}
