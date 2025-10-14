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
	"encoding/hex"
	"math/big"
	"os/exec"
	"slices"
	"strings"
	"sync"
	"testing"

	"github.com/erigontech/erigon-lib/commitment"
	"github.com/erigontech/erigon-lib/common"
	"github.com/erigontech/erigon-lib/common/hexutil"
	"github.com/erigontech/erigon-lib/common/length"
	"github.com/erigontech/erigon-lib/kv"
	"github.com/erigontech/erigon-lib/log/v3"
	"github.com/erigontech/erigon-lib/types/accounts"
	"github.com/holiman/uint256"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func Test_DomainsManager_BlockNums(t *testing.T) {
	dm, err := NewTemporaryDomainsManager(t.TempDir())
	require.NoError(t, err)
	defer dm.Close()

	noop := func(writer DomainsWriter) error { return nil }

	// Commit blocks in order.
	assert.NoError(t, dm.WithWriter(0, noop))
	assert.NoError(t, dm.WithWriter(1, noop))
	assert.NoError(t, dm.WithWriter(2, noop))

	// Cannot commit a block less than last block.
	assert.ErrorIs(t, dm.WithWriter(1, noop), errCommitBlockTooLow)
	// Cannot commit a block with a gap from the last block.
	assert.ErrorIs(t, dm.WithWriter(4, noop), errCommitBlockTooHigh)

	// Permitted to commit the last block again.
	assert.NoError(t, dm.WithWriter(2, noop))
	// Permitted to commit the block right after the last block.
	assert.NoError(t, dm.WithWriter(3, noop))
}

// Test that write -> read works.
func Test_DomainsManager_ReadWrite(t *testing.T) {
	var (
		addr = common.HexToAddress("0x1111111111111111111111111111111111111111").Bytes()
		acc  = accounts.SerialiseV3(&accounts.Account{Balance: *uint256.NewInt(90)})
	)

	dm, err := NewTemporaryDomainsManager(t.TempDir())
	require.NoError(t, err)
	defer dm.Close()

	dm.WithWriter(0, func(writer DomainsWriter) error {
		writer.DomainPutOrDel(kv.AccountsDomain, addr, acc)
		return nil
	})

	dm.WithReader(func(reader DomainsReader) error {
		actualAcc, err := reader.DomainGetAsOf(kv.AccountsDomain, addr, 0)
		assert.NoError(t, err)
		assert.Equal(t, acc, actualAcc)
		return nil
	})
}

// Test that write -> commit -> read works.
func Test_DomainsManager_Commit(t *testing.T) {
	var (
		addr   = common.HexToAddress("0x1111111111111111111111111111111111111111").Bytes()
		acc0   = accounts.SerialiseV3(&accounts.Account{Balance: *uint256.NewInt(90)})
		acc1   = accounts.SerialiseV3(&accounts.Account{Balance: *uint256.NewInt(91)})
		dir    = t.TempDir()
		logger = log.Root()
	)

	dm, err := NewDomainsManager(dir, logger, &DomainsOpts{EnableWriteWorker: true})
	require.NoError(t, err)

	require.NoError(t, dm.withWriter_workerThread(0, func(writer DomainsWriter) error {
		writer.DomainPutOrDel(kv.AccountsDomain, addr, acc0)
		return nil
	}))
	require.NoError(t, dm.withWriter_workerThread(1, func(writer DomainsWriter) error {
		writer.DomainPutOrDel(kv.AccountsDomain, addr, acc1)
		return nil
	}))

	require.NoError(t, dm.CommitWrites())

	dm.WithReader(func(reader DomainsReader) error {
		actualAcc, err := reader.DomainGetAsOf(kv.AccountsDomain, addr, 0)
		assert.NoError(t, err)
		assert.Equal(t, acc0, actualAcc)

		actualAcc, err = reader.DomainGetAsOf(kv.AccountsDomain, addr, 1)
		assert.NoError(t, err)
		assert.Equal(t, acc1, actualAcc)
		return nil
	})
	dm.Close()
}

// Test that write -> close -> open -> read works.
func Test_DomainsManager_Reopen(t *testing.T) {
	var (
		addr   = common.HexToAddress("0x1111111111111111111111111111111111111111").Bytes()
		acc0   = accounts.SerialiseV3(&accounts.Account{Balance: *uint256.NewInt(90)})
		acc1   = accounts.SerialiseV3(&accounts.Account{Balance: *uint256.NewInt(91)})
		dir    = t.TempDir()
		logger = log.Root()
	)

	// Write and close.
	dm, err := NewDomainsManager(dir, logger, &DomainsOpts{EnableWriteWorker: true})
	require.NoError(t, err)
	require.NoError(t, dm.withWriter_workerThread(0, func(writer DomainsWriter) error {
		writer.DomainPutOrDel(kv.AccountsDomain, addr, acc0)
		return nil
	}))
	require.NoError(t, dm.withWriter_workerThread(1, func(writer DomainsWriter) error {
		writer.DomainPutOrDel(kv.AccountsDomain, addr, acc1)
		return nil
	}))
	dm.Close()

	// Reopen and read.
	dm, err = NewDomainsManager(dir, logger, nil)
	require.NoError(t, err)
	dm.WithReader(func(reader DomainsReader) error {
		actualAcc, err := reader.DomainGetAsOf(kv.AccountsDomain, addr, 0)
		assert.NoError(t, err)
		assert.Equal(t, acc0, actualAcc)

		actualAcc, err = reader.DomainGetAsOf(kv.AccountsDomain, addr, 1)
		assert.NoError(t, err)
		assert.Equal(t, acc1, actualAcc)
		return nil
	})
	dm.Close()
}

func Test_DomainsManager_WriteMany(t *testing.T) {
	maxNum := 100
	count := 10000

	getPair := func(num, j int) ([]byte, []byte) {
		n := int64(num*0x10000 + j)
		k := common.BigToAddress(big.NewInt(n)).Bytes()
		v := common.BigToHash(big.NewInt(n)).Bytes()
		return k, v
	}

	putItems := func(writer DomainsWriter, num, count int) {
		for i := range count {
			k, v := getPair(num, i)
			assert.NoError(t, writer.DomainPutOrDel(kv.AccountsDomain, k, v))
		}
	}

	checkItems := func(reader DomainsReader, num, count int) {
		for i := range count {
			k, expectedV := getPair(num, i)
			v, err := reader.DomainGetAsOf(kv.AccountsDomain, k, uint64(num))
			assert.NoError(t, err)
			if !assert.Equal(t, hex.EncodeToString(expectedV), hex.EncodeToString(v), hex.EncodeToString(k)) {
				break
			}
		}
	}

	dm, err := NewDomainsManager(t.TempDir(), log.Root(), nil)
	require.NoError(t, err)
	defer dm.Close()

	for num := 0; num < maxNum; num++ {
		require.NoError(t, dm.WithWriter(uint64(num), func(writer DomainsWriter) error {
			putItems(writer, num, count)
			return nil
		}))
	}
	require.NoError(t, dm.WithReader(func(reader DomainsReader) error {
		for num := 0; num < maxNum; num++ {
			checkItems(reader, num, count)
		}
		return nil
	}))
}

func Test_DomainsManager_Iterator(t *testing.T) {
	var (
		accounts = [][2]string{
			{"0x1111111111111111111111111111111111111111", "0x00015a0000"},
			{"0x2222222222222222222222222222222222222222", "0x00015b0000"},
			{"0x3333333333333333333333333333333333333333", "0x00015c0000"},
		}

		contractAddr = common.HexToAddress("0x1111111111111111111111111111111111111111").Bytes()
		storage      = [][2]string{
			{"0x0000000000000000000000000000000000000000000000000000000000000001", "0x12"},
			{"0x0000000000000000000000000000000000000000000000000000000000000002", "0x23"},
			{"0x0000000000000000000000000000000000000000000000000000000000000003", "0x34"},
		}
	)

	// Commit across 3 blocks.
	dir := t.TempDir()
	dm, err := NewDomainsManager(dir, log.Root(), nil)
	require.NoError(t, err)
	for i := 0; i < 3; i++ {
		addr, acc := hexutil.MustDecode(accounts[i][0]), hexutil.MustDecode(accounts[i][1])
		slot, data := hexutil.MustDecode(storage[i][0]), hexutil.MustDecode(storage[i][1])
		require.NoError(t, dm.WithWriter(uint64(i), func(writer DomainsWriter) error {
			writer.DomainPutOrDel(kv.AccountsDomain, addr, acc)
			writer.DomainPutOrDel(kv.StorageDomain, append(contractAddr, slot...), data)
			return nil
		}))
	}
	require.NoError(t, dm.CommitWrites())

	it, err := NewAccountIterator(dm, 0)
	require.NoError(t, err)
	defer it.Close()
	checkIt(t, it, accounts[:1]) // only 1 account is iterated at block 0.

	it, err = NewAccountIterator(dm, 1)
	require.NoError(t, err)
	defer it.Close()
	checkIt(t, it, accounts[:2])

	it, err = NewAccountIterator(dm, 2)
	require.NoError(t, err)
	defer it.Close()
	checkIt(t, it, accounts[:3])

	it, err = NewStorageIterator(dm, contractAddr, 2)
	require.NoError(t, err)
	defer it.Close()
	checkIt(t, it, storage)
}

func checkIt(t *testing.T, it DomainsIterator, items [][2]string) {
	// Sort items by key.
	expected := slices.Clone(items)
	slices.SortFunc(expected, func(a, b [2]string) int {
		return strings.Compare(a[0], b[0])
	})

	for _, item := range expected {
		expectedKey, expectedValue := hexutil.MustDecode(item[0]), hexutil.MustDecode(item[1])
		key, value, ok, err := it.Next()
		require.NoError(t, err)
		assert.Equal(t, true, ok)
		assert.Equal(t, hex.EncodeToString(expectedKey), hex.EncodeToString(key))
		assert.Equal(t, hex.EncodeToString(expectedValue), hex.EncodeToString(value))
	}
	key, value, ok, err := it.Next()
	assert.NoError(t, err)
	assert.False(t, ok)
	assert.Nil(t, key)
	assert.Nil(t, value)
}

func Benchmark_Reader(b *testing.B) {
	dm, err := NewTemporaryDomainsManager(b.TempDir())
	require.NoError(b, err)
	defer dm.Close()

	var (
		addr = common.HexToAddress("0x1111111111111111111111111111111111111111").Bytes()
		acc  = accounts.SerialiseV3(&accounts.Account{Balance: *uint256.NewInt(90)})
	)

	// Commit some data
	require.NoError(b, dm.WithWriter(0, func(writer DomainsWriter) error {
		writer.DomainPutOrDel(kv.AccountsDomain, addr, acc)
		return nil
	}))

	b.Run("keep RoTx open", func(b *testing.B) {
		dm.WithReader(func(reader DomainsReader) error {
			for i := 0; i < b.N; i++ {
				reader.DomainGetAsOf(kv.AccountsDomain, addr, 0)
			}
			return nil
		})
	})

	b.Run("open RoTx every read", func(b *testing.B) {
		for i := 0; i < b.N; i++ {
			dm.withReader_callerThread(func(reader DomainsReader) error {
				reader.DomainGetAsOf(kv.AccountsDomain, addr, 0)
				return nil
			})
		}
	})

	b.Run("reuse RoTx in thread pool", func(b *testing.B) {
		for i := 0; i < b.N; i++ {
			dm.withReader_workerThread(func(reader DomainsReader) error {
				reader.DomainGetAsOf(kv.AccountsDomain, addr, 0)
				return nil
			})
		}
	})
}

func Benchmark_Writer(b *testing.B) {
	putItems := func(writer DomainsWriter, num, count int) {
		for i := range count {
			n := int64(num*1000 + i)
			k := common.BigToAddress(big.NewInt(n)).Bytes()
			v := common.BigToHash(big.NewInt(n)).Bytes()
			writer.DomainPutOrDel(CustomDomain, k, v)
		}
	}

	b.Run("open RwTx every block", func(b *testing.B) {
		dm, err := NewDomainsManager(b.TempDir(), log.Root(), &DomainsOpts{EnableWriteWorker: false})
		require.NoError(b, err)
		defer dm.Close()

		for i := 0; i < b.N; i++ {
			dm.withWriter_callerThread(uint64(i), func(writer DomainsWriter) error {
				putItems(writer, i, 10)
				return nil
			})
		}

		out, _ := exec.Command("du", "-sh", dm.dirs.DataDir).Output()
		b.Logf("N=%d datadir=%s", b.N, out)
	})

	b.Run("reuse RwTx", func(b *testing.B) {
		dm, err := NewDomainsManager(b.TempDir(), log.Root(), nil)
		require.NoError(b, err)

		for i := 0; i < b.N; i++ {
			dm.withWriter_workerThread(uint64(i), func(writer DomainsWriter) error {
				putItems(writer, i, 10)
				return nil
			})
		}
		dm.Close()

		out, _ := exec.Command("du", "-sh", dm.dirs.DataDir).Output()
		b.Logf("N=%d datadir=%s", b.N, out)
	})

}

func Benchmark_Hph(b *testing.B) {
	b.Run("new HPH every time", func(b *testing.B) {
		for i := 0; i < b.N; i++ {
			commitment.NewHexPatriciaHashed(length.Addr, nil, b.TempDir())
		}
	})

	b.Run("reuse HPH from pool", func(b *testing.B) {
		hphPool := sync.Pool{New: func() any {
			return commitment.NewHexPatriciaHashed(length.Addr, nil, b.TempDir())
		}}
		for i := 0; i < b.N; i++ {
			hph := hphPool.Get()
			hphPool.Put(hph)
		}
	})
}
