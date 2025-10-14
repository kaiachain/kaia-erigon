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

	"github.com/erigontech/erigon-lib/common"
	"github.com/erigontech/erigon-lib/kv"
	"github.com/erigontech/erigon-lib/kv/order"
	"github.com/erigontech/erigon-lib/kv/stream"
	"github.com/erigontech/erigon-lib/state"
)

var (
	_ DomainsIterator = (*domainsIterator)(nil)

	errStorageKeyTooShort = errors.New("storage key too short")
)

// DomainsIterator is an universal iterator over a domain.
type DomainsIterator interface {
	// Next gets the next key-value pair. It returns false if there was no more key-value pair.
	Next() ([]byte, []byte, bool, error)
	// Close closes the iterator
	Close()
}

type domainsIterator struct {
	domain kv.Domain
	tx     kv.Tx
	aggTx  *state.AggregatorRoTx
	it     stream.KV
}

// DomainsIterator is the generic low-level iterator over a domain.
func NewDomainsIterator(dm *DomainsManager, domain kv.Domain, startKey, endKey []byte, blockNum uint64) (DomainsIterator, error) {
	ctx := context.Background()
	tx, err := dm.db.BeginRo(ctx)
	if err != nil {
		return nil, err
	}
	aggTx := dm.agg.BeginFilesRo()

	it, err := aggTx.RangeAsOf(ctx, tx, domain, startKey, endKey, calcTxNum(blockNum)+1, order.Asc, kv.Unlim)
	if err != nil {
		aggTx.Close()
		tx.Rollback()
		return nil, err
	}
	return &domainsIterator{
		domain: domain,
		tx:     tx,
		aggTx:  aggTx,
		it:     it,
	}, nil
}

// AccountIterator iterates over all (address, account) pairs as of blockNum.
func NewAccountIterator(dm *DomainsManager, blockNum uint64) (DomainsIterator, error) {
	return NewDomainsIterator(dm, kv.AccountsDomain, nil, nil, blockNum)
}

// StorageIterator iterates over all (slot, data) pairs as of blockNum.
func NewStorageIterator(dm *DomainsManager, addrB []byte, blockNum uint64) (DomainsIterator, error) {
	// core/state/dump.go:DumpToCollector
	var (
		addr      = common.BytesToAddress(addrB)
		startKey  = addr.Bytes()
		endKey, _ = kv.NextSubtree(startKey)
	)
	return NewDomainsIterator(dm, kv.StorageDomain, startKey, endKey, blockNum)
}

func (di *domainsIterator) Next() ([]byte, []byte, bool, error) {
	if !di.it.HasNext() {
		return nil, nil, false, nil
	}
	k, v, err := di.it.Next()
	if err != nil {
		return nil, nil, false, err
	}
	if len(v) == 0 {
		// Skip non-existent entries. MDBX would iterate over all keys ever created
		// regardless of the requested txNum. Sometimes not-yet-existent entries show up.
		// We ignore them because they don't exist at this blockNum.
		return nil, nil, false, nil
	}
	if di.domain == kv.StorageDomain {
		if len(k) <= 20 {
			return nil, nil, false, errStorageKeyTooShort
		}
		k = k[20:]
	}
	return k, v, true, nil
}

func (di *domainsIterator) Close() {
	di.aggTx.Close()
	di.tx.Rollback()
}
