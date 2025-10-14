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
	"math"
	"sync/atomic"

	"github.com/erigontech/erigon-lib/kv"
	"github.com/erigontech/erigon-lib/state"
)

var (
	_ DomainsReader = (*domainsReader)(nil)
)

// DomainsReader is the replacement to SharedDomainsCommitmentContext without patricia trie overhead.
type DomainsReader interface {
	// DomainGetAsOf gets the value of a key at a specific block number
	DomainGetAsOf(domain kv.Domain, key []byte, blockNum uint64) ([]byte, error)
	// DomainGetLatest gets the latest value of a key
	DomainGetLatest(domain kv.Domain, key []byte) ([]byte, uint64, error)

	// Close closes the transaction and the resources
	Close()
}

type domainsReader struct {
	tx    kv.Tx
	aggTx *state.AggregatorRoTx

	buf DomainsWriteBuffer
}

func NewDomainsReader(db kv.RoDB, agg *state.Aggregator, buf DomainsWriteBuffer) (DomainsReader, error) {
	tx, err := db.BeginRo(context.Background())
	if err != nil {
		return nil, err
	}
	aggTx := agg.BeginFilesRo()
	return &domainsReader{
		tx:    tx,
		aggTx: aggTx,
		buf:   buf,
	}, nil
}

func (dr *domainsReader) DomainGetAsOf(domain kv.Domain, key []byte, blockNum uint64) ([]byte, error) {
	if v, ok := dr.buf.GetAsOf(domain, key, calcTxNum(blockNum)); ok { // not flushed
		return v, nil
	}
	v, _, err := dr.aggTx.GetAsOf(dr.tx, domain, key, calcTxNum(blockNum)+1) // flushed
	return v, err
}

func (dr *domainsReader) DomainGetLatest(domain kv.Domain, key []byte) ([]byte, uint64, error) {
	if v, ok := dr.buf.GetAsOf(domain, key, math.MaxUint64); ok { // not flushed
		return v, 0, nil
	}
	v, step, _, err := dr.aggTx.GetLatest(domain, key, dr.tx)
	return v, step, err
}

func (dr *domainsReader) Close() {
	if dr == nil {
		return
	}
	dr.tx.Rollback()
	dr.aggTx.Close()
}

type readTask struct {
	fn    func(reader DomainsReader) error
	retCh chan error
}

type readWorker struct {
	dm     *DomainsManager
	taskCh chan *readTask

	needReopen atomic.Int32
	reader     DomainsReader
}

func NewReadWorker(dm *DomainsManager, taskCh chan *readTask) *readWorker {
	return &readWorker{dm: dm, taskCh: taskCh}
}

func (worker *readWorker) reopen() error {
	if worker.reader != nil {
		worker.reader.Close()
	}

	newReader, err := NewDomainsReader(worker.dm.db, worker.dm.agg, worker.dm.writeBuffer)
	if err != nil {
		worker.reader = nil
		return err
	} else {
		worker.reader = newReader
		return nil
	}
}

func (worker *readWorker) loop() {
	for task := range worker.taskCh {
		if worker.needReopen.Load() == 1 || worker.reader == nil {
			worker.needReopen.Store(0)
			if err := worker.reopen(); err != nil {
				task.retCh <- err
				continue
			}
		}

		task.retCh <- task.fn(worker.reader)
	}
	if worker.reader != nil {
		worker.reader.Close()
	}
}
