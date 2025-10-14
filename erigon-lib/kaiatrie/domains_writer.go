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
	"math"

	"github.com/erigontech/erigon-lib/kv"
	"github.com/erigontech/erigon-lib/kv/rawdbv3"
	"github.com/erigontech/erigon-lib/state"
)

var (
	_ DomainsWriter = (*domainsWriter)(nil)

	errCommitBlockTooLow  = errors.New("block number too low to commit")
	errCommitBlockTooHigh = errors.New("block number too high to commit")
)

// DomainsWriter is the replacement to SharedDomains without patricia trie overhead.
type DomainsWriter interface {
	DomainsReader

	// DomainPutOrDel puts an key-value pair or deletes a key if the value is nil
	DomainPutOrDel(domain kv.Domain, key []byte, value []byte) error

	// SetBlockNum sets the block number for the writer
	SetBlockNum(blockNum uint64) error
	// WriteBlockNum writes the block number to the TxNums table
	WriteBlockNum(blockNum uint64) error
	Flush() error
	// Commit commits the transaction and close resources
	Commit() error
}

// Redefining the state.domainBufferedWriter because it's not exported
type bufferedWriter interface {
	PutWithPrev(key1, key2, val, prev []byte, prevStep uint64) error
	DeleteWithPrev(key1, key2, prev []byte, prevStep uint64) error
	Flush(ctx context.Context, tx kv.RwTx) error
	SetTxNum(v uint64)
	Close()
}

type domainsWriter struct {
	tx      kv.RwTx
	aggTx   *state.AggregatorRoTx
	buf     DomainsWriteBuffer
	writers [kv.DomainLen]bufferedWriter
}

func NewDomainsWriter(db kv.RwDB, agg *state.Aggregator, buf DomainsWriteBuffer) (DomainsWriter, error) {
	tx, err := db.BeginRw(context.Background())
	if err != nil {
		return nil, err
	}
	aggTx := agg.BeginFilesRo()

	// domain_shared.go:NewSharedDomains()
	dw := &domainsWriter{
		tx:    tx,
		aggTx: aggTx,
		buf:   buf,
	}
	for i := range kv.DomainLen {
		dw.writers[i] = aggTx.NewWriter(i)
	}

	return dw, nil
}

func (dw *domainsWriter) DomainGetAsOf(domain kv.Domain, key []byte, blockNum uint64) ([]byte, error) {
	if v, ok := dw.buf.GetAsOf(domain, key, calcTxNum(blockNum)); ok { // not flushed
		return v, nil
	}
	v, _, err := dw.aggTx.GetAsOf(dw.tx, domain, key, calcTxNum(blockNum)+1) // flushed
	return v, err
}

func (dw *domainsWriter) DomainGetLatest(domain kv.Domain, key []byte) ([]byte, uint64, error) {
	if v, ok := dw.buf.GetAsOf(domain, key, math.MaxUint64); ok { // not flushed
		return v, 0, nil
	}
	v, step, _, err := dw.aggTx.GetLatest(domain, key, dw.tx)
	return v, step, err
}

func (dw *domainsWriter) DomainPutOrDel(domain kv.Domain, key []byte, value []byte) error {
	prev, prevStep, _, err := dw.aggTx.GetLatest(domain, key, dw.tx)
	if err != nil {
		return err
	}

	dw.buf.Put(domain, key, value)

	if value == nil {
		return dw.writers[domain].DeleteWithPrev(key, nil, prev, prevStep)
	} else {
		return dw.writers[domain].PutWithPrev(key, nil, value, prev, prevStep)
	}
}

func (dw *domainsWriter) SetBlockNum(blockNum uint64) error {
	// Make sure we are committing to the head block or the next block
	lastBlockNum, _, err := rawdbv3.TxNums.Last(dw.tx)
	if err != nil {
		return err
	}
	if blockNum < lastBlockNum {
		return fmt.Errorf("%w (want: %d, last %d)", errCommitBlockTooLow, blockNum, lastBlockNum)
	}
	if lastBlockNum+1 < blockNum {
		return fmt.Errorf("%w (want: %d, last %d)", errCommitBlockTooHigh, blockNum, lastBlockNum)
	}

	txNum := calcTxNum(blockNum)

	// domain_shared.go:SetTxNum()
	for i := range kv.DomainLen {
		dw.writers[i].SetTxNum(txNum)
	}
	dw.buf.SetTxNum(txNum)
	return nil
}

func (dw *domainsWriter) WriteBlockNum(blockNum uint64) error {
	lastBlockNum, lastTxNum, err := rawdbv3.TxNums.Last(dw.tx)
	if err != nil {
		return err
	}

	shouldWriteGenesis := (blockNum == 0 && lastTxNum == 0) // Nothing in TxNums yet and we're writing block 0.
	shouldWriteNext := (lastBlockNum+1 == blockNum)         // First time we're writing the block at `blockNum`.
	if shouldWriteGenesis || shouldWriteNext {
		return rawdbv3.TxNums.Append(dw.tx, blockNum, calcTxNum(blockNum))
	} else {
		// Do not TxNums.Append() if we are editing the existing latest block
		return nil
	}
}

func (dw *domainsWriter) Flush() error {
	// domain_shared.go:Flush()
	ctx := context.Background()
	for i := range kv.DomainLen {
		if err := dw.writers[i].Flush(ctx, dw.tx); err != nil {
			return err
		}
		dw.aggTx.CloseValsCursor(i)
	}
	return nil
}

func (dw *domainsWriter) Commit() error {
	if err := dw.Flush(); err != nil {
		return err
	}
	if err := dw.tx.Commit(); err != nil {
		return err
	}
	dw.buf.Clear()
	return nil
}

// dw.Close() will tx.Rollback() inside. But it's safe to Commit then Rollback.
// See kv_interface.go:RwDB for the common pattern.
func (dw *domainsWriter) Close() {
	for i := range kv.DomainLen {
		dw.writers[i].Close()
	}
	dw.aggTx.Close()
	dw.tx.Rollback()
	dw.buf.Clear()
}

// Either {reopen: true, retCh} or {reopen: false, blockNum, fn, retCh}
type writeTask struct {
	reopen   bool // If true, commit and reopen the writer after executing the fn.
	blockNum uint64
	fn       func(writer DomainsWriter) error
	retCh    chan error
}

type writeWorker struct {
	dm     *DomainsManager
	taskCh chan *writeTask

	writer DomainsWriter
}

func NewWriteWorker(dm *DomainsManager, taskCh chan *writeTask) *writeWorker {
	return &writeWorker{dm: dm, taskCh: taskCh}
}

func (worker *writeWorker) openWriter() error {
	writer, err := NewDomainsWriter(worker.dm.db, worker.dm.agg, worker.dm.writeBuffer)
	if err != nil {
		return err
	}
	worker.writer = writer
	return nil
}

func (worker *writeWorker) closeWriter() error {
	defer worker.writer.Close() // Always close the writer
	if err := worker.writer.Commit(); err != nil {
		return err
	}
	for _, reader := range worker.dm.readers {
		reader.needReopen.Store(1)
	}
	return nil
}

func (worker *writeWorker) reopenWriter() error {
	if err := worker.closeWriter(); err != nil {
		return err
	}
	if err := worker.openWriter(); err != nil {
		return err
	}
	return nil
}

func (worker *writeWorker) handle(task *writeTask) error {
	if err := worker.writer.SetBlockNum(task.blockNum); err != nil {
		return err
	}
	if err := task.fn(worker.writer); err != nil {
		return err
	}
	if err := worker.writer.WriteBlockNum(task.blockNum); err != nil {
		return err
	}
	if err := worker.writer.Flush(); err != nil {
		return err
	}
	return nil
}

func (worker *writeWorker) loop() {
	openErr := worker.openWriter()

	for task := range worker.taskCh {
		if openErr != nil {
			task.retCh <- openErr
		} else if task.reopen {
			openErr := worker.reopenWriter()
			task.retCh <- openErr
		} else {
			task.retCh <- worker.handle(task)
		}
	}

	if worker.writer != nil {
		worker.closeWriter()
	}
}
