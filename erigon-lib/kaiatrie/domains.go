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
	"encoding/binary"
	"runtime"
	"sync"

	"github.com/c2h5oh/datasize"
	"github.com/erigontech/erigon-lib/commitment"
	"github.com/erigontech/erigon-lib/common"
	"github.com/erigontech/erigon-lib/common/datadir"
	"github.com/erigontech/erigon-lib/common/length"
	"github.com/erigontech/erigon-lib/config3"
	"github.com/erigontech/erigon-lib/kv"
	"github.com/erigontech/erigon-lib/kv/mdbx"
	"github.com/erigontech/erigon-lib/log/v3"
	"github.com/erigontech/erigon-lib/state"
	"golang.org/x/sync/semaphore"
)

var (
	// Abusing ReceiptDomain for custom data. This is safe because
	// (1) ReceiptDomain is irrelevant to the state trie processing.
	// (2) Kaia will use its own database for receipts, so ReceiptDomain not used for any purpose.
	CustomDomain = kv.ReceiptDomain

	// "stateroot" || roothash => blockNum
	keyRootPrefix = []byte("stateroot")
)

type DomainsOpts struct {
	NumReadWorkers    int
	EnableWriteWorker bool
}

// DomainsManager is a dispatcher for the operations reading from and writing to the MDBX database.
// MDBX explicitly requires database transactions to be created and used within the same goroutine,
// and writing transactions cannot be concurrently executed. DomainsManager is responsible for
// keeping the constraints while being efficient.
type DomainsManager struct {
	DomainsOpts

	mu     sync.Mutex
	dirs   datadir.Dirs
	logger log.Logger

	// Underlying database
	db  kv.RwDB
	agg *state.Aggregator

	// Because MDBX transactions must be created and used within the same goroutine,
	// we use dedicated reader and writer goroutines that process DB requests.

	// Shared between readers and writers
	wg          sync.WaitGroup
	writeBuffer DomainsWriteBuffer

	// DomainsReader pool
	readers   []*readWorker
	readersCh chan *readTask

	// DomainsWriter instance
	writer   *writeWorker
	writerCh chan *writeTask

	// Minimize memory allocation
	hphPool sync.Pool
}

func NewTemporaryDomainsManager(dir string) (*DomainsManager, error) {
	dirs := datadir.New(dir)
	logger := log.Root()

	// kv_mdbx_temporary.go
	db, err := mdbx.New(kv.ChainDB, logger).
		InMem(dirs.Chaindata). // dirs is only for the spill. Not persistent.
		Open(context.Background())
	if err != nil {
		return nil, err
	}

	return newDomainsManager(dirs, logger, db, &DomainsOpts{NumReadWorkers: 4, EnableWriteWorker: true})
}

func NewDomainsManager(dir string, logger_ foreignLogger, dmOpts *DomainsOpts) (*DomainsManager, error) {
	dirs := datadir.New(dir)
	logger := loggerFromForeign(logger_)

	// node.go:OpenDatabase()
	// Follow the Erigon default settings in general.
	roTxsLimiter := semaphore.NewWeighted(32) // same as OpenDatabase()
	dbOpts := mdbx.New(kv.ChainDB, logger).
		Path(dir).
		GrowthStep(16 * datasize.MB).      // same as OpenDatabase()
		PageSize(4 * datasize.KB).         // DbPageSizeFlag default
		MapSize(1 * datasize.TB).          // DbSizeLimitFlag default
		DBVerbosity(kv.DBVerbosityLvl(2)). // WARN
		RoTxsLimiter(roTxsLimiter).
		Readonly(false).
		Exclusive(true)
	db, err := dbOpts.Open(context.Background())
	if err != nil {
		return nil, err
	}

	return newDomainsManager(dirs, logger, db, dmOpts)
}

func newDomainsManager(dirs datadir.Dirs, logger log.Logger, db kv.RwDB, dmOpts *DomainsOpts) (*DomainsManager, error) {
	if dmOpts == nil {
		dmOpts = &DomainsOpts{NumReadWorkers: runtime.GOMAXPROCS(0), EnableWriteWorker: true}
	}

	// eth/backend.go:setUpBlockReader
	agg, err := state.NewAggregator2(context.Background(), dirs, config3.DefaultStepSize, db, logger)
	if err != nil {
		db.Close()
		return nil, err
	}
	if err := agg.OpenFolder(); err != nil {
		agg.Close()
		db.Close()
		return nil, err
	}

	dm := &DomainsManager{
		DomainsOpts: *dmOpts,

		dirs:   dirs,
		logger: logger,
		db:     db,
		agg:    agg,

		readers:   make([]*readWorker, dmOpts.NumReadWorkers),
		readersCh: make(chan *readTask, dmOpts.NumReadWorkers*8),

		writerCh: make(chan *writeTask, 1),

		writeBuffer: NewDomainsWriteBuffer(),

		hphPool: sync.Pool{New: func() any {
			return commitment.NewHexPatriciaHashed(length.Addr, nil, dirs.Tmp)
		}},
	}

	dm.startReadWorkers()
	dm.startWriteWorker()
	return dm, nil
}

func (dm *DomainsManager) startReadWorkers() {
	for i := 0; i < dm.NumReadWorkers; i++ {
		dm.readers[i] = NewReadWorker(dm, dm.readersCh)
		dm.wg.Add(1)
		go func() {
			dm.readers[i].loop()
			dm.wg.Done()
		}()
	}
}

func (dm *DomainsManager) startWriteWorker() {
	if !dm.EnableWriteWorker {
		return
	}
	dm.writer = NewWriteWorker(dm, dm.writerCh)
	dm.wg.Add(1)
	go func() {
		dm.writer.loop()
		dm.wg.Done()
	}()
}

func (dm *DomainsManager) WithReader(fn func(reader DomainsReader) error) error {
	if dm.NumReadWorkers == 0 {
		return dm.withReader_callerThread(fn)
	} else {
		return dm.withReader_workerThread(fn)
	}
}

func (dm *DomainsManager) withReader_callerThread(fn func(reader DomainsReader) error) error {
	reader, err := NewDomainsReader(dm.db, dm.agg, dm.writeBuffer)
	if err != nil {
		return err
	}
	defer reader.Close()
	return fn(reader)
}

func (dm *DomainsManager) withReader_workerThread(fn func(reader DomainsReader) error) error {
	task := &readTask{
		fn:    fn,
		retCh: make(chan error),
	}
	dm.readersCh <- task
	return <-task.retCh
}

func (dm *DomainsManager) WithWriter(blockNum uint64, fn func(writer DomainsWriter) error) error {
	if !dm.EnableWriteWorker {
		return dm.withWriter_callerThread(blockNum, fn)
	} else {
		return dm.withWriter_workerThread(blockNum, fn)
	}
}

func (dm *DomainsManager) withWriter_callerThread(blockNum uint64, fn func(writer DomainsWriter) error) error {
	dm.mu.Lock()
	defer dm.mu.Unlock()

	writer, err := NewDomainsWriter(dm.db, dm.agg, dm.writeBuffer)
	if err != nil {
		return err
	}
	defer writer.Close()

	if err := writer.SetBlockNum(blockNum); err != nil {
		return err
	}
	if err := fn(writer); err != nil {
		return err
	}
	if err := writer.WriteBlockNum(blockNum); err != nil {
		return err
	}
	if err := writer.Commit(); err != nil {
		return err
	}
	for _, worker := range dm.readers {
		worker.needReopen.Store(1)
	}
	return nil
}

func (dm *DomainsManager) withWriter_workerThread(blockNum uint64, fn func(writer DomainsWriter) error) error {
	task := &writeTask{
		blockNum: blockNum,
		fn:       fn,
		retCh:    make(chan error),
	}
	dm.writerCh <- task
	res := <-task.retCh
	return res
}

func (dm *DomainsManager) CommitWrites() error {
	if !dm.EnableWriteWorker {
		return nil
	}
	task := &writeTask{
		reopen: true,
		retCh:  make(chan error),
	}
	dm.writerCh <- task
	return <-task.retCh
}

func (dm *DomainsManager) Close() {
	dm.mu.Lock()
	defer dm.mu.Unlock()

	if dm.NumReadWorkers > 0 {
		close(dm.readersCh)
	}
	if dm.EnableWriteWorker {
		close(dm.writerCh)
	}
	dm.wg.Wait()

	dm.agg.Close()
	dm.db.Close()
}

func (dm *DomainsManager) StepSize() uint64 {
	return dm.agg.StepSize()
}

func (dm *DomainsManager) Tmpdir() string {
	return dm.dirs.Tmp
}

func (dm *DomainsManager) GetHph() *commitment.HexPatriciaHashed {
	return dm.hphPool.Get().(*commitment.HexPatriciaHashed)
}

func (dm *DomainsManager) ReturnHph(hph *commitment.HexPatriciaHashed) {
	dm.hphPool.Put(hph)
}

func (dm *DomainsManager) ReadBlockNumByRoot(root []byte) (blockNum uint64, ok bool, err error) {
	err = dm.WithReader(func(reader DomainsReader) error {
		if data, _, err := reader.DomainGetLatest(CustomDomain, rootKey(root)); err != nil {
			return err
		} else if len(data) < 8 {
			return nil // not found
		} else {
			blockNum = binary.BigEndian.Uint64(data)
			ok = true
			return nil
		}
	})
	return
}

func (dm *DomainsManager) WriteBlockNumByRoot(root []byte, blockNum uint64) error {
	return dm.WithWriter(blockNum, func(writer DomainsWriter) error {
		return writer.DomainPutOrDel(CustomDomain, rootKey(root), binary.BigEndian.AppendUint64([]byte{}, blockNum))
	})
}

// Treat each block as 1 Erigon transaction.
// e.g. Genesis block has one tx #1, so blockNum 0 = txNum 1.
func calcTxNum(blockNum uint64) uint64 {
	return blockNum + 1
}

func rootKey(rootHash []byte) []byte {
	return append(keyRootPrefix, common.BytesToHash(rootHash).Bytes()...)
}
