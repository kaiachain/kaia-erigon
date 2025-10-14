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
	"encoding/binary"
	"strings"
	"sync"

	"github.com/erigontech/erigon-lib/kv"
	"github.com/tidwall/btree"
)

type WriteBuffer struct {
	mu    sync.RWMutex
	txNum uint64                     // current tx num
	m     *btree.Map[string, []byte] // (key || txNum) => value
}

func NewWriteBuffer() *WriteBuffer {
	return &WriteBuffer{
		m: btree.NewMap[string, []byte](128),
	}
}

func (b *WriteBuffer) SetTxNum(txNum uint64) {
	b.mu.Lock()
	defer b.mu.Unlock()

	b.txNum = txNum
}

func (b *WriteBuffer) Clear() {
	b.mu.Lock()
	defer b.mu.Unlock()

	b.m.Clear()
}

func (b *WriteBuffer) Put(key, value []byte) {
	b.mu.Lock()
	defer b.mu.Unlock()

	b.m.Set(b.makeBufferKey(key, b.txNum), value)
}

func (b *WriteBuffer) GetAsOf(key []byte, txNum uint64) ([]byte, bool) {
	b.mu.RLock()
	defer b.mu.RUnlock()

	var (
		bottomKey = b.makeBufferKey(key, 0)
		searchKey = b.makeBufferKey(key, txNum)
		result    = []byte(nil)
		ok        = false
	)
	b.m.Descend(searchKey, func(iterKey string, value []byte) bool {
		if strings.Compare(bottomKey, iterKey) <= 0 {
			result = value
			ok = true
		}
		return false // stop Descend
	})
	return result, ok
}

// [keyLen][key][txNum]
func (b *WriteBuffer) makeBufferKey(key []byte, txNum uint64) string {
	keyLen := []byte{byte(len(key))}
	numBuf := make([]byte, 8)
	binary.BigEndian.PutUint64(numBuf, txNum)
	buf := append(append(keyLen, key...), numBuf...)
	return string(buf)
}

type DomainsWriteBuffer [kv.DomainLen]*WriteBuffer

func NewDomainsWriteBuffer() DomainsWriteBuffer {
	buf := DomainsWriteBuffer{}
	for i := range kv.DomainLen {
		buf[i] = NewWriteBuffer()
	}
	return buf
}

func (buf *DomainsWriteBuffer) SetTxNum(txNum uint64) {
	for _, b := range buf {
		b.SetTxNum(txNum)
	}
}

func (buf *DomainsWriteBuffer) Put(domain kv.Domain, key, value []byte) {
	buf[domain].Put(key, value)
}

func (buf *DomainsWriteBuffer) GetAsOf(domain kv.Domain, key []byte, txNum uint64) ([]byte, bool) {
	return buf[domain].GetAsOf(key, txNum)
}

func (buf *DomainsWriteBuffer) Clear() {
	for _, b := range buf {
		b.Clear()
	}
}
