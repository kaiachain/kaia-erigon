// Copyright 2015 The go-ethereum Authors
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

package vm

import (
	"sync"

	"github.com/holiman/uint256"
)

var memoryPool = sync.Pool{
	New: func() any {
		return &Memory{}
	},
}

// Memory implements a simple memory model for the ethereum virtual machine.
type Memory struct {
	store       []byte
	lastGasCost uint64
}

// NewMemory returns a new memory model.
func NewMemory() *Memory {
	m := memoryPool.Get().(*Memory)
	m.reset()
	return m
}

// Free returns the memory to the pool.
func (m *Memory) free() {
	// To reduce peak allocation, return only smaller memory instances to the pool.
	const maxBufferSize = 16 << 10
	if cap(m.store) <= maxBufferSize {
		m.store = m.store[:0]
		m.lastGasCost = 0
		memoryPool.Put(m)
	}
}

// Set sets offset + size to value
func (m *Memory) Set(offset, size uint64, value []byte) {
	// It's possible the offset is greater than 0 and size equals 0. This is because
	// the calcMemSize (common.go) could potentially return 0 when size is zero (NO-OP)
	if size > 0 {
		// length of store may never be less than offset + size.
		// The store should be resized PRIOR to setting the memory
		if offset+size > uint64(len(m.store)) {
			panic("invalid memory: store empty")
		}
		copy(m.store[offset:offset+size], value)
	}
}

// Set32 sets the 32 bytes starting at offset to the value of val, left-padded with zeroes to
// 32 bytes.
func (m *Memory) Set32(offset uint64, val *uint256.Int) {
	// length of store may never be less than offset + size.
	// The store should be resized PRIOR to setting the memory
	if offset+32 > uint64(len(m.store)) {
		panic("invalid memory: store empty")
	}
	// Zero the memory area
	val.PutUint256(m.store[offset:])
}

// zeroes - pre-allocated zeroes for Resize()
var zeroes = make([]byte, 4*4096)

// Resize resizes the memory to size
func (m *Memory) Resize(size uint64) {
	l := int(size) - m.Len()
	if l <= 0 {
		return
	}
	if l >= len(zeroes) {
		m.store = append(m.store, make([]byte, l)...)
		return
	}
	m.store = append(m.store, zeroes[:l]...)
}

func (m *Memory) reset() {
	m.lastGasCost = 0
	m.store = m.store[:0]
}

// GetCopy returns offset + size as a new slice
func (m *Memory) GetCopy(offset, size uint64) (cpy []byte) {
	if size == 0 {
		return nil
	}

	// memory is always resized before being accessed, no need to check bounds
	cpy = make([]byte, size)
	copy(cpy, m.store[offset:offset+size])
	return
}

// GetPtr returns the offset + size
func (m *Memory) GetPtr(offset, size uint64) []byte {
	if size == 0 {
		return nil
	}

	// memory is always resized before being accessed, no need to check bounds
	return m.store[offset : offset+size]
}

// Len returns the length of the backing slice
func (m *Memory) Len() int {
	return len(m.store)
}

// Data returns the backing slice
func (m *Memory) Data() []byte {
	return m.store
}

// Copy copies data from the src position slice into the dst position.
// The source and destination may overlap.
// OBS: This operation assumes that any necessary memory expansion has already been performed,
// and this method may panic otherwise.
func (m *Memory) Copy(dst, src, len uint64) {
	if len == 0 {
		return
	}
	copy(m.store[dst:], m.store[src:src+len])
}
