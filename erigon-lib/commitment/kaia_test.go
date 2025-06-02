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

package commitment

import (
	"context"
	"testing"

	"github.com/davecgh/go-spew/spew"
	"github.com/erigontech/erigon-lib/common"
	"github.com/erigontech/erigon-lib/common/hexutil"
	"github.com/stretchr/testify/require"
)

type accountsTC []struct {
	addressHex string
	accountHex string
}

func TestKaia_RootHash(t *testing.T) {
	/* Sample accounts from Kairos block #1 state.
	// = https://github.com/kaiachain/kaia/blob/dev/blockchain/genesis_alloc.go + 9.6 KAIA to the proposer.
	accs := []accounts.Account{
		{ // 0x0000000000000000000000000000000000000400
			CodeHash: common.HexToHash("0x6c39846f5ab402760078b7bfd16c99e687c75bcb5ec65ac8f3054bad18136f09"),
			Root:     common.HexToHash("0x56e81f171bcc55a6ff8345e692c0f86e5b48e01b996cadc001622fb5e363b421"),
		},
		{ // 0x4937a6f664630547f6b0c3c235c4f03a64ca36b1
			Balance: *uint256.MustFromHex("0x446c3b15f9926687d2c40534fdb564000000000000"),
		},
		{ // 0xb74ff9dea397fe9e231df545eb53fe2adf776cb2
			Balance: *uint256.NewInt(0x853a0d2313c00000),
		},
	}
	for _, acc := range accs {
		ser := accounts.SerialiseV3(&acc)
		fmt.Printf("serialised account: %x\n", ser)
	}
	t.Fatal(0)
	return
	*/

	testcases := []struct {
		accounts accountsTC
		hash     common.Hash
	}{
		{ // Kairos block #1 state, ErigonV3 encoding
			accountsTC{
				{"0x0000000000000000000000000000000000000400", "0x0000206c39846f5ab402760078b7bfd16c99e687c75bcb5ec65ac8f3054bad18136f0900"},
				{"0x4937a6f664630547f6b0c3c235c4f03a64ca36b1", "0x0015446c3b15f9926687d2c40534fdb5640000000000000000"},
				{"0xb74ff9dea397fe9e231df545eb53fe2adf776cb2", "0x0008853a0d2313c000000000"},
			},
			common.HexToHash("0xa6378e8c64dffd18348e9a2168deecd94aacf4adc9945b1a455284989c3efb40"),
		},
	}

	for _, tc := range testcases {
		ctx := context.Background()
		ms := NewMockState(t)
		hph := NewHexPatriciaHashed(1, ms, ms.TempDir())
		hph.SetTrace(true)

		upd := NewUpdates(ModeUpdate, t.TempDir(), KeyToHexNibbleHash)
		for _, account := range tc.accounts {
			upd.TouchPlainKey(account.addressHex, hexutil.MustDecode(account.accountHex), upd.TouchAccount)
		}
		spew.Dump(upd)

		rootHash, err := hph.Process(ctx, upd, "")
		require.NoError(t, err)
		require.Equal(t, tc.hash.Hex(), common.BytesToHash(rootHash).Hex())
	}
}
