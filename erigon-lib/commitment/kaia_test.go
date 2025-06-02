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
	"github.com/erigontech/erigon-lib/common/length"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

type accountsTC []struct {
	addressHex string
	accountHex string
}

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

func TestKaia_RootHash(t *testing.T) {
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
			common.HexToHash("0x2e3360035cfdedcf87082405607284572e3df196954133ea713c343c9bc80d73"),
		},
		{ // Kairos block #1 state, Kaia RLP encoding / incremental (1/3)
			accountsTC{
				{"0x0000000000000000000000000000000000000400", "0x02f849c580808003c0a056e81f171bcc55a6ff8345e692c0f86e5b48e01b996cadc001622fb5e363b421a06c39846f5ab402760078b7bfd16c99e687c75bcb5ec65ac8f3054bad18136f0980"},
			},
			common.HexToHash("0xfbf14f63f97468e460a42b309bbad44fdc682ab3a7f95fa5d3508c9cf0009946"),
		},
		{ // Kairos block #1 state, Kaia RLP encoding / incremental (2/3)
			accountsTC{
				{"0x0000000000000000000000000000000000000400", "0x02f849c580808003c0a056e81f171bcc55a6ff8345e692c0f86e5b48e01b996cadc001622fb5e363b421a06c39846f5ab402760078b7bfd16c99e687c75bcb5ec65ac8f3054bad18136f0980"},
				{"0x4937a6f664630547f6b0c3c235c4f03a64ca36b1", "0x01da8095446c3b15f9926687d2c40534fdb5640000000000008001c0"},
			},
			common.HexToHash("0xbe751ffacf5fcf9998d4f90b87164ff95166d55e445c8d27cfecbe0e67a032b6"),
		},
		{ // Kairos block #1 state, Kaia RLP encoding / incremental (3/3)
			accountsTC{
				{"0x0000000000000000000000000000000000000400", "0x02f849c580808003c0a056e81f171bcc55a6ff8345e692c0f86e5b48e01b996cadc001622fb5e363b421a06c39846f5ab402760078b7bfd16c99e687c75bcb5ec65ac8f3054bad18136f0980"},
				{"0x4937a6f664630547f6b0c3c235c4f03a64ca36b1", "0x01da8095446c3b15f9926687d2c40534fdb5640000000000008001c0"},
				{"0xb74ff9dea397fe9e231df545eb53fe2adf776cb2", "0x01cd8088853a0d2313c000008001c0"},
			},
			common.HexToHash("0x60e8f25e2fb479e625347c1f11e2f07c9cd7d0a5320013294d89281b6fceed4f"),
		},
		{
			accountsTC{
				{"0xd293f7799bd6c75b82c2802542e2999c14f47e35", "0x01c580648001c0"},
				{"0xebbbacfb87fbfdec9011cfad2462782b3f8a8d88", "0x01c564808001c0"},
				{"0xde20ec601c1d770a9ec6e89b2639cd63203514c4", "0x01f849c580808001c0a056e81f171bcc55a6ff8345e692c0f86e5b48e01b996cadc001622fb5e363b421a0de75942ed4731d491798b4a82bc5937553e715a97b76fc5987e35ee3cd2ee68380"},
				// {"0xe8170332ea5a606146e5a9e9deb8dcec0287047c", "0x01c580808001c0"},
				// {"0xfe90e344274e129d656e03ffd0d0dc0b6518788d", "0x01e680640102a1038318535b54105d4a7aae60c08fc45f9687181b4fdfc625bd1a753fa7397fed75"},
				// {"0x7bdf109bf068c37c97d5c84196417e034320f3fc", "0x01c781c881c88001c0"},
				// {"0x69470b1abc45767a122bc5ebb6d8a1c97e4ff935", "0x01f84bc782012c808001c0a056e81f171bcc55a6ff8345e692c0f86e5b48e01b996cadc001622fb5e363b421a0d058a2d3336759c22976856de49b828b8282e64b9d2b2d0d0d94fc44928d8e4c80"},
				// {"0x115cd038daf5cc477c7116beab167e550f41b0d4", "0x01c7820190808001c0"},
				// {"0x74ef9c1339963462581a5b96720711e7cfec22eb", "0x01f84bc7808201f48001c0a056e81f171bcc55a6ff8345e692c0f86e5b48e01b996cadc001622fb5e363b421a067cbae6de159c9d9be7017bb0a3b6be6770c0233c5f4d476523728e0520ca7bb80"},
				// {"0x5d76c9950b78dcfa47ec195f56d11a4afa8708f3", "0x01f84dc98202588202588001c0a056e81f171bcc55a6ff8345e692c0f86e5b48e01b996cadc001622fb5e363b421a02a5787ab5c11885b8b30f1a3aea5c05d48e17eb18f94210555e34a3a965b655a80"},
			},
			//common.HexToHash("0x1f359a878bdea26f8eecaa6b6fff8306b870d4b3b18871975aebc68f12c8ea51"),
			common.HexToHash("0x4a4669650a2fa9da4ac84e32240bf5f780d04a95d277c48f244536c64b8742cc"),
		},
	}

	for i, tc := range testcases {
		if i != 4 {
			continue
		}
		upd := NewUpdates(ModeUpdate, t.TempDir(), KeyToHexNibbleHash)
		for _, account := range tc.accounts {
			upd.TouchPlainKey(string(hexutil.MustDecode(account.addressHex)), hexutil.MustDecode(account.accountHex), upd.TouchAccount)
		}

		ctx := context.Background()
		ms := NewMockState(t)
		hph := NewHexPatriciaHashed(length.Addr, ms, ms.TempDir())
		hph.SetTrace(testing.Verbose())

		rootHash, err := hph.Process(ctx, upd, "")
		spew.Dump(hph.grid)
		require.NoError(t, err, i)
		assert.Equal(t, tc.hash.Hex(), common.BytesToHash(rootHash).Hex(), i)
	}
	t.Fail()
}

func TestKaia_RestoreState(t *testing.T) {
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
			common.HexToHash("0x2e3360035cfdedcf87082405607284572e3df196954133ea713c343c9bc80d73"),
		},
		{ // Kairos block #1 state, Kaia RLP encoding / incremental (3/3)
			accountsTC{
				{"0x0000000000000000000000000000000000000400", "0x02f849c580808003c0a056e81f171bcc55a6ff8345e692c0f86e5b48e01b996cadc001622fb5e363b421a06c39846f5ab402760078b7bfd16c99e687c75bcb5ec65ac8f3054bad18136f0980"},
				{"0x4937a6f664630547f6b0c3c235c4f03a64ca36b1", "0x01da8095446c3b15f9926687d2c40534fdb5640000000000008001c0"},
				{"0xb74ff9dea397fe9e231df545eb53fe2adf776cb2", "0x01cd8088853a0d2313c000008001c0"},
			},
			common.HexToHash("0x60e8f25e2fb479e625347c1f11e2f07c9cd7d0a5320013294d89281b6fceed4f"),
		},
	}

	for i, tc := range testcases {
		upd := NewUpdates(ModeUpdate, t.TempDir(), KeyToHexNibbleHash)
		for _, account := range tc.accounts {
			upd.TouchPlainKey(string(hexutil.MustDecode(account.addressHex)), hexutil.MustDecode(account.accountHex), upd.TouchAccount)
		}

		// 1. From the clean hph, apply the updates.
		ctx := context.Background()
		ms := NewMockState(t)
		hph1 := NewHexPatriciaHashed(length.Addr, ms, ms.TempDir())
		hph1.SetTrace(testing.Verbose())

		rootHash, err := hph1.Process(ctx, upd, "")
		require.NoError(t, err, i)
		assert.Equal(t, tc.hash.Hex(), common.BytesToHash(rootHash).Hex(), i)

		// 2. Dump the hph state.
		hphState, err := hph1.EncodeCurrentState(nil)
		require.NoError(t, err, i)
		spew.Dump(hphState)

		// 3. New clean hph, load the state.
		hph2 := NewHexPatriciaHashed(length.Addr, ms, ms.TempDir())
		hph2.SetTrace(testing.Verbose())
		hph2.SetState(hphState)

		rootHash2, err := hph2.RootHash()
		require.NoError(t, err, i)
		assert.Equal(t, tc.hash.Hex(), common.BytesToHash(rootHash2).Hex(), i)
	}
}
