// Copyright 2024 The Erigon Authors
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

package p2p

import (
	"github.com/erigontech/erigon-lib/event"
	"github.com/erigontech/erigon-lib/gointerfaces/sentryproto"
	"github.com/erigontech/erigon-p2p/protocols/eth"
)

//go:generate mockgen -typed=true -source=./peer_event_registrar.go -destination=./peer_event_registrar_mock.go -package=p2p
type peerEventRegistrar interface {
	RegisterPeerEventObserver(observer event.Observer[*sentryproto.PeerEvent]) UnregisterFunc
	RegisterNewBlockObserver(observer event.Observer[*DecodedInboundMessage[*eth.NewBlockPacket]]) UnregisterFunc
	RegisterNewBlockHashesObserver(observer event.Observer[*DecodedInboundMessage[*eth.NewBlockHashesPacket]]) UnregisterFunc
}
