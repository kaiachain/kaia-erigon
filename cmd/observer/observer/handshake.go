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

package observer

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"fmt"
	"math/big"
	"net"
	"time"

	"github.com/erigontech/erigon-lib/common"
	"github.com/erigontech/erigon-lib/crypto"
	"github.com/erigontech/erigon-lib/direct"
	"github.com/erigontech/erigon-lib/rlp"
	p2p "github.com/erigontech/erigon-p2p"
	"github.com/erigontech/erigon-p2p/forkid"
	"github.com/erigontech/erigon-p2p/protocols/eth"
	"github.com/erigontech/erigon-p2p/rlpx"
	"github.com/erigontech/erigon/params"
)

// https://github.com/ethereum/devp2p/blob/master/rlpx.md#p2p-capability
const (
	RLPxMessageIDHello      = 0
	RLPxMessageIDDisconnect = 1
	RLPxMessageIDPing       = 2
	RLPxMessageIDPong       = 3
)

// HelloMessage is the RLPx Hello message.
// (same as protoHandshake in p2p/peer.go)
// https://github.com/ethereum/devp2p/blob/master/rlpx.md#hello-0x00
type HelloMessage struct {
	Version    uint64
	ClientID   string
	Caps       []p2p.Cap
	ListenPort uint64
	Pubkey     []byte // secp256k1 public key

	// Ignore additional fields (for forward compatibility).
	Rest []rlp.RawValue `rlp:"tail"`
}

// StatusMessage is the Ethereum Status message v63+.
// (same as StatusPacket in eth/protocols/eth/protocol.go)
// https://github.com/ethereum/devp2p/blob/master/caps/eth.md#status-0x00
type StatusMessage struct {
	ProtocolVersion uint32
	NetworkID       uint64
	TD              *big.Int
	Head            common.Hash
	Genesis         common.Hash
	ForkID          *forkid.ID     `rlp:"-"` // parsed from Rest if exists in v64+
	Rest            []rlp.RawValue `rlp:"tail"`
}

type HandshakeErrorID string

const (
	HandshakeErrorIDConnect           HandshakeErrorID = "connect"
	HandshakeErrorIDSetTimeout        HandshakeErrorID = "set-timeout"
	HandshakeErrorIDAuth              HandshakeErrorID = "auth"
	HandshakeErrorIDRead              HandshakeErrorID = "read"
	HandshakeErrorIDUnexpectedMessage HandshakeErrorID = "unexpected-message"
	HandshakeErrorIDDisconnectDecode  HandshakeErrorID = "disconnect-decode"
	HandshakeErrorIDDisconnect        HandshakeErrorID = "disconnect"
	HandshakeErrorIDHelloEncode       HandshakeErrorID = "hello-encode"
	HandshakeErrorIDHelloDecode       HandshakeErrorID = "hello-decode"
	HandshakeErrorIDStatusDecode      HandshakeErrorID = "status-decode"
)

type HandshakeError struct {
	id         HandshakeErrorID
	wrappedErr error
	param      uint64
}

func NewHandshakeError(id HandshakeErrorID, wrappedErr error, param uint64) *HandshakeError {
	instance := HandshakeError{
		id,
		wrappedErr,
		param,
	}
	return &instance
}

func (e *HandshakeError) Unwrap() error {
	return e.wrappedErr
}

func (e *HandshakeError) Error() string {
	switch e.id {
	case HandshakeErrorIDConnect:
		return fmt.Sprintf("handshake failed to connect: %v", e.wrappedErr)
	case HandshakeErrorIDSetTimeout:
		return fmt.Sprintf("handshake failed to set timeout: %v", e.wrappedErr)
	case HandshakeErrorIDAuth:
		return fmt.Sprintf("handshake RLPx auth failed: %v", e.wrappedErr)
	case HandshakeErrorIDRead:
		return fmt.Sprintf("handshake RLPx read failed: %v", e.wrappedErr)
	case HandshakeErrorIDUnexpectedMessage:
		return fmt.Sprintf("handshake got unexpected message ID: %d", e.param)
	case HandshakeErrorIDDisconnectDecode:
		return fmt.Sprintf("handshake failed to parse disconnect reason: %v", e.wrappedErr)
	case HandshakeErrorIDDisconnect:
		return fmt.Sprintf("handshake got disconnected: %v", e.wrappedErr)
	case HandshakeErrorIDHelloEncode:
		return fmt.Sprintf("handshake failed to encode outgoing Hello message: %v", e.wrappedErr)
	case HandshakeErrorIDHelloDecode:
		return fmt.Sprintf("handshake failed to parse Hello message: %v", e.wrappedErr)
	case HandshakeErrorIDStatusDecode:
		return fmt.Sprintf("handshake failed to parse Status message: %v", e.wrappedErr)
	default:
		return "<unhandled HandshakeErrorID>"
	}
}

func (e *HandshakeError) StringCode() string {
	switch e.id {
	case HandshakeErrorIDUnexpectedMessage:
		fallthrough
	case HandshakeErrorIDDisconnect:
		return fmt.Sprintf("%s-%d", e.id, e.param)
	default:
		return string(e.id)
	}
}

func Handshake(
	ctx context.Context,
	ip net.IP,
	rlpxPort int,
	pubkey *ecdsa.PublicKey,
	myPrivateKey *ecdsa.PrivateKey,
) (*HelloMessage, *StatusMessage, *HandshakeError) {
	connectTimeout := 10 * time.Second
	dialer := net.Dialer{
		Timeout: connectTimeout,
	}
	addr := net.TCPAddr{IP: ip, Port: rlpxPort}

	tcpConn, err := dialer.DialContext(ctx, "tcp", addr.String())
	if err != nil {
		return nil, nil, NewHandshakeError(HandshakeErrorIDConnect, err, 0)
	}

	conn := rlpx.NewConn(tcpConn, pubkey)
	defer func() { _ = conn.Close() }()

	handshakeTimeout := 5 * time.Second
	handshakeDeadline := time.Now().Add(handshakeTimeout)
	err = conn.SetDeadline(handshakeDeadline)
	if err != nil {
		return nil, nil, NewHandshakeError(HandshakeErrorIDSetTimeout, err, 0)
	}
	err = conn.SetWriteDeadline(handshakeDeadline)
	if err != nil {
		return nil, nil, NewHandshakeError(HandshakeErrorIDSetTimeout, err, 0)
	}

	_, err = conn.Handshake(myPrivateKey)
	if err != nil {
		return nil, nil, NewHandshakeError(HandshakeErrorIDAuth, err, 0)
	}

	ourHelloMessage := makeOurHelloMessage(myPrivateKey)
	ourHelloData, err := rlp.EncodeToBytes(&ourHelloMessage)
	if err != nil {
		return nil, nil, NewHandshakeError(HandshakeErrorIDHelloEncode, err, 0)
	}
	go func() { _, _ = conn.Write(RLPxMessageIDHello, ourHelloData) }()

	var helloMessage HelloMessage
	if err := readMessage(conn, RLPxMessageIDHello, HandshakeErrorIDHelloDecode, &helloMessage); err != nil {
		return nil, nil, err
	}

	// All messages following Hello are compressed using the Snappy algorithm.
	if helloMessage.Version >= 5 {
		conn.SetSnappy(true)
	}

	var statusMessage StatusMessage
	if err := readMessage(conn, 16+eth.StatusMsg, HandshakeErrorIDStatusDecode, &statusMessage); err != nil {
		return &helloMessage, nil, err
	}

	// parse fork ID
	if (statusMessage.ProtocolVersion >= 64) && (len(statusMessage.Rest) > 0) {
		var forkID forkid.ID
		if err := rlp.DecodeBytes(statusMessage.Rest[0], &forkID); err != nil {
			return &helloMessage, nil, NewHandshakeError(HandshakeErrorIDStatusDecode, err, 0)
		}
		statusMessage.ForkID = &forkID
	}

	return &helloMessage, &statusMessage, nil
}

func readMessage(conn *rlpx.Conn, expectedMessageID uint64, decodeError HandshakeErrorID, message interface{}) *HandshakeError {
	messageID, data, _, err := conn.Read()
	if err != nil {
		return NewHandshakeError(HandshakeErrorIDRead, err, 0)
	}

	if messageID == RLPxMessageIDPing {
		pongData, _ := rlp.EncodeToBytes(make([]string, 0, 1))
		go func() { _, _ = conn.Write(RLPxMessageIDPong, pongData) }()
		return readMessage(conn, expectedMessageID, decodeError, message)
	}
	if messageID == 16+eth.GetPooledTransactionsMsg {
		return readMessage(conn, expectedMessageID, decodeError, message)
	}
	if messageID == RLPxMessageIDDisconnect {
		reason, err := p2p.DisconnectMessagePayloadDecode(bytes.NewBuffer(data))
		if err != nil {
			return NewHandshakeError(HandshakeErrorIDDisconnectDecode, err, 0)
		}
		return NewHandshakeError(HandshakeErrorIDDisconnect, reason, uint64(reason))
	}
	if messageID != expectedMessageID {
		return NewHandshakeError(HandshakeErrorIDUnexpectedMessage, nil, messageID)
	}

	if err = rlp.DecodeBytes(data, message); err != nil {
		return NewHandshakeError(decodeError, err, 0)
	}
	return nil
}

func makeOurHelloMessage(myPrivateKey *ecdsa.PrivateKey) HelloMessage {
	version := params.VersionWithCommit(params.GitCommit)
	clientID := common.MakeName("observer", version)

	caps := []p2p.Cap{
		{Name: eth.ProtocolName, Version: direct.ETH67},
		{Name: eth.ProtocolName, Version: direct.ETH68},
	}

	return HelloMessage{
		Version:    5,
		ClientID:   clientID,
		Caps:       caps,
		ListenPort: 0, // not listening
		Pubkey:     crypto.MarshalPubkey(&myPrivateKey.PublicKey),
	}
}
