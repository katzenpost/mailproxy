// api_kaetzchen.go - Katzenpost mailproxy Kaetzchen API.
// Copyright (C) 2018  Yawning Angel.
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU Affero General Public License as
// published by the Free Software Foundation, either version 3 of the
// License, or (at your option) any later version.
//
// This program is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
// GNU Affero General Public License for more details.
//
// You should have received a copy of the GNU Affero General Public License
// along with this program.  If not, see <http://www.gnu.org/licenses/>.

package mailproxy

import (
	"bytes"
	"encoding/hex"
	"errors"
	"fmt"
	"strings"

	"github.com/katzenpost/core/crypto/ecdh"
	"github.com/katzenpost/core/thwack"
	"github.com/ugorji/go/codec"
)

const (
	keyserverService = "keyserver"
	keyserverVersion = 0

	keyserverStatusOk          = 0
	keyserverStatusSyntaxError = 1
	keyserverStatusNoIdentity  = 2

	tetherService = "tether"
	tetherVersion = 0
)

var (
	// ErrKeyserverSyntaxError is the error returned when the keyserver
	// rejects a query due to a malformed request.
	ErrKeyserverSyntaxError = errors.New("keyserver: syntax error")

	// ErrNoIdentity is the error returned when the keyserver fails to
	// find the requested user, or the user's public key.
	ErrNoIdentity = errors.New("keyserver: user or public key not found")

	jsonHandle codec.JsonHandle
)

type keyserverRequest struct {
	Version int
	User    string
}

type keyserverResponse struct {
	Version    int
	StatusCode int
	User       string
	PublicKey  string
}

// QueryKeyFromProvider enqueues a keyserver lookup from the sender for the
// specified recipient and returns the message identifier tag.
func (p *Proxy) QueryKeyFromProvider(senderID, recipientID string) ([]byte, error) {
	acc, _, err := p.getAccount(senderID)
	if err != nil {
		return nil, err
	}
	defer acc.Deref()

	_, user, provider, err := p.recipients.Normalize(recipientID)
	if err != nil {
		return nil, err
	}

	var req = keyserverRequest{
		Version: keyserverVersion,
		User:    user,
	}
	var out []byte
	enc := codec.NewEncoderBytes(&out, &jsonHandle)
	enc.Encode(req)

	return p.SendKaetzchenRequest(senderID, keyserverService, provider, out, true)
}

// ParseKeyQueryResponse parses a response obtained from a key server query.
func (p *Proxy) ParseKeyQueryResponse(payload []byte) (string, *ecdh.PublicKey, error) {
	var resp keyserverResponse
	dec := codec.NewDecoderBytes(bytes.TrimRight(payload, "\x00"), &jsonHandle)
	if err := dec.Decode(&resp); err != nil {
		return "", nil, err
	}
	if err := keyserverStatusCodeToErr(resp.StatusCode); err != nil {
		return "", nil, err
	}

	pubKey := new(ecdh.PublicKey)
	if err := pubKey.FromString(resp.PublicKey); err != nil {
		return "", nil, err
	}

	return resp.User, pubKey, nil
}

func (p *Proxy) onQueryRecipient(c *thwack.Conn, l string) error {
	sp := strings.Split(l, " ")
	if len(sp) != 3 {
		c.Log().Debugf("QUERY_RECIPIENT invalid syntax: '%v'", l)
		return c.WriteReply(thwack.StatusSyntaxError)
	}

	tag, err := p.QueryKeyFromProvider(sp[1], sp[2])
	if err != nil {
		c.Log().Debugf("QUERY_RECIPIENT failed to enqueue: %v", err)
		return c.WriteReply(thwack.StatusTransactionFailed)
	}

	return c.Writer().PrintfLine("%v %v", thwack.StatusOk, hex.EncodeToString(tag))
}

type tetherRequest struct {
	Version      int
	User         string
	Authenticate string
	Command      string
	Sequence     int
}

type tetherResponse struct {
	Version    int
	StatusCode int
	QueueHint  int
	Sequence   int
	Payload    string
}

func (p *Proxy) genTetherAuthToken() (string, error) {
	return "", nil // XXX fix me
}

// GetTetherMessage retreives a message from a remote Provider,
// specified recipient and returns the message identifier tag.
func (p *Proxy) GetTetherMessage(senderID, remoteID string, sequence int) ([]byte, error) {
	_, user, provider, err := p.recipients.Normalize(remoteID)
	if err != nil {
		return nil, err
	}

	authToken, err := p.genTetherAuthToken()
	if err != nil {
		return nil, err
	}
	var req = tetherRequest{
		Version:      keyserverVersion,
		User:         user,
		Authenticate: authToken,
		Command:      "retrieve",
		Sequence:     0,
	}

	var out []byte
	enc := codec.NewEncoderBytes(&out, &jsonHandle)
	err = enc.Encode(req)
	if err != nil {
		p.log.Errorf("GetTetherMessage failed to encode kaetzchen message: %s", err)
		return nil, err
	}

	return p.SendKaetzchenRequest(senderID, tetherService, provider, out, true)
}

func keyserverStatusCodeToErr(statusCode int) error {
	switch statusCode {
	case keyserverStatusOk:
		return nil
	case keyserverStatusSyntaxError:
		return ErrKeyserverSyntaxError
	case keyserverStatusNoIdentity:
		return ErrNoIdentity
	default:
		return fmt.Errorf("keyserver: unknown status code: %v", statusCode)
	}
}

func init() {
	jsonHandle.Canonical = true
	jsonHandle.ErrorIfNoField = true
}
