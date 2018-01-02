// imf.go - Internet Message Format related routines.
// Copyright (C) 2017  Yawning Angel.
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

// Package imf implements useful routines for dealing with the Internet Message
// Format as used by Katzenpost.
package imf

import (
	"bytes"
	"fmt"
	"io"

	"github.com/emersion/go-message"
)

// SenderIdentityHeader is mail header containing the Base64 representation
// of the sender's public key, set by the recipient upon successfully receiving
// a message.
const SenderIdentityHeader = "X-Katzenpost-Sender-Identity-Key"

var proscribedHeaders = []string{
	SenderIdentityHeader,
}

// BytesToEntity de-serializes a byte buffer to a message.Entity, while doing
// some basic sanity checking for RFC 5322 compliance.
func BytesToEntity(b []byte) (*message.Entity, error) {
	// RFC 5322 2.1 - Mandates US-ASCII encoding.  This doesn't mean that
	// users can't send binary data or non-English, it just means that they
	// need to use MIME.
	for _, v := range b {
		if v == 0 || v > 0x7f {
			return nil, fmt.Errorf("octet '%x' is not US-ASCII", v)
		}
	}

	// BUG/#6: If we decide to enforce line length restrictions on incoming
	// messages, this would be the logical place to do so (RFC 5322 2.1.1).

	// This returns an entity with the header parsed, but the entirety of the
	// body left unexamined, because parsing muti-part MIME is fraught with
	// peril, particularly if the input is hostile.
	e, err := message.Read(bytes.NewReader(b))
	if err != nil {
		// The parser is overly verbose and includes snippets of the payload,
		// which is probably not a good idea to propagate everywhere.
		return nil, fmt.Errorf("failed to parse message headers")
	}

	return e, nil
}

// EntityToBytes re-serializes a message.Entity into a byte slice suitable for
// storage or presentation to the user.  It assumes that e.Body points to an
// io.Reader containing the entire flattened body.
//
// Note: Unique message header fields will get reordered due to the backing
// implementation being a map.  This is spec compliant (RFC 5322 3.6), though
// the RFC strongly recommends against doing so at a `SHOULD NOT` level.
func EntityToBytes(e *message.Entity) ([]byte, error) {
	var b bytes.Buffer

	w, err := message.CreateWriter(&b, e.Header)
	if err != nil {
		return nil, err
	}

	// The message package's transformation example recursively parses
	// all of the parts for multipart bodies, but all we want to do is
	// examine and alter the headers.
	io.Copy(w, e.Body)

	return b.Bytes(), nil
}

// ValidateHeaders sanity checks an IMF message to ensure that none of the
// proscribed headers are defined.
func ValidateHeaders(e *message.Entity) error {
	for _, k := range proscribedHeaders {
		if e.Header.Get(k) != "" {
			return fmt.Errorf("forbidden header '%v' defined", k)
		}
	}
	return nil
}
