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
	"io"

	"github.com/emersion/go-message"
)

// SenderIdentityHeader is mail header containing the Base64 representation
// of the sender's public key, set by the recipient upon successfully receiving
// a message.
const SenderIdentityHeader = "X-Katzenpost-Sender-Identity-Key"

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
