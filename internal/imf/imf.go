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
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"io"
	"io/ioutil"
	"strconv"
	"time"

	"github.com/emersion/go-message"
	"github.com/katzenpost/core/crypto/rand"
)

const (
	// SenderIdentityHeader is mail header containing the Base64 representation
	// of the sender's public key, set by the recipient upon successfully
	// receiving a message.
	SenderIdentityHeader = "X-Katzenpost-Sender-Identity-Key"

	// LocalName is the common hostname used by mail proxy instances.
	LocalName = "katzenpost.localhost"

	dateFmt = "Mon, 02 Jan 2006 15:04:05 -0700 (UTC)"
)

var proscribedHeaders = []string{
	SenderIdentityHeader,
}

// BytesToEntity de-serializes a byte buffer to a message.Entity.
func BytesToEntity(b []byte) (*message.Entity, error) {
	// RFC 5322 2.1 - Mandates US-ASCII encoding, but the reality is that
	// everyone expects either 8BITMIME support, or 8 bit messages to just
	// work, so no enforcement is done.

	// This returns an entity with the header parsed, but the entirety of the
	// body left unexamined, because parsing muti-part MIME is fraught with
	// peril, particularly if the input is hostile, and we want to examine
	// the body as is afterwards.
	e, err := message.Read(bytes.NewReader(b))
	if err != nil {
		// The parser is overly verbose and includes snippets of the payload,
		// which is probably not a good idea to propagate everywhere.
		return nil, fmt.Errorf("failed to parse message headers")
	}

	// RFC 5322 2.1.1 - Mandates lines less than or equal to 998 characters,
	// but there's enough broken things out there that enforcing this will
	// lead to problems, and the POP3 code should support arbitrary length
	// lines.

	// RFC 7103 6 - "Thus, it will typically be safe and helpful to treat an
	// isolated CR or LF as equivalent to a CRLF when parsing a message."
	body, err := ioutil.ReadAll(e.Body)
	if err != nil {
		return nil, fmt.Errorf("internal error reading message body")
	}
	body = ToCRLF(body)
	e.Body = bytes.NewReader(body)

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

// ToCRLF attempts to canonicalize the buffer to have the IMF CRLF line endings
// by converting `\n` octets not immediately preceeded by a `\r` to `\r\n`.
func ToCRLF(b []byte) []byte {
	var dst bytes.Buffer
	dst.Grow(len(b))

	wasCR := false
	for _, c := range b {
		if c == '\n' {
			if !wasCR {
				dst.WriteByte('\r')
			}
		}
		wasCR = c == '\r'
		dst.WriteByte(c)
	}
	return dst.Bytes()
}

// AddMessageID sets the `Message-ID` header if one is not already present in
// the Entity's header block.
func AddMessageID(e *message.Entity) {
	const (
		tsFmt           = "20060102150405"
		messageIDHeader = "Message-ID"
	)
	if e.Header.Get(messageIDHeader) != "" {
		return
	}

	// Generate one following the traditional way of doing such things, based
	// on JWZ and Matt Curtin's IETF draft.
	tsPart := time.Now().UTC().Format(tsFmt)

	var randBytes [8]byte
	io.ReadFull(rand.Reader, randBytes[:])
	randUint := binary.LittleEndian.Uint64(randBytes[:])
	randPart := strconv.FormatUint(randUint, 36)

	msgID := "<" + tsPart + "." + randPart + "@" + LocalName + ">"
	e.Header.Set(messageIDHeader, msgID)
}

// AddReceived prepends a `Received` header entry based on the supplied
// position and protocol.
func AddReceived(e *message.Entity, isMSA bool, viaESMTP bool) {
	const receivedHeader = "Received"

	var hdrStr string
	if isMSA {
		hdrStr = "from localhost (localhost [127.0.0.1]) "
	} else {
		hdrStr = "from mixnetwork.invalid (mixnetwork.invalid [127.0.0.2]) "
	}
	hdrStr += "by " + LocalName + " (Katzenpost mailproxy) "
	if viaESMTP {
		hdrStr += "with ESMTP "
	} else {
		hdrStr += "with SMTP "
	}

	var randID [5]byte
	io.ReadFull(rand.Reader, randID[:])
	hdrStr += "id " + hex.EncodeToString(randID[:]) + " "
	hdrStr += "for <recipient@anonymous.invalid>; " + time.Now().UTC().Format(dateFmt)

	e.Header[receivedHeader] = append([]string{hdrStr}, e.Header[receivedHeader]...)
}
