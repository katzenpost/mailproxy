// report.go - multipart/report generator.
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

package imf

import (
	"bytes"
	"encoding/base64"
	"fmt"
	"io"
	"time"

	"github.com/emersion/go-message"
	"github.com/katzenpost/core/crypto/ecdh"
)

var (
	multipartReportContentTypeParams = map[string]string{
		"report-type": "delivery-status",
	}

	multipartStatusPerMessage = message.Header{
		"Reporting-MTA": []string{"dns; " + LocalName},
	}
)

// ReportPart is the third part(s) of a multipart/report containing the
// message body.
type ReportPart struct {
	Header message.Header
	Body   io.Reader
}

// HACK
//
// The go-message package includes a self-contained function to output
// Header to a writer while following the line length limits for IMF,
// but they don't export it.  Thankfully it seems to cope with something
// like this.
func writeHeader(w io.Writer, h message.Header) error {
	e, err := message.New(h, bytes.NewReader([]byte{}))
	if err != nil {
		return err
	}
	return e.WriteTo(w)
}

func newMultipartReportHeader(toAddr, subject string) message.Header {
	h := make(message.Header)

	h.Set("From", "Katzenpost Postmaster <postmaster@"+LocalName+">")
	h.Set("To", "<"+toAddr+">")
	h.Set("Date", time.Now().UTC().Format(dateFmt))
	h.SetContentType("multipart/report", multipartReportContentTypeParams)
	h.Set("Subject", subject)
	doAddMessageID(h)

	return h
}

func newMultipartReport(toAddr, subject, humanReadable string, perRecipient []message.Header, returned []*ReportPart) ([]byte, error) {
	var b bytes.Buffer

	// Create the top level writer.
	h := newMultipartReportHeader(toAddr, subject)
	mw, err := message.CreateWriter(&b, h)
	if err != nil {
		return nil, err
	}

	// (REQUIRED) The first body part contains a human-readable message.
	ph := make(message.Header)
	ph.SetContentType("text/plain", nil)
	pw, err := mw.CreatePart(ph)
	if err != nil {
		return nil, err
	}
	io.WriteString(pw, humanReadable)
	pw.Close()

	// (REQUIRED) A machine-parsable body part containing an account of
	// the reported message handling event.
	ph = make(message.Header)
	ph.SetContentType("message/delivery-status", nil)
	pw, err = mw.CreatePart(ph)
	if err != nil {
		return nil, err
	}
	writeHeader(pw, multipartStatusPerMessage)
	for _, v := range perRecipient {
		writeHeader(pw, v)
	}
	pw.Close()

	// (OPTIONAL) A body part containing the returned message or a
	// portion thereof.
	for _, v := range returned {
		pw, err = mw.CreatePart(v.Header)
		if err != nil {
			return nil, err
		}
		io.Copy(pw, v.Body)
		pw.Close()
	}

	mw.Close()
	return b.Bytes(), nil
}

// NewDecryptionFailure creates a new mutipart/report message to be used to
// indicate a receiver side decryption failure.
func NewDecryptionFailure(toAddr string, ciphertext []byte) ([]byte, error) {
	const humanReadable = `This message was created automatically by the Katzenpost Mail Proxy.

A remote peer sent a ciphertext to this account that was impossible to
decrypt with the account's Identity Key.

This is a permament error, and no action is required on your part.
A copy of the undecipherable ciphertext is included as an attachment.
`

	perRecipient := make(message.Header)
	perRecipient.Set("Final-Recipient", "rfc822;"+toAddr)
	perRecipient.Set("Status", "5.7.5 (Cryptographic failure)")
	perRecipient.Set("Action", "delivered")

	p := &ReportPart{
		Header: message.Header{
			"Content-Type":              []string{"application/octet-string"},
			"Content-Transfer-Encoding": []string{"base64"},
			"Content-Disposition":       []string{"attachment; filename=ciphertext.bin"},
		},
		Body: bytes.NewReader(ciphertext),
	}

	return newMultipartReport(toAddr, "Message decryption failure", humanReadable, []message.Header{perRecipient}, []*ReportPart{p})
}

// NewMalformedIMF creates a new multipart/report message to be used to
// indicate a receiver side IMF de-serialization failure.
func NewMalformedIMF(toAddr string, sender *ecdh.PublicKey, payload []byte) ([]byte, error) {
	const humanReadable = `This message was created automatically by the Katzenpost Mail Proxy.

A remote peer sent a message that does not appear to be a well-formed
Internet Message Format document.

This is a permanent error, and no action is required on your part.
A copy of the malformed message is included as an attachment.

The sender's public key was: %v
`
	hrStr := fmt.Sprintf(humanReadable, base64.StdEncoding.EncodeToString(sender.Bytes()))

	perRecipient := make(message.Header)
	perRecipient.Set("Final-Recipient", "rfc822;"+toAddr)
	perRecipient.Set("Status", "5.6.1 (Media not supported)")
	perRecipient.Set("Action", "delivered")

	p := &ReportPart{
		Header: message.Header{
			"Content-Type":              []string{"application/octet-string"},
			"Content-Transfer-Encoding": []string{"base64"},
			"Content-Disposition":       []string{"attachment; filename=message_malformed.bin"},
		},
		Body: bytes.NewReader(payload),
	}

	return newMultipartReport(toAddr, "Malformed message, Not IMF", hrStr, []message.Header{perRecipient}, []*ReportPart{p})
}

// NewForbiddenHeaders creates a new multipart/report message to be used to
// indicate a receiver side header validation failure.
func NewForbiddenHeaders(toAddr string, sender *ecdh.PublicKey, payload []byte) ([]byte, error) {
	const humanReadable = `This message was created automatically by the Katzenpost Mail Proxy.

A remote peer sent a message containing headers that are forbidden by
the Katzenpost specification.  This may be a sign that the peer is
attempting to maliciously impersonate another sender.

This is a permanent error, and no action is required on your part.
A copy of the malformed message is included as an attachment.

The sender's public key was: %v
`
	hrStr := fmt.Sprintf(humanReadable, base64.StdEncoding.EncodeToString(sender.Bytes()))

	perRecipient := make(message.Header)
	perRecipient.Set("Final-Recipient", "rfc822;"+toAddr)
	perRecipient.Set("Status", "5.7.7 (Message integrity failure)")
	perRecipient.Set("Action", "delivered")

	p := &ReportPart{
		Header: message.Header{
			"Content-Type":              []string{"application/octet-string"},
			"Content-Transfer-Encoding": []string{"base64"},
			"Content-Disposition":       []string{"attachment; filename=message_spoofed.bin"},
		},
		Body: bytes.NewReader(payload),
	}

	return newMultipartReport(toAddr, "Malformed message, spoofed sender", hrStr, []message.Header{perRecipient}, []*ReportPart{p})
}

// NewReserializationFailure creates a new multipart/report message to be used
// to indicate a receiver side re-serialization failure.
func NewReserializationFailure(toAddr string, sender *ecdh.PublicKey, payload []byte) ([]byte, error) {
	const humanReadable = `This message was created automatically by the Katzenpost Mail Proxy.

A failure was encountered when processing an incoming message that
appeared to be valid.  This is likely a bug in the Katzenpost Mail
Proxy.

This is a permanent error, and no action is required on your part.
A copy of the malformed message is included as an attachment.

The sender's public key was: %v
`
	hrStr := fmt.Sprintf(humanReadable, base64.StdEncoding.EncodeToString(sender.Bytes()))

	perRecipient := make(message.Header)
	perRecipient.Set("Final-Recipient", "rfc822;"+toAddr)
	perRecipient.Set("Status", "5.6.0 (Other or undefined media error)")
	perRecipient.Set("Action", "delivered")

	p := &ReportPart{
		Header: message.Header{
			"Content-Type":              []string{"application/octet-string"},
			"Content-Transfer-Encoding": []string{"base64"},
			"Content-Disposition":       []string{"attachment; filename=message.bin"},
		},
		Body: bytes.NewReader(payload),
	}

	return newMultipartReport(toAddr, "Internal mail proxy error", hrStr, []message.Header{perRecipient}, []*ReportPart{p})
	return nil, nil
}
