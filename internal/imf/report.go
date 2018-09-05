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

type reportPart struct {
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

func newMultipartReport(toAddr, subject, humanReadable string, perRecipient []message.Header, returned *reportPart) ([]byte, error) {
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
	if returned != nil {
		pw, err = mw.CreatePart(returned.Header)
		if err != nil {
			return nil, err
		}
		io.Copy(pw, returned.Body)
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

	p := &reportPart{
		Header: message.Header{
			"Content-Type":              []string{"application/octet-string"},
			"Content-Transfer-Encoding": []string{"base64"},
			"Content-Disposition":       []string{"attachment; filename=ciphertext.bin"},
		},
		Body: bytes.NewReader(ciphertext),
	}

	return newMultipartReport(toAddr, "Message decryption failure", humanReadable, []message.Header{perRecipient}, p)
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

	p := &reportPart{
		Header: message.Header{
			"Content-Type":              []string{"application/octet-string"},
			"Content-Transfer-Encoding": []string{"base64"},
			"Content-Disposition":       []string{"attachment; filename=message_malformed.bin"},
		},
		Body: bytes.NewReader(payload),
	}

	return newMultipartReport(toAddr, "Malformed message, Not IMF", hrStr, []message.Header{perRecipient}, p)
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

	p := &reportPart{
		Header: message.Header{
			"Content-Type":              []string{"application/octet-string"},
			"Content-Transfer-Encoding": []string{"base64"},
			"Content-Disposition":       []string{"attachment; filename=message_spoofed.bin"},
		},
		Body: bytes.NewReader(payload),
	}

	return newMultipartReport(toAddr, "Malformed message, spoofed sender", hrStr, []message.Header{perRecipient}, p)
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

	p := &reportPart{
		Header: message.Header{
			"Content-Type":              []string{"application/octet-string"},
			"Content-Transfer-Encoding": []string{"base64"},
			"Content-Disposition":       []string{"attachment; filename=message.bin"},
		},
		Body: bytes.NewReader(payload),
	}

	return newMultipartReport(toAddr, "Internal mail proxy error", hrStr, []message.Header{perRecipient}, p)
}

// NewEnqueueFailure creates a new multipart/report message to be used to
// indicate one or more failures in enqueueing a mail.
func NewEnqueueFailure(toAddr string, enqueued []string, failed map[string]error, header message.Header) ([]byte, error) {
	const humanReadable = `This message was created automatically by the Katzenpost Mail Proxy.

The SMTP to Katzenpost interface encountered one or more failures when
enqueueing a message to be dispatched over the Katzenpost mix network.

The following addresses encountered failures:
`

	hrStr := humanReadable

	var perRecipients []message.Header
	for k, v := range failed {
		recipStr := fmt.Sprintf("<%v> (unrecoverable error, %v)\n", k, v)
		hrStr += recipStr

		r := make(message.Header)
		r.Set("Final-Recipient", "rfc822;"+k)
		r.Set("Status", "5.0.0 (Other undefined status)")
		r.Set("Action", "failed")
		perRecipients = append(perRecipients, r)
	}

	for _, v := range enqueued {
		r := make(message.Header)
		r.Set("Final-Recipient", "rfc822;"+v)
		r.Set("Status", "4.0.0 (Other undefined status)")
		r.Set("Action", "delayed")
		perRecipients = append(perRecipients, r)
	}

	var hdrBuf bytes.Buffer
	if err := writeHeader(&hdrBuf, header); err != nil {
		return nil, err
	}
	p := &reportPart{
		Header: message.Header{
			"Content-Type": []string{"text/rfc822-headers"},
		},
		Body: &hdrBuf,
	}

	return newMultipartReport(toAddr, "Delivery failure", hrStr, perRecipients, p)
}

// NewBounce creates a new multipart/report message to be used to indicate a
// failure to deliver a mail.
func NewBounce(toAddr, recipAddr string, payload []byte) ([]byte, error) {
	const humanReadable = `This message was created automatically by the Katzenpost Mail Proxy.

The SMTP to Katzenpost interface failed to deliver a message to it's
intended recipient.

This is a permanent error, and no action is required on your part.
A copy of the original message is included as an attachment.

The recipient's address was: %v
`

	hrStr := fmt.Sprintf(humanReadable, recipAddr)

	perRecipient := make(message.Header)
	perRecipient.Set("Final-Recipient", "rfc822;"+recipAddr)
	perRecipient.Set("Status", "5.4.7 (Delivery time expired)")
	perRecipient.Set("Action", "failed")

	p := &reportPart{
		Header: message.Header{
			"Content-Type": []string{"message/rfc822"},
		},
		Body: bytes.NewReader(payload),
	}

	return newMultipartReport(toAddr, "Delivery failure, timeout", hrStr, []message.Header{perRecipient}, p)
}

// NewReceiveTimeout creates a new multipart/report message to be used to
// indicate a failure to receive a mail.
func NewReceiveTimeout(toAddr string, sender *ecdh.PublicKey, blocks map[uint64][]byte, totalBlocks uint64) ([]byte, error) {
	const humanReadable = `This message was created automatically by the Katzenpost Mail Proxy.

A message sent by a remote peer has timed out mid-delivery.

This is a permanent error, and no action is required on your part.
The partially received message is included as an attachment.

The sender's public key was: %v
`

	hrStr := fmt.Sprintf(humanReadable, base64.StdEncoding.EncodeToString(sender.Bytes()))

	perRecipient := make(message.Header)
	perRecipient.Set("Final-Recipient", "rfc822;"+toAddr)
	perRecipient.Set("Status", "5.4.7 (Delivery time expired)")
	perRecipient.Set("Action", "delivered")

	var returnedBody []byte
	for i := uint64(0); i < totalBlocks; i++ {
		blk, ok := blocks[i]
		if !ok {
			blk = []byte(fmt.Sprintf("\n\n[MISSING BLOCK: %v/%v]\n\n", i+1, totalBlocks))
		}

		returnedBody = append(returnedBody, blk...)
	}

	p := &reportPart{
		Header: message.Header{
			"Content-Type":              []string{"application/octet-string"},
			"Content-Transfer-Encoding": []string{"base64"},
			"Content-Disposition":       []string{"attachment; filename=message_partial.bin"},
		},
		Body: bytes.NewReader(returnedBody),
	}

	return newMultipartReport(toAddr, "Receive failure, timeout", hrStr, []message.Header{perRecipient}, p)
}

func KeyLookupSuccess(toAddr string, accountId string, identityKey *ecdh.PublicKey) ([]byte, error) {
	const humanReadable = `This message was created automatically by the Katzenpost Mail Proxy.

The SMTP to Katzenpost interface successfully requested an identity key for the following identity:
"<%v> %v"

This key has been saved in the Mail Proxy RecipientDir as %v.pem and will
be used for future messages. You are encouraged to verify this key
out-of-band, because the confidentiality of messages to this recipient
depend upon it!
`
	keyStr := base64.StdEncoding.EncodeToString(identityKey.Bytes())
	hrStr := fmt.Sprintf(humanReadable, accountId, keyStr, accountId)

	var b bytes.Buffer
	// Create the top level writer.
	h := newMultipartReportHeader(toAddr, "Key Discovery")
	mw, err := message.CreateWriter(&b, h)
	if err != nil {
		return nil, err
	}

	ph := make(message.Header)
	ph.SetContentType("text/plain", nil)
	pw, err := mw.CreatePart(ph)
	if err != nil {
		return nil, err
	}
	io.WriteString(pw, hrStr)
	pw.Close()
	mw.Close()
	return b.Bytes(), nil
}
