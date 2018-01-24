// api.go - Katzenpost client mailproxy external API
// Copyright (C) 2018  Yawning Angel, David Anthony Stainton.
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
	"errors"

	"github.com/emersion/go-message"
	"github.com/katzenpost/core/crypto/ecdh"
	"github.com/katzenpost/mailproxy/internal/account"
	"github.com/katzenpost/mailproxy/internal/imf"
)

var (
	// ErrUnknownRecipient is the error that is returned when a recipient for
	// which there is no public key is specified.
	ErrUnknownRecipient = errors.New("mailproxy/api: unknown recipient, missing public key")

	// ErrNoMessages is the error that is returned when an account's receive
	// queue is empty.
	ErrNoMessages = errors.New("mailproxy/api: account receive queue empty")
)

// SendMessage enqueues payload for transmission from the sender to the
// recipient (account IDs).  The payload MUST be a well formed IMF message.
//
// Any delivery failures after the message has been successfully enqueued will
// result in a delivery status notification message being sent from the
// postmaster to the senderID account.
func (p *Proxy) SendMessage(senderID, recipientID string, payload []byte) error {
	acc, _, err := p.getAccount(senderID)
	if err != nil {
		return err
	}
	defer acc.Deref()

	rcpt, err := p.toAccountRecipient(recipientID)
	if err != nil {
		p.log.Warningf("Invalid recipient identity argument '%v': %v", recipientID, err)
		return err
	}
	if rcpt.PublicKey == nil {
		p.log.Warningf("Recipient identity ('%v') does not specify a known recipient.", rcpt.ID)
		return ErrUnknownRecipient
	}

	// Validate and pre-process the outgoing message body.
	payloadIMF, _, isUnreliable, err := p.preprocessOutgoing(payload, true)
	if err != nil {
		return err
	}

	// Enqueue the outgoing message.
	if err = acc.EnqueueMessage(rcpt, payloadIMF, isUnreliable); err != nil {
		p.log.Errorf("Failed to enqueue for '%v': %v", rcpt, err)
		return err
	}
	return nil
}

func (p *Proxy) toAccountRecipient(recipientID string) (*account.Recipient, error) {
	rcptID, local, domain, err := p.recipients.Normalize(recipientID)
	if err != nil {
		return nil, err
	}

	return &account.Recipient{
		ID:        rcptID,
		User:      local,
		Provider:  domain,
		PublicKey: p.recipients.Get(rcptID),
	}, nil
}

func (p *Proxy) preprocessOutgoing(b []byte, viaESMTP bool) ([]byte, *message.Entity, bool, error) {
	// Parse the message payload so that headers can be manipulated,
	// and ensure that there is a Message-ID header, and prepend the
	// "Received" header.
	entity, err := imf.BytesToEntity(b)
	if err != nil {
		return nil, nil, false, err
	}
	imf.AddMessageID(entity)
	imf.AddReceived(entity, true, viaESMTP)
	isUnreliable, err := imf.IsUnreliable(entity)
	if err != nil {
		return nil, nil, false, err
	}

	// Re-serialize the IMF message now to apply the new headers,
	// and canonicalize the line endings.
	payload, err := imf.EntityToBytes(entity)

	return payload, entity, isUnreliable, err
}

// ReceivePeek returns the eldest message in the given account's receive queue,
// the sender's public key if any, and a unique identifier tag. The account's
// receive queue is left intact.
func (p *Proxy) ReceivePeek(accountID string) ([]byte, *ecdh.PublicKey, []byte, error) {
	return p.doReceivePeekPop(accountID, false)
}

// ReceivePop removes and returns the eldest message in the given account's
// receive queue, the sender's public key if any, and a unique identifier tag.
func (p *Proxy) ReceivePop(accountID string) ([]byte, *ecdh.PublicKey, []byte, error) {
	return p.doReceivePeekPop(accountID, true)
}

func (p *Proxy) doReceivePeekPop(accountID string, isPop bool) ([]byte, *ecdh.PublicKey, []byte, error) {
	acc, _, err := p.getAccount(accountID)
	if err != nil {
		return nil, nil, nil, err
	}
	defer acc.Deref()

	msg, sender, msgID, err := acc.ReceivePeekPop(isPop)
	if msg == nil && sender == nil && msgID == nil && err == nil {
		// Allow the caller to easily distinguish an empty queue.
		err = ErrNoMessages
	}
	return msg, sender, msgID, err
}

func (p *Proxy) getAccount(accountID string) (*account.Account, string, error) {
	accID, _, _, err := p.recipients.Normalize(accountID)
	if err != nil {
		p.log.Warningf("Invalid account identifier '%v': %v", accountID, err)
		return nil, "", err
	}
	acc, err := p.accounts.Get(accID)
	if err != nil {
		p.log.Warningf("Account identifier ('%v') does not specify a valid account: %v", accountID, err)
		return nil, "", err
	}
	return acc, accID, nil
}

// GetRecipient returns the public key for the provided recipient.
func (p *Proxy) GetRecipient(recipientID string) (*ecdh.PublicKey, error) {
	// Somewhat redundant because Store.Get will also normalize, but
	// Get treats parse errors as unknown recipients rather than
	// returning an error.
	_, _, _, err := p.recipients.Normalize(recipientID)
	if err != nil {
		return nil, err
	}

	pk := p.recipients.Get(recipientID)
	if pk == nil {
		err = ErrUnknownRecipient
	}
	return pk, err
}

// SetRecipient sets the public key for the provided recipient.
func (p *Proxy) SetRecipient(recipientID string, publicKey *ecdh.PublicKey) error {
	return p.recipients.Set(recipientID, publicKey)
}

// RemoveRecipient removes the provided recipient.  This has no impact on
// messages that have already been enqueued for transmission via SendMessage.
func (p *Proxy) RemoveRecipient(recipientID string) error {
	return p.recipients.Clear(recipientID)
}

// ListRecipients returns a map of recipientIDs to public keys consisting of
// all currently known entries.  Modifications to the returned map have no
// effect.
func (p *Proxy) ListRecipients() map[string]*ecdh.PublicKey {
	return p.recipients.CloneRecipients()
}
