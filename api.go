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
	"bytes"
	"context"
	"errors"
	"time"

	"github.com/emersion/go-message"
	"github.com/katzenpost/core/crypto/ecdh"
	"github.com/katzenpost/core/epochtime"
	"github.com/katzenpost/core/pki"
	"github.com/katzenpost/mailproxy/event"
	"github.com/katzenpost/mailproxy/internal/account"
	"github.com/katzenpost/mailproxy/internal/imf"
	"gopkg.in/eapache/channels.v1"
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
// recipient (account IDs), and returns he message identifier tag.  The
// payload MUST be a well formed IMF message.
//
// Any delivery failures after the message has been successfully enqueued will
// result in a delivery status notification message being sent from the
// postmaster to the senderID account.
func (p *Proxy) SendMessage(senderID, recipientID string, payload []byte) ([]byte, error) {
	acc, _, err := p.getAccount(senderID)
	if err != nil {
		return nil, err
	}
	defer acc.Deref()

	rcpt, err := p.toAccountRecipient(recipientID)
	if err != nil {
		return nil, err
	}

	if rcpt.PublicKey == nil && !acc.InsecureKeyDiscovery {
		return nil, ErrUnknownRecipient
	}

	if rcpt.PublicKey == nil {
		p.log.Warning("sending insecure message")
		expire := time.Now().Add(time.Duration(p.cfg.Debug.UrgentQueueLifetime) * time.Second)
		isUnreliable := false
		entity, err := message.Read(bytes.NewReader(payload))
		if err != nil {
			return nil, err
		}
		msgID, err := p.QueryKeyFromProvider(senderID, recipientID)
		if err != nil {
			return nil, err
		}
		p.log.Debugf("message ID %x", msgID)
		p.eventListener.enqueueLaterCh <- &enqueueLater{string(msgID), senderID, recipientID, &payload, entity, isUnreliable, expire}
		p.log.Debug("message enqueued for sending later")
		return msgID, nil
	}

	// Validate and pre-process the outgoing message body.
	payloadIMF, _, isUnreliable, err := p.preprocessOutgoing(payload, true)
	if err != nil {
		return nil, err
	}

	// Enqueue the outgoing message.
	return acc.EnqueueMessage(rcpt, payloadIMF, isUnreliable)
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

// SendKaetzchenRequest enqueues the payload for transmission from the sender
// to the service on the remote provider, and returns the message identifier
// tag.
//
// Note: Replies are delivered as `event.KaetzchenReplyEvent`s, via the
// EventSink channel.  It is on the caller to keep track of requests via
// the message identifier tag to correctly handle responses.
func (p *Proxy) SendKaetzchenRequest(senderID, serviceID, providerID string, payload []byte, wantResponse bool) ([]byte, error) {
	acc, _, err := p.getAccount(senderID)
	if err != nil {
		return nil, err
	}
	defer acc.Deref()

	rcpt := &account.Recipient{
		ID:       serviceID + "@" + providerID,
		User:     serviceID, // Fixed up in EnqueueKaetzchenRequest.
		Provider: providerID,
	}

	return acc.EnqueueKaetzchenRequest(rcpt, payload, !wantResponse)
}

// Message is the received message.
type Message struct {
	// Payload is the Message payload.
	Payload []byte

	// SenderID is the Message sender's identifier set iff the sender is
	// a known recipient.
	SenderID string

	// SenderKey is the Message sender's public key, if any.
	SenderKey *ecdh.PublicKey

	// MessageID is the local unique identifier for the message.
	MessageID []byte
}

// ReceivePeek returns the eldest message in the given account's receive queue.
// The account's receive queue is left intact.
func (p *Proxy) ReceivePeek(accountID string) (*Message, error) {
	return p.doReceivePeekPop(accountID, false)
}

// ReceivePop removes and returns the eldest message in the given account's
// receive queue.
func (p *Proxy) ReceivePop(accountID string) (*Message, error) {
	return p.doReceivePeekPop(accountID, true)
}

func (p *Proxy) doReceivePeekPop(accountID string, isPop bool) (*Message, error) {
	acc, _, err := p.getAccount(accountID)
	if err != nil {
		return nil, err
	}
	defer acc.Deref()

	msg, sender, msgID, err := acc.ReceivePeekPop(isPop)
	if err != nil {
		return nil, err
	} else if msg == nil && sender == nil && msgID == nil {
		// Allow the caller to easily distinguish an empty queue.
		return nil, ErrNoMessages
	}

	return &Message{
		Payload:   msg,
		SenderID:  p.recipients.GetByKey(sender),
		SenderKey: sender,
		MessageID: msgID,
	}, nil
}

func (p *Proxy) getAccount(accountID string) (*account.Account, string, error) {
	accID, _, _, err := p.recipients.Normalize(accountID)
	if err != nil {
		return nil, "", err
	}
	acc, err := p.accounts.Get(accID)
	if err != nil {
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
	p.log.Debug("SetRecipient %s %s", recipientID, publicKey.String())
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

// IsConnected returns true iff a connection to the provider is established.
func (p *Proxy) IsConnected(accountID string) bool {
	acc, _, err := p.getAccount(accountID)
	if err != nil {
		return false
	}
	defer acc.Deref()

	return acc.IsConnected()
}

// ListProviders returns a list of Provider identifiers published for the
// current epoch by the authority identified by authorityID.
func (p *Proxy) ListProviders(authorityID string) ([]*pki.MixDescriptor, error) {
	authority, err := p.nonvotingAuthorities.Get(authorityID)
	if err != nil {
		authority, err = p.votingAuthorities.Get(authorityID)
		if err != nil {
			return nil, err
		}
	}
	defer authority.Deref()

	authClient := authority.Client()
	ctx, cancel := context.WithTimeout(context.Background(), time.Second*5)
	defer cancel()

	epoch, _, _ := epochtime.Now()
	doc, _, err := authClient.Get(ctx, epoch)
	if err != nil {
		return nil, err
	}
	return doc.Providers, nil
}

func (p *Proxy) eventSinkWorker() {
	for {
		select {
		case <-p.HaltCh():
			return
		case e := <-p.eventCh.Out():
			p.cfg.Proxy.EventSink <- e.(event.Event)
		}
	}
}

func (p *Proxy) initializeEventSink() {
	if p.cfg.Proxy.EventSink != nil {
		p.Go(p.eventSinkWorker)
	} else {
		channels.Pipe(p.eventCh, channels.NewBlackHole())
	}
}
