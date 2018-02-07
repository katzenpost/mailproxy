// send.go - Message transmission backend.
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

package account

//
// The send component of the version 0 per-account database consists of the
// following buckets/keys.
//
// - "send" - Send related buckets.
//   - "lastSendGC" - Last unix time the send state was GCed.
//   - "surbs" - SURBs that can potentially be received.
//     - `surbID` - SURB ID.
//       - "sprpKey"   - The SURB payload SPRP key.
//       - "messageID" - The spool entry for which this belongs to.
//       - "blockID"   - The block ID corresponding to the SURB.
//       - "eta"       - The SURB ETA unix time (uint64).
//       - "type"      - The expected type of the SURB (uint8).
//   - "spool" - The outgoing message queue (SMTP spool).
//     - `seqNR` - A message (BoltDB's per-bucket sequence number).
//       - "messageID"   - The message ID of the message.
//       - "user"        - The recipient.
//       - "provider"    - The recipient's provider.
//       - "lastACK"     - The last ACK unix time (uint64).
//       - "bounceAt"    - The earliest bounce unix time (uint64).
//       - "plaintext"   - The message plaintext (Optionally encrypted).
//       - "unreliable"  - Denotes that no SURBs should be sent ('0x01').
//       - "totalBlocks" - The number of blocks in the message (uint64).
//       - "sentBlocks"  - The number of blocks that have been sent at least once (uint64).
//       - "blocks"     - The blocks belonging to this message.
//         - blockID - A queued block. (uint64 Block ID keys).
//       - "surbETAs"    - The retransmit unix times.
//         - blockID - A estimated ACK arrival time (uint64).
//   - "urgentSpool" - The outgoing urgent message queue (Kaetzchen spool).
//     - `seqNR` - A message (BoltDB's per-bucket sequence number).
//       - "messageID"   - The message ID of the message.
//       - "user"        - The recipient service ID (NOT endpoint).
//       - "provider"    - The recipient's provider.
//       - "bounceAt"    - The earliest bounce unix time (uint64).
//       - "plaintext"   - The message plaintext (Optionally encrypted).
//       - "unreliable"  - Denotes that no SURBs should be sent ('0x01').
//
// Note: Unless stated otherwise, all integer values are in network byte
// order.
//

import (
	"bytes"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"time"

	bolt "github.com/coreos/bbolt"
	"github.com/katzenpost/core/constants"
	"github.com/katzenpost/core/crypto/ecdh"
	"github.com/katzenpost/core/crypto/rand"
	"github.com/katzenpost/core/pki"
	"github.com/katzenpost/core/queue"
	"github.com/katzenpost/core/sphinx"
	sConstants "github.com/katzenpost/core/sphinx/constants"
	"github.com/katzenpost/core/utils"
	"github.com/katzenpost/mailproxy/event"
	"github.com/katzenpost/mailproxy/internal/imf"
	"github.com/katzenpost/minclient/block"
)

const (
	sendBucket    = "send"
	lastSendGCKey = "lastSendGC"

	surbsBucket  = "surbs"
	sprpKey      = "sprpKey"
	messageIDKey = "messageID"
	blockIDKey   = "blockID"
	etaKey       = "eta"
	typeKey      = "type"

	// spoolBucket - also a subkey of "receive".
	userKey       = "user"
	providerKey   = "provider"
	lastACKKey    = "lastACK"
	bounceAtKey   = "bounceAt"
	plaintextKey  = "plaintext"
	unreliableKey = "unreliable"
	// totalBlocks - also a subkey of a recv entry.
	sentBlocksKey  = "sentBlocks"
	blocksBucket   = "blocks"
	surbETAsBucket = "surbETAs"

	urgentSpoolBucket = "urgentSpool"

	sendReceiveDrainWait  = 1 * time.Minute
	sendMinimumOnlineTime = 1 * time.Minute

	surbTypeACK       = 0
	surbTypeKaetzchen = 1
)

var (
	errEntryGone  = errors.New("spool entry disapeared while sending")
	errNoDocument = errors.New("no directory information available")

	errSendTimeout  = errors.New("timed out attempting to send")
	errReplyTimeout = errors.New("timed out waiting for reply")
	errInvalidReply = errors.New("reply body was malformed")
)

// Recipient is a outgoing recipient.
type Recipient struct {
	ID        string
	User      string
	Provider  string
	PublicKey *ecdh.PublicKey
}

type surbCtx struct {
	messageID [block.MessageIDLength]byte
	blockID   uint64
	eta       uint64
	surbType  byte
}

func (sc *surbCtx) fromBucket(bkt *bolt.Bucket) error {
	msgID := bkt.Get([]byte(messageIDKey))
	if len(msgID) != len(sc.messageID) {
		return fmt.Errorf("invalid messageID length: %v", len(msgID))
	}
	copy(sc.messageID[:], msgID)

	blockID := bkt.Get([]byte(blockIDKey))
	if len(blockID) != 8 {
		return fmt.Errorf("invalid blockID length: %v", len(blockID))
	}
	sc.blockID = binary.BigEndian.Uint64(blockID[:])

	eta := bkt.Get([]byte(etaKey))
	if len(eta) != 8 {
		return fmt.Errorf("invalid eta length: %v", len(blockID))
	}
	sc.eta = binary.BigEndian.Uint64(eta[:])

	if b := bkt.Get([]byte(typeKey)); len(b) == 1 {
		sc.surbType = b[0]
	}

	return nil
}

// EnqueueMessage enqueues a message for transmission.
func (a *Account) EnqueueMessage(recipient *Recipient, msg []byte, isUnreliable bool) error {
	// Generate a distinct message ID for this message.
	var msgID [block.MessageIDLength]byte
	if _, err := io.ReadFull(rand.Reader, msgID[:]); err != nil {
		return err
	}

	// Fragment and encrypt the messages into ciphertexts.
	blocks, err := block.EncryptMessage(&msgID, msg, a.identityKey, recipient.PublicKey)
	if err != nil {
		return err
	}

	// Append to the send queue.
	if err = a.db.Update(func(tx *bolt.Tx) error {
		sendBkt := tx.Bucket([]byte(sendBucket))
		spoolBkt := sendBkt.Bucket([]byte(spoolBucket))

		// Create the spool entry bucket.
		seq, _ := spoolBkt.NextSequence()
		msgBkt, err := spoolBkt.CreateBucketIfNotExists(uint64ToBytes(seq))
		if err != nil {
			return err
		}

		// Insert the metadata.
		ts := uint64ToBytes(a.nowUnix() + uint64(a.s.cfg.Debug.BounceQueueLifetime))
		msgBkt.Put([]byte(messageIDKey), msgID[:])
		msgBkt.Put([]byte(userKey), []byte(recipient.User))
		msgBkt.Put([]byte(providerKey), []byte(recipient.Provider))
		msgBkt.Put([]byte(bounceAtKey), ts)
		msgBkt.Put([]byte(totalBlocksKey), uint64ToBytes(uint64(len(blocks))))
		a.dbEncryptAndPut(msgBkt, []byte(plaintextKey), msg)
		if isUnreliable {
			msgBkt.Put([]byte(unreliableKey), []byte{0x01})
		}

		// Insert the blocks.
		blocksBkt, err := msgBkt.CreateBucketIfNotExists([]byte(blocksBucket))
		if err != nil {
			return err
		}
		for i, v := range blocks {
			blocksBkt.Put(uint64ToBytes(uint64(i)), v)
		}

		_, err = msgBkt.CreateBucketIfNotExists([]byte(surbETAsBucket))
		return err
	}); err != nil {
		return err
	}

	a.log.Debugf("Message [%v](->%v): Enqueued %d blocks.", hex.EncodeToString(msgID[:]), recipient.ID, len(blocks))
	return nil
}

// EnqueueKaetzchenRequest enqueues a Katzchen request for transmission.
//
// Note: Kaetzchen requests are treated as "urgent" and will skip to the head
// of the transmit queue.  Additonally, the requests are considered one-shot
// and not retransmitted.
func (a *Account) EnqueueKaetzchenRequest(recipient *Recipient, msg []byte, isUnreliable bool) ([]byte, error) {
	doc := a.client.CurrentDocument()
	if doc == nil {
		return nil, errNoDocument
	}

	// Check that the recipient is a service with a valid endpoint.  This
	// is re-checked when scheduling the message for transmission.
	if _, err := a.getServiceEndpoint(doc, recipient.Provider, recipient.User); err != nil {
		return nil, err
	}

	// Generate a distinct message ID for this message.
	var msgID [block.MessageIDLength]byte
	if _, err := io.ReadFull(rand.Reader, msgID[:]); err != nil {
		return nil, err
	}

	// Ensure the request message is under the maximum for a single
	// packet, and pad out the message so that it is the correct size.
	if len(msg) > constants.UserForwardPayloadLength {
		return nil, fmt.Errorf("invalid message size: %v", len(msg))
	}
	payload := make([]byte, constants.UserForwardPayloadLength)
	copy(payload, msg)

	// Append to the urgent send queue.
	if err := a.db.Update(func(tx *bolt.Tx) error {
		sendBkt := tx.Bucket([]byte(sendBucket))
		urgentSpoolBkt := sendBkt.Bucket([]byte(urgentSpoolBucket))

		// Create the spool entry bucket.
		seq, _ := urgentSpoolBkt.NextSequence()
		msgBkt, err := urgentSpoolBkt.CreateBucketIfNotExists(uint64ToBytes(seq))
		if err != nil {
			return err
		}

		// Insert the metadata and payload.
		ts := uint64ToBytes(a.nowUnix() + uint64(a.s.cfg.Debug.UrgentQueueLifetime))
		msgBkt.Put([]byte(messageIDKey), msgID[:])
		msgBkt.Put([]byte(userKey), []byte(recipient.User))
		msgBkt.Put([]byte(providerKey), []byte(recipient.Provider))
		msgBkt.Put([]byte(bounceAtKey), ts)
		a.dbEncryptAndPut(msgBkt, []byte(plaintextKey), payload)
		if isUnreliable {
			msgBkt.Put([]byte(unreliableKey), []byte{0x01})
		}
		return nil
	}); err != nil {
		return nil, err
	}

	a.log.Debugf("Message [%v](->%v): Enqueued Kaetzchen Request.", hex.EncodeToString(msgID[:]), recipient.ID)

	return msgID[:], nil
}

type sendBlockCtx struct {
	msgID        [block.MessageIDLength]byte
	surbID       [sConstants.SURBIDLength]byte
	payload      []byte
	user         string
	provider     string
	blockID      uint64
	sentBlocks   uint64
	isUnreliable bool
	isUrgent     bool
}

func (a *Account) sendNextBlock() error {
	// Unlike everything else that uses a single transaction to accomplish
	// various operations, this uses two, because the code will deadlock
	// on the send if a fetch related callback happens to get called while
	// the block is passed to minclient for the send operation.
	//
	// While this isn't great, the worst that can happen is one missed (or
	// spurious) retransmission, both of which are mostly harmless.

	doc := a.client.CurrentDocument()
	if doc == nil {
		return errNoDocument
	}
	now := a.nowUnix()

	var blk *sendBlockCtx
	var err error
	if err = a.db.View(func(tx *bolt.Tx) error {
		sendBkt := tx.Bucket([]byte(sendBucket))
		if blk, err = a.nextSendUrgentBlock(sendBkt, doc, now); err != nil {
			return err
		} else if blk != nil {
			return nil
		}

		// No urgent messages to send, check the normal message spool.
		blk, err = a.nextSendMessageBlock(sendBkt, doc, now)
		return err
	}); err != nil {
		return err
	} else if blk == nil {
		// Nothing in the queue found.
		return nil
	}

	// Actually dispatch the packet.  The `SendCiphertext` call is where the
	// deadlock can happen in minclient.
	msgIDStr := hex.EncodeToString(blk.msgID[:])
	destStr := blk.user + "@" + blk.provider
	var surbKey []byte
	var eta uint64
	if !blk.isUnreliable {
		a.log.Debugf("Message [%v](->%v): Sending block %v.", msgIDStr, destStr, blk.blockID)

		var deltaT time.Duration
		surbKey, deltaT, err = a.client.SendCiphertext(blk.user, blk.provider, &blk.surbID, blk.payload)
		if err != nil {
			return err
		}
		eta = a.nowUnix() + uint64(deltaT.Seconds())
	} else {
		a.log.Debugf("Message [%v](->%v, Unreliable): Sending block %v.", msgIDStr, destStr, blk.blockID)
		if err = a.client.SendUnreliableCiphertext(blk.user, blk.provider, blk.payload); err != nil {
			return nil
		}
	}

	if err = a.db.Update(func(tx *bolt.Tx) error {
		sendBkt := tx.Bucket([]byte(sendBucket))

		if !blk.isUnreliable {
			// Save the SURB-ACK metadata.
			surbsBkt := sendBkt.Bucket([]byte(surbsBucket))
			surbBkt, err := surbsBkt.CreateBucket(blk.surbID[:])
			if err != nil {
				// This should be impossible, because the SURB ID was unique
				// right after it was generated, and this function won't be
				// simultaniously called ever.
				a.log.Errorf("BUG: Failed to create SURB bucket [%v]: %v", hex.EncodeToString(blk.surbID[:]), err)
				return err
			}
			surbBkt.Put([]byte(messageIDKey), blk.msgID[:])
			surbBkt.Put([]byte(sprpKey), surbKey)
			surbBkt.Put([]byte(blockIDKey), uint64ToBytes(blk.blockID))
			surbBkt.Put([]byte(etaKey), uint64ToBytes(eta))
			if blk.isUrgent {
				surbBkt.Put([]byte(typeKey), []byte{surbTypeKaetzchen})
			} else {
				surbBkt.Put([]byte(typeKey), []byte{surbTypeACK})
			}
		}

		// Urgent messages require different handling by virtue of not
		// being retransmitted or persisted.
		if blk.isUrgent {
			urgentSpoolBkt := sendBkt.Bucket([]byte(urgentSpoolBucket))
			msgSeq, msgBkt := sendSpoolEntryByID(urgentSpoolBkt, &blk.msgID)
			if msgBkt != nil {
				urgentSpoolBkt.DeleteBucket(msgSeq)
				a.resetSpoolSeq(urgentSpoolBkt)
			}
			return nil
		}

		// Update the message in-flight status.
		spoolBkt := sendBkt.Bucket([]byte(spoolBucket))
		_, msgBkt := sendSpoolEntryByID(spoolBkt, &blk.msgID)
		if msgBkt == nil {
			// The message completed between the schedule and update.
			// Roll back the transaction and return no error, since
			// this is not a bug, and "only" a spurious retransmission.
			return errEntryGone
		}
		msgBkt.Put([]byte(sentBlocksKey), uint64ToBytes(blk.sentBlocks+1))
		if !blk.isUnreliable {
			etaBkt := msgBkt.Bucket([]byte(surbETAsBucket))
			etaBkt.Put(uint64ToBytes(blk.blockID), uint64ToBytes(eta))
			a.log.Debugf("Message [%v](->%v): SURB stored [%v](Block: %v ETA: %v)", msgIDStr, destStr, hex.EncodeToString(blk.surbID[:]), blk.blockID, eta)
		} else {
			// Treat sending a block of an unreliable message as if it
			// immediately received a synthetic ACK.
			ack := &surbCtx{
				blockID: blk.blockID,
				eta:     eta,
			}
			copy(ack.messageID[:], blk.msgID[:])
			a.onACK("<synthetic>", sendBkt, ack, true)
		}

		return nil
	}); err == errEntryGone {
		// Suppress errors if the spool entry happened to disapear while
		// sending a packet.
		err = nil
	}

	return err
}

func (a *Account) nextSendMessageBlock(sendBkt *bolt.Bucket, doc *pki.Document, now uint64) (*sendBlockCtx, error) {
	// Find the best available block to transmit.  This is currently done
	// by examining each message in sequence (FIFO), and:
	//
	//  * Picking the first block that has not been sent at least once.
	//
	//  * If all blocks have been sent, seeing if the earliest ACK arrival
	//    is sufficiently in the past, and if so, retransmitting the
	//    corresponding block.
	//
	// If neither check produces a block to transmit, the next message
	// in the queue is examined.
	//
	// TODO: This could have better fairness to interleave all the messages
	// in the queue, instead of transmitting each message fully in-order,
	// but that's quite a bit of complexity.

	spoolBkt := sendBkt.Bucket([]byte(spoolBucket))

	// Iterate in ascending queue order (Oldest message).
	var blk sendBlockCtx
	cur := spoolBkt.Cursor()
	for k, v := cur.First(); k != nil; k, v = cur.Next() {
		if v != nil {
			continue
		}
		msgBkt := spoolBkt.Bucket(k)

		// Retreive the initial send metadata.
		var totalBlocks uint64
		if b := msgBkt.Get([]byte(totalBlocksKey)); len(b) == 8 {
			totalBlocks = binary.BigEndian.Uint64(b[:])
		}
		if b := msgBkt.Get([]byte(sentBlocksKey)); len(b) == 8 {
			blk.sentBlocks = binary.BigEndian.Uint64(b[:])
		}
		if blk.sentBlocks < totalBlocks {
			// There is fresh data available to send, so send fresh
			// data, under the assumption that losses are relatively
			// infrequent.
			blk.blockID = blk.sentBlocks
		} else {
			// All blocks were sent at least once, check to see
			// if a retransmission should happen.
			var waitTill uint64

			// We only need to make the decision based off the block
			// that we expect to be ACKed at the earliest time, for
			// reasons that should be obvious.
			//
			// TODO/performance: The PQ could be cached instead of
			// rebuilding it each send cycle, but having multiple
			// views of the same data is messy.
			q := buildETAQueue(msgBkt)
			if e := q.Peek(); e != nil {
				waitTill = e.Priority
				blk.blockID = e.Value.(uint64)
			} else {
				// This never happen, again the GC will fix this.
				continue
			}

			// Check the ACK travel time to see if it's obviously
			// still in-flight.
			if waitTill+uint64(a.s.cfg.Debug.RetransmitSlack) > now {
				continue
			}

			// Even if it's past the retransmission time, there
			// is a chance that the ACK is sitting in the receive
			// queue waiting to be downloaded.  Try to be somewhat
			// clever about this.

			// If the server told us that the receive queue was
			// empty relatively recently, then we probably should
			// retransmit.
			if time.Since(a.emptyAt) > sendReceiveDrainWait {
				// Otherwise, if we have not been online for a
				// "reasonable" amount of time, delay the retransmit
				// to hopefully get the receive queue to settle.
				if time.Since(a.onlineAt) < sendMinimumOnlineTime {
					continue
				}
			}
		}

		// Skip further retransmissions for messages that will soon be
		// bounced.
		if b := msgBkt.Get([]byte(bounceAtKey)); len(b) == 8 {
			bounceAt := binary.BigEndian.Uint64(b[:])

			// TODO: Check to see if the message is still making
			// forward progress, by examining when it last got an
			// ACK, and relax the bounce time.

			if bounceAt < now {
				continue
			}
		}

		// Copy out the block and relevant meta-data.
		blk.provider = string(msgBkt.Get([]byte(providerKey)))
		if _, err := doc.GetProvider(blk.provider); err != nil {
			// The current view of the network does not contain this
			// message's Provider, so this will just fail in path
			// selection.
			//
			// Note: This is inherently race prone, because the document
			// is not refreshed at all through the decision making
			// process, but the failure is going to be limited to one
			// send iteration.
			continue
		}
		blocksBkt := msgBkt.Bucket([]byte(blocksBucket))
		if b := blocksBkt.Get(uint64ToBytes(blk.blockID)); b != nil {
			blk.payload = make([]byte, 0, len(b))
			blk.payload = append(blk.payload, b...)
		} else {
			// This should never happen, but the GC cycle will deal with
			// this.
			continue
		}
		blk.user = string(msgBkt.Get([]byte(userKey)))
		copy(blk.msgID[:], msgBkt.Get([]byte(messageIDKey)))
		if b := msgBkt.Get([]byte(unreliableKey)); len(b) == 1 && b[0] == 0x01 {
			blk.isUnreliable = true
		} else if _, err := io.ReadFull(rand.Reader, blk.surbID[:]); err != nil {
			return nil, err
		}

		// A candidate block has been found.
		return &blk, nil
	}

	return nil, nil
}

func (a *Account) nextSendUrgentBlock(sendBkt *bolt.Bucket, doc *pki.Document, now uint64) (*sendBlockCtx, error) {
	// Mostly like nextSendMessageBlock(), except urgent requests are not
	// retransmitted and will only have a single block of payload.

	urgentSpoolBkt := sendBkt.Bucket([]byte(urgentSpoolBucket))

	// Iterate in ascending queue order (Oldest message).
	var blk = sendBlockCtx{isUrgent: true}
	cur := urgentSpoolBkt.Cursor()
	for k, v := cur.First(); k != nil; k, v = cur.Next() {
		if v != nil {
			continue
		}
		msgBkt := urgentSpoolBkt.Bucket(k)

		// Skip messages that will soon be bounced.
		if b := msgBkt.Get([]byte(bounceAtKey)); len(b) == 8 {
			bounceAt := binary.BigEndian.Uint64(b[:])
			if bounceAt < now {
				continue
			}
		}

		// Fixup the user (Kaetzchen service ID) to endpoint, after
		// making sure it still exists in the current document.
		var err error
		blk.provider = string(msgBkt.Get([]byte(providerKey)))
		blk.user = string(msgBkt.Get([]byte(userKey)))
		if blk.user, err = a.getServiceEndpoint(doc, blk.provider, blk.user); err != nil {
			continue
		}

		// Copy out the payload and the rest of the metadata.
		copy(blk.msgID[:], msgBkt.Get([]byte(messageIDKey)))
		payload := a.dbGetAndDecrypt(msgBkt, []byte(plaintextKey))
		blk.payload = make([]byte, 0, len(payload))
		blk.payload = append(blk.payload, payload...)
		if b := msgBkt.Get([]byte(unreliableKey)); len(b) == 1 && b[0] == 0x01 {
			blk.isUnreliable = true
		} else if _, err = io.ReadFull(rand.Reader, blk.surbID[:]); err != nil {
			return nil, err
		}

		// A candidate block has been found.
		return &blk, nil
	}

	return nil, nil
}

func (a *Account) onSURB(surbID *[sConstants.SURBIDLength]byte, payload []byte) error {
	idStr := fmt.Sprintf("[%v]", hex.EncodeToString(surbID[:]))
	a.log.Debugf("onSURB: %v.", idStr)

	// WARNING: Returning non-nil from this will kill the connection and
	// roll back the transaction.
	return a.db.Update(func(tx *bolt.Tx) error {
		sendBkt := tx.Bucket([]byte(sendBucket))
		surbsBkt := sendBkt.Bucket([]byte(surbsBucket))

		// Retreive the metadata associated with the SURB.
		bkt := surbsBkt.Bucket(surbID[:])
		if bkt == nil {
			// There isn't any.  This is either someone doing something
			// really odd, or a duplicate (due to the provider side queue
			// not getting advanced after the SURB was purged from the
			// database.
			a.log.Warningf("Discarding SURB %v: Unknown SURB ID.", idStr)
			return nil
		}

		// Decrypt and validate the SURB payload.
		b := bkt.Get([]byte(sprpKey))
		surbKey := make([]byte, 0, len(b))
		surbKey = append(surbKey, b...) // Copy, `b` is read-only.
		plaintext, err := sphinx.DecryptSURBPayload(payload, surbKey)
		if err != nil {
			// Either the sender messed up generating the packet from the
			// SURB or the payload was tampered with somehow.
			a.log.Warningf("Discarding SURB %v: Decryption failure: %v", idStr, err)
			return nil
		}

		// Past this point, regardless of what happens, it's safe to obliterate
		// the SURB's metadata, because they are Single Use by definition, and
		// the receiving provider has used the SURB (packet arrived back,
		// authenticated decryption succeeded).
		defer surbsBkt.DeleteBucket(surbID[:])

		if len(plaintext) != constants.ForwardPayloadLength {
			a.log.Warningf("Discarding SURB %v: Invalid payload size: %v", idStr, len(plaintext))
			return nil
		}

		// Retreive the rest of the metadata.
		ctx := new(surbCtx)
		if err = ctx.fromBucket(bkt); err != nil {
			// This should NEVER happen.
			a.log.Warningf("Failed to lookup SURB %v: %v", idStr, err)
			return nil
		}

		if plaintext[0] != ctx.surbType {
			a.log.Warningf("Discarding SURB %v: Unexpected type: 0x%02x (expected 0x%02x)", idStr, plaintext[0], ctx.surbType)
			// Send a failure message iff the expected type is
			// surbTypeKaetzchen.
			if ctx.surbType == surbTypeKaetzchen {
				a.onKaezchenComplete(ctx.messageID[:], nil, errInvalidReply)
			}
			return nil
		}

		// Shunt off the SURB to the correct handler based on the format id.
		switch ctx.surbType {
		case surbTypeACK:
			// Validate that the ACK payload is entirely '0x00'.
			if !utils.CtIsZero(plaintext) {
				a.log.Warningf("Discarding SURB-ACK %v: Malformed payload.", idStr)
				return nil
			}

			a.onACK(idStr, sendBkt, ctx, false)
		case surbTypeKaetzchen:
			// Validate the reserved field.
			if plaintext[1] != 0 {
				a.log.Warningf("Discarding Kaetzchen SURB %v: Malformed payload.", idStr)
				a.onKaezchenComplete(ctx.messageID[:], nil, errInvalidReply)
				return nil
			}

			a.onKaetzchenReply(idStr, ctx, plaintext[2:]) // Omit the header.
		default:
			a.log.Warningf("Discarding SURB %v: Unknown type: 0x%02x", idStr, ctx.surbType)
		}
		return nil
	})
}

func (a *Account) onACK(idStr string, sendBkt *bolt.Bucket, ack *surbCtx, isSynthetic bool) {
	msgIDStr := hex.EncodeToString(ack.messageID[:])
	a.log.Debugf("OnACK: %v [%v](Block: %v ETA: %v)", idStr, msgIDStr, ack.blockID, ack.eta)

	spoolBkt := sendBkt.Bucket([]byte(spoolBucket))

	// Figure out which send spool entry this ACK's message belongs to.
	msgSeq, msgBkt := sendSpoolEntryByID(spoolBkt, &ack.messageID)
	if msgBkt == nil {
		// The SURB-ACK is for a non-existent message, probably ACKing a
		// spurious retransmission.  There is nothing that can be done
		// about this.
		a.log.Warning("Discarding SURB-ACK %v: No corresponding message.", idStr)
		return
	}

	// Mark the corresponding block as ACKed.
	blocksBkt := msgBkt.Bucket([]byte(blocksBucket))
	blockID := uint64ToBytes(ack.blockID)
	if blocksBkt.Get(blockID) != nil {
		blocksBkt.Delete(blockID)
		if !isSynthetic {
			etaBkt := msgBkt.Bucket([]byte(surbETAsBucket))
			etaBkt.Delete(blockID)
		}
	} else {
		a.log.Warningf("Discarding SURB-ACK %v: Block already ACKed.", idStr)
	}

	// If appropriate remove the message from the queue.
	cur := blocksBkt.Cursor()
	if first, _ := cur.First(); first == nil {
		// Message has been fully ACKed.
		a.log.Debugf("Message [%v]: Fully ACKed by peer.", msgIDStr)
		spoolBkt.DeleteBucket(msgSeq)
		a.resetSpoolSeq(spoolBkt)
		return
	}

	// Update the "last forward progress" timestamp.
	msgBkt.Put([]byte(lastACKKey), uint64ToBytes(a.nowUnix()))
}

func (a *Account) onKaetzchenReply(idStr string, rep *surbCtx, payload []byte) {
	msgIDStr := hex.EncodeToString(rep.messageID[:])
	a.log.Debugf("OnKaetzchenReply: %v [%v](ETA: %v)", idStr, msgIDStr, rep.eta)

	// Pass the reply to the user.
	a.onKaezchenComplete(rep.messageID[:], payload, nil)
}

func (a *Account) doSendGC() {
	const gcIntervalSec = 300 // 5 minutes.

	now := a.nowUnix()
	deltaT := now - a.lastSendGC
	if deltaT < gcIntervalSec && now > a.lastSendGC {
		// Don't do the GC pass all that frequently.
		return
	}

	a.log.Debugf("Starting send state GC cycle.")

	surbsExamined, surbsDeleted, msgsBounced, urgentMsgsBounced := 0, 0, 0, 0
	if err := a.db.Update(func(tx *bolt.Tx) error {
		sendBkt := tx.Bucket([]byte(sendBucket))
		recvBkt := tx.Bucket([]byte(recvBucket))

		// Purge the expired SURBs.
		surbsBkt := sendBkt.Bucket([]byte(surbsBucket))
		cur := surbsBkt.Cursor()
		for k, v := cur.First(); k != nil; k, v = cur.Next() {
			if v != nil {
				continue
			}
			surbsExamined++
			surbBkt := surbsBkt.Bucket(k)

			purge := true
			if etaBytes := surbBkt.Get([]byte(etaKey)); len(etaBytes) == 8 {
				eta := binary.BigEndian.Uint64(etaBytes)
				purge = eta+uint64(a.s.cfg.Debug.RetransmitSlack) < now
			}
			if purge {
				if b := surbBkt.Get([]byte(typeKey)); len(b) == 1 && b[0] == surbTypeKaetzchen {
					// This was for an urgent message that did not get ACKed.
					// Send a completion event notifing the caller of the
					// failure.
					b = surbBkt.Get([]byte(messageIDKey))
					msgID := make([]byte, 0, len(b))
					msgID = append(msgID, b...)
					a.onKaezchenComplete(msgID, nil, errReplyTimeout)
				}
				cur.Delete()
				surbsDeleted++
			}
		}

		// Bounce timed out messages, reap zombie messages with no blocks.
		spoolBkt := sendBkt.Bucket([]byte(spoolBucket))
		cur = spoolBkt.Cursor()
		for k, v := cur.First(); k != nil; k, v = cur.Next() {
			if v != nil {
				continue
			}

			msgBkt := spoolBkt.Bucket(k)

			bounce := true
			zombie := false
			if bounceAtBytes := msgBkt.Get([]byte(bounceAtKey)); len(bounceAtBytes) == 8 {
				bounceAt := binary.BigEndian.Uint64(bounceAtBytes)
				bounce = bounceAt < now
				// TODO: Check the last forward progress time, and push back
				// the bounce time if there is active forward progress being
				// made.
			}
			if !bounce {
				// Ensure there's no messages stuck in the send queue
				// with no remaining unACKed blocks.  Should never happen,
				// checking is cheap.
				blocksBkt := msgBkt.Bucket([]byte(blocksBucket))
				bCur := blocksBkt.Cursor()
				if first, _ := bCur.First(); first == nil {
					zombie = true
				}
			} else {
				msgsBounced++

				msgIDStr := hex.EncodeToString(msgBkt.Get([]byte(messageIDKey)))
				addr := string(msgBkt.Get([]byte(userKey))) + "@" + string(msgBkt.Get([]byte(providerKey)))
				a.log.Errorf("Message [%v](->%v): Delivery timed out", msgIDStr, addr)

				payload := a.dbGetAndDecrypt(msgBkt, []byte(plaintextKey))
				if report, err := imf.NewBounce(a.id, addr, payload); err == nil {
					a.storeMessage(recvBkt, nil, report)
				} else {
					a.log.Errorf("Failed to generate a report: %v", err)
				}
			}
			if bounce || zombie {
				cur.Delete()
			}
		}

		// Bounce timed out urgent messages.
		urgentSpoolBkt := sendBkt.Bucket([]byte(urgentSpoolBucket))
		cur = urgentSpoolBkt.Cursor()
		for k, v := cur.First(); k != nil; k, v = cur.Next() {
			if v != nil {
				continue
			}

			msgBkt := urgentSpoolBkt.Bucket(k)
			if bounceAtBytes := msgBkt.Get([]byte(bounceAtKey)); len(bounceAtBytes) == 8 {
				bounceAt := binary.BigEndian.Uint64(bounceAtBytes)
				if bounceAt < now {
					// This was for an urgent message that did not get sent.
					// Send a completion event notifing the caller of the
					// failure.
					b := msgBkt.Get([]byte(messageIDKey))
					msgID := make([]byte, 0, len(b))
					msgID = append(msgID, b...)

					a.onKaezchenComplete(msgID, nil, errSendTimeout)

					urgentMsgsBounced++
					cur.Delete()
				}
			}
		}

		// Update the timestamp of the last GC cycle.
		sendBkt.Put([]byte(lastSendGCKey), uint64ToBytes(now))

		return nil
	}); err != nil {
		a.log.Warningf("Failed to GC send state: %v", err)
		return
	}

	a.log.Debugf("Finished send state GC cycle: %v/%v SURBs pruned, %v messages %v urgent bounced", surbsDeleted, surbsExamined, msgsBounced, urgentMsgsBounced)
	a.lastSendGC = now
}

func (a *Account) onKaezchenComplete(msgID, payload []byte, err error) {
	a.s.eventCh <- &event.KaetzchenReplyEvent{
		AccountID: a.id,
		MessageID: msgID,
		Payload:   payload,
		Err:       err,
	}
}

func (a *Account) getServiceEndpoint(doc *pki.Document, provider, serviceID string) (string, error) {
	pDesc, err := doc.GetProvider(provider)
	if err != nil {
		return "", err
	}

	params, ok := pDesc.Kaetzchen[serviceID]
	if !ok {
		return "", fmt.Errorf("no such service: '%v'", serviceID)
	}

	endpoint, ok := params["endpoint"].(string)
	if ok {
		return endpoint, nil
	}
	return "", fmt.Errorf("invalid endpoint in descriptor")
}

func sendSpoolEntryByID(spoolBkt *bolt.Bucket, id *[block.MessageIDLength]byte) ([]byte, *bolt.Bucket) {
	// There could be a map of the messageID -> spool sequence number,
	// but that's annoying to keep in sync.
	cur := spoolBkt.Cursor()
	for k, v := cur.First(); k != nil; k, v = cur.Next() {
		if v != nil {
			continue
		}
		bkt := spoolBkt.Bucket(k)
		if bytes.Equal(id[:], bkt.Get([]byte(messageIDKey))) {
			return k, bkt
		}
	}
	return nil, nil
}

func buildETAQueue(msgBkt *bolt.Bucket) *queue.PriorityQueue {
	q := queue.New()

	etaBkt := msgBkt.Bucket([]byte(surbETAsBucket))
	cur := etaBkt.Cursor()
	for k, v := cur.First(); k != nil; k, v = cur.Next() {
		blockID := binary.BigEndian.Uint64(k)
		eta := binary.BigEndian.Uint64(v)
		q.Enqueue(eta, blockID)
	}
	return q
}
