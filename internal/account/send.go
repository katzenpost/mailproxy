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
//   - "spool" - The outgoing message queue (SMTP spool).
//     - `seqNR` - A message (BoltDB's per-bucket sequence number).
//       - "messageID" - The message ID of the message.
//       - "user"      - The recipient.
//       - "provider"  - The recipient's provider.
//       - "lastACK"   - The last ACK unix time (uint64).
//       - "waitTill"  - The retransmit unix time (Stop-And-Wait, uint64).
//       - "bounceAt"  - The earliest bounce unix time (uint64).
//       - "plaintext" - The message plaintext (Optionally encrypted).
//       - "blocks"    - The blocks belonging to this message.
//         - blockID - A queued block. (uint64 Block ID keys).
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
	"github.com/katzenpost/core/sphinx"
	sConstants "github.com/katzenpost/core/sphinx/constants"
	"github.com/katzenpost/core/utils"
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

	// spoolBucket - also a subkey of "receive".
	userKey      = "user"
	providerKey  = "provider"
	lastACKKey   = "lastACK"
	waitTillKey  = "waitTill"
	bounceAtKey  = "bounceAt"
	plaintextKey = "plaintext"
	blocksBucket = "blocks"
)

var (
	errEntryGone  = errors.New("spool entry disapeared while sending")
	errNoDocument = errors.New("no directory information available")
)

// Recipient is a outgoing recipient.
type Recipient struct {
	ID        string
	User      string
	Provider  string
	PublicKey *ecdh.PublicKey
}

type surbACK struct {
	messageID [block.MessageIDLength]byte
	blockID   uint64
	eta       uint64
}

func (sa *surbACK) fromBucket(bkt *bolt.Bucket) error {
	msgID := bkt.Get([]byte(messageIDKey))
	if len(msgID) != len(sa.messageID) {
		return fmt.Errorf("invalid messageID length: %v", len(msgID))
	}
	copy(sa.messageID[:], msgID)

	blockID := bkt.Get([]byte(blockIDKey))
	if len(blockID) != 8 {
		return fmt.Errorf("invalid blockID length: %v", len(blockID))
	}
	sa.blockID = binary.BigEndian.Uint64(blockID[:])

	eta := bkt.Get([]byte(etaKey))
	if len(eta) != 8 {
		return fmt.Errorf("invalid eta length: %v", len(blockID))
	}
	sa.eta = binary.BigEndian.Uint64(eta[:])

	return nil
}

// EnqueueMessage enqueues a message for transmission.
func (a *Account) EnqueueMessage(recipient *Recipient, msg []byte) error {
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
		a.dbEncryptAndPut(msgBkt, []byte(plaintextKey), msg)

		// Insert the blocks.
		blocksBkt, err := msgBkt.CreateBucketIfNotExists([]byte(blocksBucket))
		if err != nil {
			return err
		}
		for i, v := range blocks {
			blocksBkt.Put(uint64ToBytes(uint64(i)), v)
		}

		return nil
	}); err != nil {
		return err
	}

	a.log.Debugf("Message [%v](->%v): Enqueued %d blocks.", hex.EncodeToString(msgID[:]), recipient.ID, len(blocks))
	return nil
}

func (a *Account) sendNextBlock() error {
	// Unlike everything else that uses a single transaction to accomplish
	// various operations, this uses two, because the code will deadlock
	// on the send if a fetch related callback happens to get called while
	// the block is passed to minclient for the send operation.
	//
	// While this isn't great, the worst that can happen is one missed (or
	// spurious) retransmission, both of which are mostly harmless.

	// Find the best available block to transmit, where best is loosely
	// defined as the first un-ACKed block from the oldest message, that
	// does not already have a block in-flight.
	//
	// Note: There is slightly more complexity than this, read the code.

	doc := a.client.CurrentDocument()
	if doc == nil {
		return errNoDocument
	}

	retransmitSlack := uint64(a.s.cfg.Debug.RetransmitSlack)
	now := a.nowUnix()
	var user, provider string
	var msgID [block.MessageIDLength]byte
	var block []byte
	var blockID uint64
	var surbID [sConstants.SURBIDLength]byte
	if err := a.db.View(func(tx *bolt.Tx) error {
		sendBkt := tx.Bucket([]byte(sendBucket))
		spoolBkt := sendBkt.Bucket([]byte(spoolBucket))

		// Iterate in ascending queue order (Oldest message).
		cur := spoolBkt.Cursor()
		for k, v := cur.First(); k != nil; k, v = cur.Next() {
			if v != nil {
				continue
			}
			msgBkt := spoolBkt.Bucket(k)

			// Check to see if there is a block in-flight already.
			if b := msgBkt.Get([]byte(waitTillKey)); len(b) == 8 {
				// Yes, there is a block in-flight.
				waitTill := binary.BigEndian.Uint64(b[:])

				// Check the ACK travel time to see if it's obviously
				// still in-flight.
				if waitTill+retransmitSlack > now {
					continue
				}

				// Even if it's past the retransmission time, there
				// is a chance that the ACK is sitting in the receive
				// queue waiting to be downloaded.  Try to be somewhat
				// clever about this.

				// If the server told us that the receive queue was
				// empty relatively recently, then we probably should
				// retransmit.
				if time.Since(a.emptyAt) > 1*time.Minute {
					// Otherwise, if we have not been online for a
					// "reasonable" amount of time, delay the retransmit
					// to hopefully get the receive queue to settle.
					if time.Since(a.onlineAt) < 1*time.Minute {
						continue
					}

					// TODO: This should also check to see if the receive
					// process is making forward progress somehow, but
					// not doing so "only" results in spurrious retransmits.
				}
			}

			// Skip further retransmissions for messages that will soon be
			// bounced.
			if b := msgBkt.Get([]byte(bounceAtKey)); len(b) == 8 {
				bounceAt := binary.BigEndian.Uint64(b[:])
				if bounceAt < now {
					continue
				}
			}

			// Copy out the block and relevant meta-data.
			provider = string(msgBkt.Get([]byte(providerKey)))
			if _, err := doc.GetProvider(provider); err != nil {
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
			bCur := blocksBkt.Cursor()
			if first, b := bCur.First(); first != nil {
				blockID = binary.BigEndian.Uint64(first)
				block = make([]byte, 0, len(b))
				block = append(block, b...)
			} else {
				// This should never happen, but the GC cycle will deal with
				// this.
				continue
			}
			user = string(msgBkt.Get([]byte(userKey)))
			copy(msgID[:], msgBkt.Get([]byte(messageIDKey)))

			// Now that we selected a block, generate a SURB ID.  This is
			// done mid-transaction so that it is possible to ensure that
			// the generate ID is not already in use.
			surbsBkt := sendBkt.Bucket([]byte(surbsBucket))
			for {
				if _, err := io.ReadFull(rand.Reader, surbID[:]); err != nil {
					return err
				}
				if surbBkt := surbsBkt.Bucket(surbID[:]); surbBkt == nil {
					return nil
				}
			}
		}
		return nil
	}); err != nil {
		return err
	} else if block == nil {
		// Nothing in the queue found.
		return nil
	}

	// Actually dispatch the packet.  The `SendCiphertext` call is where the
	// deadlock can happen in minclient.
	msgIDStr := hex.EncodeToString(msgID[:])
	a.log.Debugf("Message [%v](->%v): Sending block %v.", msgIDStr, user+"@"+provider, blockID)
	surbKey, deltaT, err := a.client.SendCiphertext(user, provider, &surbID, block)
	if err != nil {
		return err
	}
	eta := a.nowUnix() + uint64(deltaT.Seconds())

	if err = a.db.Update(func(tx *bolt.Tx) error {
		sendBkt := tx.Bucket([]byte(sendBucket))

		// Save the SURB-ACK metadata.
		surbsBkt := sendBkt.Bucket([]byte(surbsBucket))
		surbBkt, err := surbsBkt.CreateBucket(surbID[:])
		if err != nil {
			// This should be impossible, because the SURB ID was unique
			// right after it was generated, and this function won't be
			// simultaniously called ever.
			a.log.Errorf("BUG: Failed to create SURB bucket [%v]: %v", hex.EncodeToString(surbID[:]), err)
			return err
		}
		surbBkt.Put([]byte(messageIDKey), msgID[:])
		surbBkt.Put([]byte(sprpKey), surbKey)
		surbBkt.Put([]byte(blockIDKey), uint64ToBytes(blockID))
		surbBkt.Put([]byte(etaKey), uint64ToBytes(eta))

		// Update the message in-flight status.
		spoolBkt := sendBkt.Bucket([]byte(spoolBucket))
		_, msgBkt := sendSpoolEntryByID(spoolBkt, &msgID)
		if msgBkt == nil {
			// The message completed between the schedule and update.
			// Roll back the transaction and return no error, since
			// this is not a bug, and "only" a spurious retransmission.
			return errEntryGone
		}
		msgBkt.Put([]byte(waitTillKey), uint64ToBytes(eta))

		a.log.Debugf("Message [%v](->%v): SURB stored [%v](Block: %v ETA: %v)", msgIDStr, user+"@"+provider, hex.EncodeToString(surbID[:]), blockID, eta)

		return nil
	}); err == errEntryGone {
		// Suppress errors if the spool entry happened to disapear while
		// sending a packet.
		err = nil
	}

	return err
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
		k := bkt.Get([]byte(sprpKey))
		surbKey := make([]byte, 0, len(k))
		surbKey = append(surbKey, k...) // Copy, `k` is read-only.
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

		// When this does more than process ACKs, this is where it would be
		// differentiated.
		if len(plaintext) != constants.ForwardPayloadLength || !utils.CtIsZero(plaintext) {
			// The SURB-ACK payload format is a maximum sized payload
			// consisting of all 0x00 bytes.
			a.log.Warningf("Discarding SURB %v: Malformed payload.", idStr)
			return nil
		}

		// This is a valid ACK.  Retreive the rest of the metadata, and handle
		// it.
		ack := new(surbACK)
		if err = ack.fromBucket(bkt); err != nil {
			// This should NEVER happen.
			a.log.Warningf("Failed to lookup SURB-ACK %v: %v", idStr, err)
			return nil
		}

		a.onACK(idStr, sendBkt, ack)
		return nil
	})
}

func (a *Account) onACK(idStr string, sendBkt *bolt.Bucket, ack *surbACK) {
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
		msgBkt.Delete([]byte(waitTillKey)) // No longer a block in-flight.
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

func (a *Account) doSendGC() {
	const gcIntervalSec = 86400 // 1 day. XXX: Reduce when this generates bounces.

	a.Lock()
	defer a.Unlock()

	retransmitSlack := uint64(a.s.cfg.Debug.RetransmitSlack)
	now := a.nowUnix()
	deltaT := now - a.lastSendGC
	if deltaT < gcIntervalSec && now > a.lastSendGC {
		// Don't do the GC pass all that frequently.
		return
	}

	a.log.Debugf("Starting send state GC cycle.")

	examined, deleted := 0, 0
	if err := a.db.Update(func(tx *bolt.Tx) error {
		sendBkt := tx.Bucket([]byte(sendBucket))
		surbsBkt := sendBkt.Bucket([]byte(surbsBucket))

		cur := surbsBkt.Cursor()
		for k, v := cur.First(); k != nil; k, v = cur.Next() {
			if v != nil {
				continue
			}
			examined++
			surbBkt := surbsBkt.Bucket(k)

			purge := true
			if etaBytes := surbBkt.Get([]byte(etaKey)); len(etaBytes) == 8 {
				eta := binary.BigEndian.Uint64(etaBytes)
				purge = eta+retransmitSlack < now
			}
			if purge {
				cur.Delete()
				deleted++
			}
		}

		// Update the timestamp of the last GC cycle.
		sendBkt.Put([]byte(lastSendGCKey), uint64ToBytes(now))

		return nil
	}); err != nil {
		a.log.Warningf("Failed to GC send state: %v", err)
		return
	}

	a.lastSendGC = now
	a.log.Debugf("Finished send state GC cycle: %v/%v SURBs pruned.", deleted, examined)
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
