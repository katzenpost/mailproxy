// recv.go - Receive implementation.
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

package account

//
// The receive component of the version 0 per-account database consists
// of the following buckets/keys.
//
// - "receive" - Receive related buckets.
//   - "lastDedupGC" - Last unix time the dedup cache was GCed.
//   - "fragments"   - Messages in the process of being reassembled.
//     - senderPK | messageID - A message entry.
//       - "totalBlocks"    - Total blocks in the message (uint64).
//       - "receivedBlocks" - Number of blocks received so far (uint64).
//       - "lastRecv"       - The last forward-progress unix time (uint64).
//       - blockID          - A received block. (uint64 Block ID keys).
//   - "spool"      - Messages ready for the user (POP3 spool).
//     - `seqNR` - A message (BoltDB's per-bucket sequence number).
//   - "dedup"      - Message de-duplication.
//     - senderPK | messageID   - The receive unix time (uint64).
//     - SHA512/256(ciphertext) - Ditto, for failed decryptions.
//
// Note: Unless stated otherwise, all integer values are in network byte
// order.
//
// TODO:
//
//  * The sender probably shouldn't be displayed in logs unless debugging
//    is enabled.
//

import (
	"crypto/sha512"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"fmt"

	bolt "github.com/coreos/bbolt"
	"github.com/katzenpost/core/crypto/ecdh"
	"github.com/katzenpost/mailproxy/internal/imf"
	"github.com/katzenpost/mailproxy/internal/pop3"
	"github.com/katzenpost/minclient/block"
)

const (
	recvBucket     = "receive"
	lastDedupGCKey = "lastDedupGC"
	fragsBucket    = "fragments"
	lastRecvKey    = "lastRecv"
	spoolBucket    = "spool"
	dedupBucket    = "dedup"
)

func (a *Account) onBlockDecryptFailure(msg []byte) error {
	// WARNING: Returning non-nil from this will kill the connection
	// and roll back the transaction.
	return a.db.Update(func(tx *bolt.Tx) error {
		// Check the de-duplication cache to see if this ciphertext
		// should just be discarded.
		//
		// It's possible but extremely unlikely for SHA512/256(ciphertext)
		// to collide, but if something like this isn't done, the user can
		// get spammed with useless crap.
		recvBkt := tx.Bucket([]byte(recvBucket))
		tag := sha512.Sum512_256(msg)
		if a.testDuplicate(recvBkt, tag[:], true) {
			// The sender retransmitted something we can't decrypt, discard.
			a.log.Warningf("Discarding Ciphertext: %v: Already received.", hex.EncodeToString(tag[:]))
			return nil
		}

		// Blocks that fail to decrypt will be presented to the user in the
		// form of a DSN with the ciphertext as the attachment.
		//
		// XXX: Make it so (RFC 6522).

		return nil
	})
}

func (a *Account) onBlock(sender *ecdh.PublicKey, blk *block.Block) error {
	a.log.Debugf("onBlock: %v.", blkToStr(sender, blk))

	// WARNING: Returning non-nil from this will kill the connection
	// and roll back the transaction.
	return a.db.Update(func(tx *bolt.Tx) error {
		const (
			totalBlocksKey    = "totalBlocks"
			receivedBlocksKey = "receivedBlocks"
		)

		// Grab the message ID used for the fragments bucket key and
		// the deduplication tag.
		msgID := make([]byte, 0, ecdh.PublicKeySize+block.MessageIDLength)
		msgID = append(msgID, sender.Bytes()...)
		msgID = append(msgID, blk.MessageID[:]...)

		// Check the de-duplication cache to see if the block should just be
		// discarded.
		recvBkt := tx.Bucket([]byte(recvBucket))
		if a.testDuplicate(recvBkt, msgID, false) {
			// Block for a message in the de-duplication cache, discard.
			a.log.Warningf("Discarding Block %v: Part of an already received message.", blkToStr(sender, blk))
			return nil
		}

		// Fast path for messages that do not require reassembly.
		if blk.TotalBlocks == 1 {
			return a.storeRecvMessage(recvBkt, msgID, blk.Payload)
		}

		// The block is a fragment for a message.
		fragsBkt := recvBkt.Bucket([]byte(fragsBucket))
		msgBkt, err := fragsBkt.CreateBucketIfNotExists(msgID)
		if err != nil {
			return err
		}

		// Validate or set the total block count for this message.
		b := msgBkt.Get([]byte(totalBlocksKey))
		if len(b) == 8 {
			t := binary.BigEndian.Uint64(b[:])
			if t != uint64(blk.TotalBlocks) {
				// Total block count mismatch.
				//
				// XXX: I'm not sure what the best behavior is here.
				// This could happen if the message ID happens to collide,
				// but that's extremely unlikely to happen if the sender is
				// spec compliant.
				//
				// For now opting to discard the block as malformed seems like
				// a reasonable thing to do, though if this situation does
				// ever occur, this is eating mail.
				a.log.Warningf("Discarding Block %v: Metadata mismatch (expecting %v).", blkToStr(sender, blk), t)
				return nil
			}
		} else {
			msgBkt.Put([]byte(totalBlocksKey), uint64ToBytes(uint64(blk.TotalBlocks)))
		}

		// Store the fragment's payload.
		blockID := uint64ToBytes(uint64(blk.BlockID))
		if msgBkt.Get(blockID) != nil {
			// Duplicate block, discard.
			a.log.Warningf("Discarding Block %v: Already in reassembly queue.", blkToStr(sender, blk))
			return nil
		}
		if blk.Payload == nil {
			blk.Payload = []byte{} // XXX: I hope BoltDB handles this.
		}
		msgBkt.Put(blockID, blk.Payload)

		// Update the message reassembly state.
		var receivedBlocks []byte
		b = msgBkt.Get([]byte(receivedBlocksKey))
		if len(b) == 8 {
			recved := binary.BigEndian.Uint64(b[:]) + 1
			if recved == uint64(blk.TotalBlocks) {
				// All fragments of the message have arrived. Regardless of
				// if the reassembly process fails or not, we are done with
				// this message, so we can omit updating any more metadata.

				b, err = reassembleFragments(msgBkt, uint64(blk.TotalBlocks))
				if err != nil {
					// Reassembly failure.
					//
					// This should NEVER happen, unless something has gone
					// horrifically wrong with the database.  This is
					// irrecoverable.
					a.log.Errorf("Critical reassembly failure: %v", err)
					return err
				}

				// Store the reassembled message.
				err = a.storeRecvMessage(recvBkt, msgID, b)
				if err == nil {
					// Delete the message bucket.
					fragsBkt.DeleteBucket(msgID)
				}
				return err
			}
			receivedBlocks = uint64ToBytes(recved)
		} else {
			receivedBlocks = uint64ToBytes(1)
		}
		msgBkt.Put([]byte(receivedBlocksKey), receivedBlocks)

		// Update the timestamp.
		msgBkt.Put([]byte(lastRecvKey), uint64ToBytes(a.nowUnix()))

		a.log.Debugf("Stored Block: %v.", blkToStr(sender, blk))

		return nil
	})
}

func (a *Account) testDuplicate(recvBkt *bolt.Bucket, msgID []byte, testAndSet bool) bool {
	dedupBkt := recvBkt.Bucket([]byte(dedupBucket))
	wasPresent := dedupBkt.Get(msgID) != nil
	if testAndSet || wasPresent {
		// If this is a test and set operation OR it is a hit, update the
		// timestamp.  The on-hit update happens because it is better to
		// continue to ignore spurious retransmissions while the peer
		// continues to send them.
		dedupBkt.Put(msgID, uint64ToBytes(a.nowUnix()))
	}

	return wasPresent
}

func (a *Account) storeRecvMessage(recvBkt *bolt.Bucket, id, payload []byte) error {
	// Recover the sender public key and message ID.
	sender := new(ecdh.PublicKey)
	sender.FromBytes(id[:ecdh.PublicKeySize])
	msgID := id[ecdh.PublicKeySize:]

	idStr := fmt.Sprintf("%v:%v", sender, hex.EncodeToString(msgID))
	a.log.Debugf("storeRecvMessage: %v", idStr)

	// Test+set the de-duplication cache entry.
	if a.testDuplicate(recvBkt, msgID, true) {
		// Duplicate message, discard.
		a.log.Warningf("Discarding message %v: Already received.", idStr)
		return nil
	}

	a.log.Debugf("Message %v Payload: %v", idStr, hex.Dump(payload))

	// Validate that the message is well formed IMF.
	msg, err := imf.BytesToEntity(payload)
	if err != nil {
		// If the message is malformed, wrap it in a DSN.
		a.log.Warningf("Message %v is not well formed IMF: %v", idStr, err)
		// XXX: Payload -> DSN.
		return nil
	}

	// Ensure that none of the verboten headers are set.
	if err = imf.ValidateHeaders(msg); err != nil {
		// The message has proscribed headers set, wrap it in a DSN.
		a.log.Warningf("Message %v failed header validation: %v", idStr, err)
		// XXX: Payload -> DSN.
		return nil
	}

	// Add the various headers.
	imf.AddReceived(msg, false, true)
	msg.Header.Set(imf.SenderIdentityHeader, base64.StdEncoding.EncodeToString(sender.Bytes()))

	// Store the modified message in the spool.
	toStore, err := imf.EntityToBytes(msg)
	if err != nil {
		// This should NEVER happen, but if it does, wrap it in a DSN.
		a.log.Warningf("Failed to re-serialize message: %v", idStr, err)
		// XXX: Payload -> DSN.
		return nil
	}

	a.log.Debugf("Message %v ToStore: %v", idStr, hex.Dump(toStore))

	return a.storeMessage(recvBkt, toStore)
}

func (a *Account) storeMessage(recvBkt *bolt.Bucket, payload []byte) error {
	// At this point payload is a valid IMF format mail, that is ready
	// to be thrown into the spool.
	spoolBkt := recvBkt.Bucket([]byte(spoolBucket))

	// Store the message as the next sequence number.
	seq, _ := spoolBkt.NextSequence()
	spoolBkt.Put(uint64ToBytes(seq), payload)

	return nil
}

func (a *Account) resetSpoolSeq(spoolBkt *bolt.Bucket) {
	// WARNING: This assumes it is called as part of a write capable
	// transaction.

	cur := spoolBkt.Cursor()
	if first, _ := cur.First(); first == nil {
		spoolBkt.SetSequence(0)
	}
}

func (a *Account) newPOPSession() (pop3.BackendSession, error) {
	a.Lock()
	defer a.Unlock()

	if a.popSession != nil {
		return nil, pop3.ErrInUse
	}

	s := new(popSession)
	s.a = a
	s.sequenceMap = make(map[int]uint64)

	// Read-only transaction because nothing is actually modified here.
	idx := 0
	if err := a.db.View(func(tx *bolt.Tx) error {
		recvBkt := tx.Bucket([]byte(recvBucket))
		spoolBkt := recvBkt.Bucket([]byte(spoolBucket))

		cur := spoolBkt.Cursor()
		for k, v := cur.First(); k != nil; k, v = cur.Next() {
			s.sequenceMap[idx] = binary.BigEndian.Uint64(k)

			// Copy, v is invalidate at the end of the transaction.
			msg := make([]byte, 0, len(v))
			msg = append(msg, v...)
			s.messages = append(s.messages, msg)
			idx++
		}

		return nil
	}); err != nil {
		return nil, pop3.ErrBackendFail
	}

	a.log.Noticef("POP3 session created.")

	return s, nil
}

func (a *Account) doDedupGC() {
	const (
		gcIntervalSec = 86400     // 1 day.
		entryTTL      = 5 * 86400 // 5 days.
	)

	a.Lock()
	defer a.Unlock()

	now := a.nowUnix()
	deltaT := now - a.lastDedupGC
	if deltaT < gcIntervalSec && now > a.lastDedupGC {
		// Don't do the GC pass all that frequently.
		return
	}

	a.log.Debugf("Starting de-duplication cache GC cycle.")

	examined, deleted := 0, 0
	if err := a.db.Update(func(tx *bolt.Tx) error {
		recvBkt := tx.Bucket([]byte(recvBucket))
		dedupBkt := recvBkt.Bucket([]byte(dedupBucket))

		cur := dedupBkt.Cursor()
		for k, v := cur.First(); k != nil; k, v = cur.Next() {
			examined++
			t := binary.BigEndian.Uint64(v)
			if now > t && now-t > entryTTL {
				cur.Delete()
				deleted++
			}
		}

		// Update the time stamp of the last GC cycle.
		recvBkt.Put([]byte(lastDedupGCKey), uint64ToBytes(now))

		return nil
	}); err != nil {
		a.log.Warningf("Failed to GC de-duplication cache: %v", err)
		return
	}

	a.lastDedupGC = now
	a.log.Debugf("Finished de-duplication cache GC cycle: %v/%v pruned.", deleted, examined)
}

func reassembleFragments(bkt *bolt.Bucket, totalBlocks uint64) ([]byte, error) {
	b := make([]byte, 0, block.BlockPayloadLength*totalBlocks)
	for i := uint64(0); i < totalBlocks; i++ {
		p := bkt.Get(uint64ToBytes(i))
		if p == nil {
			// XXX: Double check that the "right" thing happens if the block
			// has a 0 length payload.
			return nil, fmt.Errorf("reassembly failure: block %v/%v missing", i, totalBlocks)
		}
		b = append(b, p...)
	}
	return b, nil
}

func blkToStr(pk *ecdh.PublicKey, blk *block.Block) string {
	return fmt.Sprintf("[%v:%v]: %v/%v, %v bytes", pk, hex.EncodeToString(blk.MessageID[:]), blk.BlockID, blk.TotalBlocks, len(blk.Payload))
}

type popSession struct {
	a *Account

	sequenceMap map[int]uint64
	messages    [][]byte
}

func (s *popSession) Messages() ([][]byte, error) {
	return s.messages, nil
}

func (s *popSession) DeleteMessages(msgs []int) error {
	return s.a.db.Update(func(tx *bolt.Tx) error {
		recvBkt := tx.Bucket([]byte(recvBucket))
		spoolBkt := recvBkt.Bucket([]byte(spoolBucket))

		// Apply the deletions to the store.
		for _, idx := range msgs {
			seq, ok := s.sequenceMap[idx]
			if !ok {
				s.a.log.Warningf("pop3: Deletion for invalid sequence number: %v", idx)
				continue
			}

			spoolBkt.Delete(uint64ToBytes(seq))
		}

		// Reset the sequence number if the spool was depleted.
		s.a.resetSpoolSeq(spoolBkt)
		return nil
	})
}

func (s *popSession) Close() {
	defer s.a.Deref()

	s.a.Lock()
	defer s.a.Unlock()

	// All of the interesting cleanup work is done in the DeleteMessages()
	// call.
	s.a.popSession = nil

	s.a.log.Noticef("POP3 session closed.")
}
