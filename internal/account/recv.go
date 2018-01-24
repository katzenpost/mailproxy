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
//   - "lastDedupGC"    - Last unix time the dedup cache was GCed.
//   - "lastFragsSweep" - Last unix time the fragment bucket was swept.
//   - "pendingBlocks"  - Block ciphertexts pending decryption/processing.
//                         (BoltDB's per-bucket sequence number.)
//   - "fragments"      - Messages in the process of being reassembled.
//     - senderPK | messageID - A message entry.
//       - "totalBlocks"    - Total blocks in the message (uint64).
//       - "receivedBlocks" - Number of blocks received so far (uint64).
//       - "lastRecv"       - The last forward-progress unix time (uint64).
//       - blockID          - A received block. (uint64 Block ID keys.
//                              Optionally encrypted).
//   - "spool"          - Messages ready for the user (POP3 spool).
//     - `seqNR` - A message (BoltDB's per-bucket sequence number.)
//       - "messageID" - The receiver re-generated message ID of the
//                         message.
//       - "sender"    - The sender public key, if any.
//       - "plaintext" - The message payload (Optionally encrypted).
//   - "dedup"          - Message de-duplication.
//     - senderPK | messageID   - The receive unix time (uint64).
//     - SHA512/256(ciphertext) - Ditto, for failed decryptions.
//
// Note: Unless stated otherwise, all integer values are in network byte
// order.
//

import (
	"crypto/sha512"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"io"
	"runtime"
	"time"

	bolt "github.com/coreos/bbolt"
	"github.com/katzenpost/core/crypto/ecdh"
	"github.com/katzenpost/core/crypto/rand"
	"github.com/katzenpost/mailproxy/internal/imf"
	"github.com/katzenpost/mailproxy/internal/pop3"
	"github.com/katzenpost/minclient/block"
)

const (
	recvBucket        = "receive"
	lastDedupGCKey    = "lastDedupGC"
	lastFragsSweepKey = "lastFragsSweep"
	pendingBlocksKey  = "pendingBlocks"
	fragsBucket       = "fragments"
	totalBlocksKey    = "totalBlocks"
	lastRecvKey       = "lastRecv"
	spoolBucket       = "spool"
	// messageID - also a subkey of a send entry.
	senderKey = "sender"
	// plaintest - also a subkey of a send entry.
	dedupBucket = "dedup"
)

func (a *Account) recvWorker() {
	const pendingBlocksFallbackInterval = 3 * time.Minute

	timer := time.NewTimer(pendingBlocksFallbackInterval)
	defer timer.Stop()
	for {
		var timerFired bool
		select {
		case <-a.HaltCh():
			return
		case <-a.onRecvCh:
			// This could try to be extra clever and batch process
			// blocks by delaying processing for a while, but I'm
			// not sure how much of a difference that makes.
		case <-timer.C:
			timerFired = true
		}
		if !timerFired && !timer.Stop() {
			<-timer.C
		}

		// Process the pending blocks.
		if err := a.processPendingBlocks(); err != nil {
			// Something has gone catastrophically wrong, bring
			// down the server.
			a.log.Errorf("Catastrophic failure in block processing: %v", err)
			a.s.fatalErrCh <- err
			return
		}
		timer.Reset(pendingBlocksFallbackInterval)
	}
}

func (a *Account) enqueueBlockCiphertext(rawBlock []byte) error {
	err := a.db.Update(func(tx *bolt.Tx) error {
		recvBkt := tx.Bucket([]byte(recvBucket))
		pendingBkt := recvBkt.Bucket([]byte(pendingBlocksKey))

		seq, _ := pendingBkt.NextSequence()
		pendingBkt.Put(uint64ToBytes(seq), rawBlock)
		return nil
	})
	if err == nil {
		// Kick the receiver worker to do reassembly.
		select {
		case a.onRecvCh <- true:
		default:
		}
	}
	return err
}

func (a *Account) processPendingBlocks() error {
	const drainBatchSz = 5 // TODO/perf: Tune this.
	drained := false
	for !drained {
		// Break up the processing to a handful of blocks at a time,
		// so that the database isn't hogged for excessive amounts of
		// time.
		if err := a.db.Update(func(tx *bolt.Tx) error {
			recvBkt := tx.Bucket([]byte(recvBucket))
			pendingBkt := recvBkt.Bucket([]byte(pendingBlocksKey))

			nrProcessed := 0
			cur := pendingBkt.Cursor()
			for k, v := cur.First(); k != nil; k, v = cur.Next() {
				// Decrypt the block.
				blk, sender, err := block.DecryptBlock(v, a.identityKey)
				if err != nil {
					a.log.Warningf("Failed to decrypt message into a Block: %v", err)

					// Save undecryptable ciphertexts.
					a.onBlockDecryptFailure(recvBkt, v)
				} else if err = a.onBlock(recvBkt, sender, blk); err != nil {
					a.log.Warningf("Failed to process decrypted Block: %v", err)
					return err
				}
				cur.Delete()
				if nrProcessed++; nrProcessed > drainBatchSz {
					return nil
				}
			}

			a.resetSpoolSeq(pendingBkt)
			drained = true
			return nil
		}); err != nil {
			return err
		}
		runtime.Gosched()
	}
	return nil
}

func (a *Account) onBlockDecryptFailure(recvBkt *bolt.Bucket, msg []byte) {
	// Check the de-duplication cache to see if this ciphertext
	// should just be discarded.
	//
	// It's possible but extremely unlikely for SHA512/256(ciphertext)
	// to collide, but if something like this isn't done, the user can
	// get spammed with useless crap.
	tag := sha512.Sum512_256(msg)
	if a.testDuplicate(recvBkt, tag[:], true) {
		// The sender retransmitted something we can't decrypt, discard.
		a.log.Warningf("Discarding Ciphertext: %v: Already received.", hex.EncodeToString(tag[:]))
		return
	}

	// Blocks that fail to decrypt will be presented to the user in the
	// form of a multipart/report with the ciphertext as the attachment.
	report, err := imf.NewDecryptionFailure(a.id, msg)
	if err != nil {
		a.log.Errorf("Failed to generate a report: %v", err)
		return
	}
	a.storeMessage(recvBkt, nil, report)
}

func (a *Account) onBlock(recvBkt *bolt.Bucket, sender *ecdh.PublicKey, blk *block.Block) error {
	const receivedBlocksKey = "receivedBlocks"

	a.log.Debugf("onBlock: %v.", blkToStr(sender, blk))

	// Grab the message ID used for the fragments bucket key and
	// the deduplication tag.
	msgID := make([]byte, 0, ecdh.PublicKeySize+block.MessageIDLength)
	msgID = append(msgID, sender.Bytes()...)
	msgID = append(msgID, blk.MessageID[:]...)

	// Check the de-duplication cache to see if the block should just be
	// discarded.
	if a.testDuplicate(recvBkt, msgID, false) {
		// Block for a message in the de-duplication cache, discard.
		a.log.Warningf("Discarding Block %v: Part of an already received message.", blkToStr(sender, blk))
		return nil
	}

	// Fast path for messages that do not require reassembly.
	if blk.TotalBlocks == 1 {
		a.storeRecvMessage(recvBkt, msgID, blk.Payload)
		return nil
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
		blk.Payload = []byte{}
	}
	a.dbEncryptAndPut(msgBkt, blockID, blk.Payload)

	// Update the message reassembly state.
	var receivedBlocks []byte
	b = msgBkt.Get([]byte(receivedBlocksKey))
	if len(b) == 8 {
		recved := binary.BigEndian.Uint64(b[:]) + 1
		if recved == uint64(blk.TotalBlocks) {
			// All fragments of the message have arrived. Regardless of
			// if the reassembly process fails or not, we are done with
			// this message, so we can omit updating any more metadata.

			b, err = a.reassembleFragments(msgBkt, uint64(blk.TotalBlocks))
			if err != nil {
				// Reassembly failure.
				//
				// This should NEVER happen, unless something has gone
				// horrifically wrong with the database.  This is
				// irrecoverable.
				a.log.Errorf("Critical reassembly failure: %v", err)
				return err
			}

			// Store the reassembled message, and delete the message bucket.
			a.storeRecvMessage(recvBkt, msgID, b)
			fragsBkt.DeleteBucket(msgID)
			return nil
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

func (a *Account) storeRecvMessage(recvBkt *bolt.Bucket, id, payload []byte) {
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
		return
	}

	a.log.Debugf("Message %v Payload: %v", idStr, hex.Dump(payload))

	// Validate that the message is well formed IMF.
	msg, err := imf.BytesToEntity(payload)
	if err != nil {
		// If the message is malformed, wrap it in a report.
		a.log.Warningf("Message %v is not well formed IMF: %v", idStr, err)

		report, err := imf.NewMalformedIMF(a.id, sender, payload)
		if err != nil {
			a.log.Errorf("Failed to generate a report: %v", err)
			return
		}
		a.storeMessage(recvBkt, nil, report)
		return
	}

	// Ensure that none of the verboten headers are set.
	if err = imf.ValidateHeaders(msg); err != nil {
		// The message has proscribed headers set, wrap it in a report.
		a.log.Warningf("Message %v failed header validation: %v", idStr, err)

		report, err := imf.NewForbiddenHeaders(a.id, sender, payload)
		if err != nil {
			a.log.Errorf("Failed to generate a report: %v", err)
			return
		}
		a.storeMessage(recvBkt, nil, report)
		return
	}

	// Add the various headers.
	imf.AddReceived(msg, false, true)
	msg.Header.Set(imf.SenderIdentityHeader, base64.StdEncoding.EncodeToString(sender.Bytes()))

	// Store the modified message in the spool.
	toStore, err := imf.EntityToBytes(msg)
	if err != nil {
		// This should NEVER happen, but if it does, wrap it in a report.
		a.log.Warningf("Failed to re-serialize message: %v", idStr, err)

		report, err := imf.NewReserializationFailure(a.id, sender, payload)
		if err != nil {
			a.log.Errorf("Failed to generate a report: %v", err)
			return
		}
		a.storeMessage(recvBkt, nil, report)
		return
	}

	a.log.Debugf("Message %v ToStore: %v", idStr, hex.Dump(toStore))
	a.storeMessage(recvBkt, sender, toStore)
}

func (a *Account) storeMessage(recvBkt *bolt.Bucket, sender *ecdh.PublicKey, payload []byte) {
	// At this point payload is a valid IMF format mail, that is ready
	// to be thrown into the spool.
	spoolBkt := recvBkt.Bucket([]byte(spoolBucket))

	// Generate a unique message identifier for use with the non-POP API.
	var recvID [block.MessageIDLength]byte
	if _, err := io.ReadFull(rand.Reader, recvID[:]); err != nil {
		panic("BUG: recv: Failed to generate recvID: " + err.Error())
	}

	// Store the message as the next sequence number.
	seq, _ := spoolBkt.NextSequence()
	msgBkt, _ := spoolBkt.CreateBucket(uint64ToBytes(seq))
	msgBkt.Put([]byte(messageIDKey), recvID[:])
	if sender != nil {
		msgBkt.Put([]byte(senderKey), sender.Bytes())
	}
	a.dbEncryptAndPut(msgBkt, []byte(plaintextKey), payload)
}

// StoreReport stores a locally generated report directly in the account's
// receive spool.
func (a *Account) StoreReport(payload []byte) error {
	return a.db.Update(func(tx *bolt.Tx) error {
		recvBkt := tx.Bucket([]byte(recvBucket))

		a.storeMessage(recvBkt, nil, payload)
		return nil
	})
}

func (a *Account) resetSpoolSeq(spoolBkt *bolt.Bucket) {
	// WARNING: This assumes it is called as part of a write capable
	// transaction.

	cur := spoolBkt.Cursor()
	if first, _ := cur.First(); first == nil {
		spoolBkt.SetSequence(0)
	}
}

func (a *Account) doDedupGC() {
	const (
		gcIntervalSec = 86400     // 1 day.
		entryTTL      = 5 * 86400 // 5 days.
	)

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

func (a *Account) doFragsSweep() {
	const timeoutSweepInterval = 15 * 60 // 15 mins.

	// Default case, no receive timeout.
	if a.s.cfg.Debug.ReceiveTimeout <= 0 {
		return
	}

	now := a.nowUnix()
	deltaT := now - a.lastFragsSweep
	if deltaT < timeoutSweepInterval && now > a.lastFragsSweep {
		return
	}

	a.log.Debugf("Starting receive timeout sweep.")

	examined, timedOut := 0, 0
	if err := a.db.Update(func(tx *bolt.Tx) error {
		recvBkt := tx.Bucket([]byte(recvBucket))
		fragsBkt := recvBkt.Bucket([]byte(fragsBucket))

		cur := fragsBkt.Cursor()
		for k, v := cur.First(); k != nil; k, v = cur.Next() {
			if v != nil {
				continue
			}
			examined++

			msgBkt := fragsBkt.Bucket(k)
			lastRecv := binary.BigEndian.Uint64(msgBkt.Get([]byte(lastRecvKey)))
			if !(now > lastRecv && now-lastRecv > uint64(a.s.cfg.Debug.ReceiveTimeout)) {
				continue
			}

			// Entry timed out.  Generate a report, force enter the
			// message into the de-duplication cache, and expunge the
			// message.

			// Pull out all of the components needed for the report.
			sender := new(ecdh.PublicKey)
			sender.FromBytes(k[:ecdh.PublicKeySize])
			totalBlocks := binary.BigEndian.Uint64(msgBkt.Get([]byte(totalBlocksKey)))
			blocks := make(map[uint64][]byte)
			for i := uint64(0); i < totalBlocks; i++ {
				b := msgBkt.Get(uint64ToBytes(i))
				if b != nil {
					blocks[i] = a.dbDecrypt(b)
				}
			}

			report, err := imf.NewReceiveTimeout(a.id, sender, blocks, totalBlocks)
			if err != nil {
				a.log.Errorf("Failed to generate a report: %v", err)
			} else {
				// This has a valid sender, but the reassembly failed and
				// it's a report now.
				a.storeMessage(recvBkt, nil, report)
			}

			a.testDuplicate(recvBkt, k, true)
			cur.Delete()
			timedOut++
		}

		recvBkt.Put([]byte(lastFragsSweepKey), uint64ToBytes(now))
		return nil
	}); err != nil {
		a.log.Warningf("Failed to sweep partial messages: %v", err)
	}

	a.lastFragsSweep = now
	a.log.Debugf("Finished receive timeout sweep: %v/%v timed out.", timedOut, examined)
}

func (a *Account) reassembleFragments(bkt *bolt.Bucket, totalBlocks uint64) ([]byte, error) {
	fragments := make([][]byte, 0, totalBlocks)
	for i := uint64(0); i < totalBlocks; i++ {
		p := bkt.Get(uint64ToBytes(i))
		if p == nil {
			return nil, fmt.Errorf("reassembly failure: block %v/%v missing", i, totalBlocks)
		}
		fragments = append(fragments, p)
	}

	b := make([]byte, 0, block.BlockPayloadLength*totalBlocks)
	for _, v := range fragments {
		b = append(b, a.dbDecrypt(v)...)
	}
	return b, nil
}

func (a *Account) ReceivePeekPop(isPop bool) ([]byte, *ecdh.PublicKey, []byte, error) {
	tx, err := a.db.Begin(isPop)
	if err != nil {
		return nil, nil, nil, err
	}
	defer tx.Rollback()

	recvBkt := tx.Bucket([]byte(recvBucket))
	spoolBkt := recvBkt.Bucket([]byte(spoolBucket))

	// Grab the eldest message.
	cur := spoolBkt.Cursor()
	mKey, _ := cur.First()
	if mKey == nil {
		// The receive bucket is empty.
		return nil, nil, nil, nil
	}

	// There is a message to return.
	msgBkt := spoolBkt.Bucket(mKey)

	pt := a.dbGetAndDecrypt(msgBkt, []byte(plaintextKey))
	msg := make([]byte, 0, len(pt))
	msg = append(msg, pt...)
	msgID := append([]byte{}, msgBkt.Get([]byte(messageIDKey))...)
	var sender *ecdh.PublicKey
	if rawPub := msgBkt.Get([]byte(senderKey)); rawPub != nil {
		sender = new(ecdh.PublicKey)
		sender.FromBytes(rawPub)
	}

	if isPop {
		spoolBkt.Delete(mKey)
		a.resetSpoolSeq(spoolBkt)
		err = tx.Commit()
	}

	return msg, sender, msgID, err
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
		for k, _ := cur.First(); k != nil; k, _ = cur.Next() {
			s.sequenceMap[idx] = binary.BigEndian.Uint64(k)

			msgBkt := spoolBkt.Bucket(k)
			pt := a.dbGetAndDecrypt(msgBkt, []byte(plaintextKey)) // MUST COPY.
			msg := make([]byte, 0, len(pt))
			msg = append(msg, pt...)
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

			spoolBkt.DeleteBucket(uint64ToBytes(seq))
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

func blkToStr(pk *ecdh.PublicKey, blk *block.Block) string {
	return fmt.Sprintf("[%v:%v]: %v/%v, %v bytes", pk, hex.EncodeToString(blk.MessageID[:]), blk.BlockID, blk.TotalBlocks, len(blk.Payload))
}
