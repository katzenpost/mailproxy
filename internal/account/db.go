// db.go - Common database storage routines.
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
// The version 0 per-account database is a dead simple BoltDB database
// consisting of the send queue, reassembly queue, and POP3 spool with
// the following layout:
//
// - "metadata"  - Per-file metadata.
//   - "version"     - File format version (0x00).
// - "receive"   - Receive related buckets.
// - "send"      - Send related buckets.
//
// TODO:
//
//  * This is extremely tightly coupled to BoltDB, which will probably make
//    people sad.  At some point, maybe abstract away the backing store,
//    if I can think of a clean way to do so.
//

import (
	"encoding/binary"
	"fmt"
	"path/filepath"

	bolt "github.com/coreos/bbolt"
)

func (a *Account) initDatabase() error {
	const (
		metadataBucket = "metadata"
		versionKey     = "version"
	)

	var err error
	a.db, err = bolt.Open(filepath.Join(a.basePath, "storage.db"), 0600, nil)
	if err != nil {
		return err
	}

	// Initialize (or load) all the buckets.
	err = a.db.Update(func(tx *bolt.Tx) error {
		// Ensure that all the buckets exist, and grab the metadata bucket.
		bkt, err := tx.CreateBucketIfNotExists([]byte(metadataBucket))
		if err != nil {
			return err
		}

		recvBkt, err := tx.CreateBucketIfNotExists([]byte(recvBucket))
		if err != nil {
			return err
		}
		if _, err := recvBkt.CreateBucketIfNotExists([]byte(fragsBucket)); err != nil {
			return err
		}
		if _, err := recvBkt.CreateBucketIfNotExists([]byte(spoolBucket)); err != nil {
			return err
		}
		if _, err := recvBkt.CreateBucketIfNotExists([]byte(dedupBucket)); err != nil {
			return err
		}

		sendBkt, err := tx.CreateBucketIfNotExists([]byte(sendBucket))
		if err != nil {
			return err
		}
		if _, err := sendBkt.CreateBucketIfNotExists([]byte(surbsBucket)); err != nil {
			return err
		}
		if _, err := sendBkt.CreateBucketIfNotExists([]byte(spoolBucket)); err != nil {
			return err
		}

		if b := bkt.Get([]byte(versionKey)); b != nil {
			if len(b) != 1 || b[0] != 0 {
				return fmt.Errorf("db: incompatible version: %v", b)
			}

			// Restore state.
			b = recvBkt.Get([]byte(lastDedupGCKey))
			if len(b) == 8 {
				a.lastDedupGC = binary.BigEndian.Uint64(b)
			}
			b = sendBkt.Get([]byte(lastSendGCKey))
			if len(b) == 8 {
				a.lastSendGC = binary.BigEndian.Uint64(b)
			}

			return nil
		}

		bkt.Put([]byte(versionKey), []byte{0})
		return nil
	})
	if err != nil {
		a.db.Close()
		a.db = nil
	}
	return err
}

func uint64ToBytes(i uint64) []byte {
	// Avoid the foot + gun pitfalls of BoltDB's Put() call being reference
	// based by allocating byte slices.
	var buf [8]byte
	binary.BigEndian.PutUint64(buf[:], i)
	return buf[:]
}
