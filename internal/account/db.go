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
//   - "publicKey"   - File encryption public key if ever set.
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
	"math"
	"path/filepath"

	bolt "github.com/coreos/bbolt"
	"github.com/katzenpost/core/crypto/ecdh"
	"github.com/katzenpost/core/crypto/rand"
	"github.com/katzenpost/noise"
)

func (a *Account) initDatabase(basePath string) error {
	const (
		metadataBucket = "metadata"
		versionKey     = "version"
		dbPublicKey    = "publicKey"
	)

	var err error
	a.db, err = bolt.Open(filepath.Join(basePath, "storage.db"), 0600, nil)
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
		if _, err := recvBkt.CreateBucketIfNotExists([]byte(pendingBlocksKey)); err != nil {
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
		if _, err := sendBkt.CreateBucketIfNotExists([]byte(urgentSpoolBucket)); err != nil {
			return err
		}

		if b := bkt.Get([]byte(versionKey)); b != nil {
			if len(b) != 1 || b[0] != 0 {
				return fmt.Errorf("db: incompatible version: %v", b)
			}

			if b = recvBkt.Get([]byte(dbPublicKey)); b != nil {
				var storePubKey ecdh.PublicKey
				if err = storePubKey.FromBytes(b); err != nil {
					return fmt.Errorf("db: failed to deserialize public key: %v", err)
				}
				if a.storageKey != nil {
					return fmt.Errorf("db: encrypted database with no storage key configured")
				}
				if !a.storageKey.PublicKey().Equal(&storePubKey) {
					return fmt.Errorf("db: provided storage key does not match the database")
				}
			} else if a.storageKey != nil {
				return fmt.Errorf("db: storage key configured for unencrypted database")
			}

			// Restore state.
			b = recvBkt.Get([]byte(lastDedupGCKey))
			if len(b) == 8 {
				a.lastDedupGC = binary.BigEndian.Uint64(b)
			}
			b = recvBkt.Get([]byte(lastFragsSweepKey))
			if len(b) == 8 {
				a.lastFragsSweep = binary.BigEndian.Uint64(b)
			}
			b = sendBkt.Get([]byte(lastSendGCKey))
			if len(b) == 8 {
				a.lastSendGC = binary.BigEndian.Uint64(b)
			}

			return nil
		}

		bkt.Put([]byte(versionKey), []byte{0})
		if a.storageKey != nil {
			bkt.Put([]byte(dbPublicKey), a.storageKey.PublicKey().Bytes())
		}
		return nil
	})
	if err != nil {
		a.db.Close()
		a.db = nil
	}
	return err
}

func (a *Account) dbEncryptAndPut(bkt *bolt.Bucket, key, value []byte) error {
	if a.storageKey == nil {
		return bkt.Put(key, value)
	}

	hs := a.newDBCryptoState(false)
	ciphertext, _, _, err := hs.WriteMessage(nil, value)
	if err != nil {
		return err
	}
	return bkt.Put(key, ciphertext)
}

func (a *Account) dbGetAndDecrypt(bkt *bolt.Bucket, key []byte) []byte {
	if a.storageKey == nil {
		return bkt.Get(key)
	}

	return a.dbDecrypt(bkt.Get(key))
}

func (a *Account) dbDecrypt(ciphertext []byte) []byte {
	if a.storageKey == nil {
		// Presumably this is stored in the clear.
		return ciphertext
	}
	if ciphertext == nil {
		return nil
	}
	hs := a.newDBCryptoState(true)
	plaintext, _, _, err := hs.ReadMessage(nil, ciphertext)
	if err != nil {
		panic("dbEncryptedGet: decryption failed: " + err.Error())
	}
	return plaintext
}

func (a *Account) newDBCryptoState(forDecrypt bool) *noise.HandshakeState {
	cs := noise.NewCipherSuite(noise.DH25519, noise.CipherChaChaPoly, noise.HashSHA256)
	cfg := noise.Config{
		CipherSuite: cs,
		Random:      rand.Reader,
		Pattern:     noise.HandshakeN,
		Initiator:   !forDecrypt,
		MaxMsgLen:   math.MaxInt32,
	}
	if forDecrypt {
		cfg.StaticKeypair = noise.DHKey{
			Private: a.storageKey.Bytes(),
			Public:  a.storageKey.PublicKey().Bytes(),
		}
	} else {
		cfg.PeerStatic = a.storageKey.PublicKey().Bytes()
	}

	hs, err := noise.NewHandshakeState(cfg)
	if err != nil {
		panic("newDBCryptoState: initialization failed: " + err.Error())
	}
	return hs
}

func uint64ToBytes(i uint64) []byte {
	// Avoid the foot + gun pitfalls of BoltDB's Put() call being reference
	// based by allocating byte slices.
	var buf [8]byte
	binary.BigEndian.PutUint64(buf[:], i)
	return buf[:]
}

func copyOutBytes(b []byte) []byte {
	ret := make([]byte, 0, len(b))
	ret = append(ret, b...)
	return ret
}
