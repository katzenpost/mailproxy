// account.go - Provider interface.
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

import (
	"encoding/hex"
	"fmt"
	"path/filepath"
	"strings"
	"sync"
	"time"

	bolt "github.com/coreos/bbolt"
	"github.com/katzenpost/core/crypto/ecdh"
	"github.com/katzenpost/core/crypto/rand"
	"github.com/katzenpost/core/utils"
	"github.com/katzenpost/core/worker"
	"github.com/katzenpost/mailproxy/config"
	"github.com/katzenpost/mailproxy/internal/authority"
	"github.com/katzenpost/minclient"
	"github.com/katzenpost/minclient/block"
	"github.com/op/go-logging"
)

// Account is a Provider account and it's associated client instance.
type Account struct {
	worker.Worker
	sync.Mutex
	s *Store

	log       *logging.Logger
	db        *bolt.DB
	authority *authority.Authority
	client    *minclient.Client
	basePath  string

	linkKey     *ecdh.PrivateKey
	identityKey *ecdh.PrivateKey

	popSession *popSession

	id       string
	refCount int32

	opCh        chan workerOp
	onlineAt    time.Time
	emptyAt     time.Time
	lastDedupGC uint64
	lastSendGC  uint64
}

// Deref decrements the reference count of the Account.  If the reference count
// reaches 0, the Account will be torn down and removed from it's associated
// Store.
func (a *Account) Deref() {
	a.s.Lock()
	defer a.s.Unlock()

	a.doDeref()
}

func (a *Account) doDeref() {
	// Note: This assumes the Store lock is held.

	a.refCount--
	switch {
	case a.refCount == 0:
		// This is used to clean up partially constructed instances,
		// so the account isn't guaranteed to be in the store.
		if _, ok := a.s.accounts[a.id]; ok {
			delete(a.s.accounts, a.id)
		}
		a.doCleanup()
	case a.refCount < 0:
		panic("BUG: account: refcount is negative: " + a.id)
	default:
	}
}

func (a *Account) doCleanup() {
	a.Halt()

	if a.popSession != nil {
		// This should never happen, the POP3 server is torn down before
		// everything else...
		a.log.Warningf("POP3 session still open on account teardown.")
	}
	if a.client != nil {
		a.client.Shutdown()
		a.client = nil
	}
	if a.authority != nil {
		a.authority.Deref()
		a.authority = nil
	}
	if a.db != nil {
		a.db.Sync()
		a.db.Close()
		a.db = nil
	}

	a.linkKey.Reset()
	a.identityKey.Reset()
}

func (a *Account) initKeys(cfg *config.Account) error {
	var err error

	// WARNING: Using the Force[Link,Encryption]Key options is a bad idea
	// unless you know what you are doing.

	if cfg.ForceLinkKey != "" {
		if a.linkKey, err = privKeyFromString(cfg.ForceLinkKey); err != nil {
			return err
		}
	} else {
		linkPriv := filepath.Join(a.basePath, "link.private.pem")
		linkPub := filepath.Join(a.basePath, "link.public.pem")

		if a.linkKey, err = ecdh.Load(linkPriv, linkPub, rand.Reader); err != nil {
			return err
		}
	}

	if cfg.ForceIdentityKey != "" {
		a.identityKey, err = privKeyFromString(cfg.ForceIdentityKey)
	} else {
		idPriv := filepath.Join(a.basePath, "identity.private.pem")
		idPub := filepath.Join(a.basePath, "identity.public.pem")
		a.identityKey, err = ecdh.Load(idPriv, idPub, rand.Reader)
	}
	return err
}

func (a *Account) onConn(isConnected bool) {
	a.log.Debugf("onConn(%v)", isConnected)

	// Wake up the worker so it can adjust it's send scheduling.
	a.opCh <- &opConnStatusChanged{isConnected}
}

func (a *Account) onEmpty() error {
	a.log.Debugf("onEmpty()")

	// Call into the worker to update the state.
	a.opCh <- &opIsEmpty{}

	return nil
}

func (a *Account) onMessage(msg []byte) error {
	// XXX: Should errors here bring the server down instead of just tearing
	// down the connection?  They should essentially NEVER happen, unless the
	// database has totally shit itself.

	// Decrypt the block.
	blk, sender, err := block.DecryptBlock(msg, a.identityKey)
	if err != nil {
		a.log.Warningf("Failed to decrypt message into a Block: %v", err)

		// Save undecryptable ciphertexts.
		return a.onBlockDecryptFailure(msg)
	}

	// Store the block.  The DB code handles reassembly and shunting messages
	// to the POP3 account's spool.
	return a.onBlock(sender, blk)
}

func (a *Account) nowUnix() uint64 {
	return uint64(time.Now().Unix())
}

func (s *Store) newAccount(id string, cfg *config.Account) (*Account, error) {
	a := new(Account)
	a.s = s
	a.log = s.logBackend.GetLogger("account:" + id)
	a.basePath = filepath.Join(s.cfg.Proxy.DataDir, id)
	a.opCh = make(chan workerOp)
	a.id = id
	a.refCount = 1 // Store holds a reference.

	// Initialize the per-account directory.
	if err := utils.MkDataDir(a.basePath); err != nil {
		return nil, err
	}

	// Initialize the cryptographic keys.
	if err := a.initKeys(cfg); err != nil {
		return nil, err
	}

	if s.cfg.Debug.GenerateOnly {
		// Bail before actually bringing the account online.
		return a, nil
	}

	isOk := false
	defer func() {
		if !isOk {
			a.doDeref()
		}
	}()

	// Initialize the storage backend.
	if err := a.initDatabase(); err != nil {
		return nil, err
	}

	// Configure and bring up the minclient instance.
	clientCfg := &minclient.ClientConfig{
		User:           cfg.User,
		Provider:       cfg.Provider,
		ProviderKeyPin: cfg.ProviderKeyPin,
		LinkKey:        a.linkKey,
		LogBackend:     s.logBackend,
		PKIClient:      nil, // Set later.
		OnConnFn:       a.onConn,
		OnEmptyFn:      a.onEmpty,
		OnMessageFn:    a.onMessage,
		OnACKFn:        a.onSURB, // Defined in send.go.
	}

	var err error
	a.authority, err = s.authorities.Get(cfg.Authority)
	if err != nil {
		return nil, err
	}
	clientCfg.PKIClient = a.authority.Client()

	a.client, err = minclient.New(clientCfg)
	if err != nil {
		return nil, err
	}

	// Start the worker.
	a.Go(a.worker)

	isOk = true
	return a, nil
}

func privKeyFromString(s string) (*ecdh.PrivateKey, error) {
	s = strings.TrimSpace(s)
	raw, err := hex.DecodeString(s)
	if err != nil {
		return nil, fmt.Errorf("failed to parse key: %v", err)
	}
	defer utils.ExplicitBzero(raw) // Sort of pointless because of strings.

	k := new(ecdh.PrivateKey)
	if err = k.FromBytes(raw); err != nil {
		return nil, err
	}
	return k, nil
}
