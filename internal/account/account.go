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
	"path/filepath"
	"sync"
	"time"

	bolt "github.com/coreos/bbolt"
	"github.com/katzenpost/core/crypto/ecdh"
	"github.com/katzenpost/core/crypto/rand"
	"github.com/katzenpost/core/pki"
	"github.com/katzenpost/core/utils"
	"github.com/katzenpost/core/worker"
	"github.com/katzenpost/mailproxy/config"
	"github.com/katzenpost/mailproxy/event"
	"github.com/katzenpost/mailproxy/internal/authority"
	"github.com/katzenpost/mailproxy/internal/proxy"
	"github.com/katzenpost/minclient"
	"gopkg.in/op/go-logging.v1"
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
	clientCfg *minclient.ClientConfig

	linkKey     *ecdh.PrivateKey
	identityKey *ecdh.PrivateKey
	storageKey  *ecdh.PrivateKey

	popSession *popSession

	id string

	onRecvCh       chan interface{}
	opCh           chan workerOp
	onlineAt       time.Time
	emptyAt        time.Time
	lastDedupGC    uint64
	lastFragsSweep uint64
	lastSendGC     uint64

	isConnected bool
	refCount    int32
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

func (a *Account) GetID() string {
	return a.id
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
	if a.storageKey != nil {
		a.storageKey.Reset()
	}
}

func (a *Account) initKeys(cfg *config.Account, basePath string) error {
	var err error

	if cfg.LinkKey != nil {
		// Copy to avoid side-effects.
		a.linkKey = new(ecdh.PrivateKey)
		a.linkKey.FromBytes(cfg.LinkKey.Bytes())
	} else {
		linkPriv := filepath.Join(basePath, "link.private.pem")
		linkPub := filepath.Join(basePath, "link.public.pem")

		if a.linkKey, err = ecdh.Load(linkPriv, linkPub, rand.Reader); err != nil {
			return err
		}
	}

	if cfg.IdentityKey != nil {
		// Copy to avoid side-effects.
		a.identityKey = new(ecdh.PrivateKey)
		a.identityKey.FromBytes(cfg.IdentityKey.Bytes())
	} else {
		idPriv := filepath.Join(basePath, "identity.private.pem")
		idPub := filepath.Join(basePath, "identity.public.pem")
		a.identityKey, err = ecdh.Load(idPriv, idPub, rand.Reader)
	}

	a.storageKey = cfg.StorageKey

	return err
}

func (a *Account) onConn(err error) {
	a.log.Debugf("onConn(%v)", err)

	a.s.eventCh <- &event.ConnectionStatusEvent{
		AccountID:   a.id,
		IsConnected: err == nil,
		Err:         err,
	}

	a.Lock()
	defer a.Unlock()

	wasConnected, isConnected := a.isConnected, err == nil
	a.isConnected = isConnected

	if a.refCount > 0 && wasConnected != a.isConnected {
		// Wake up the worker so it can adjust it's send scheduling.
		a.opCh <- &opConnStatusChanged{isConnected}
	}
}

func (a *Account) onEmpty() error {
	a.log.Debugf("onEmpty()")

	a.Lock()
	defer a.Unlock()

	if a.refCount > 0 {
		// Call into the worker to update the state.
		a.opCh <- &opIsEmpty{}
	}
	return nil
}

func (a *Account) onMessage(msg []byte) error {
	return a.enqueueBlockCiphertext(msg)
}

func (a *Account) onDocument(doc *pki.Document) {
	a.log.Debugf("onDocument(): Epoch %v", doc.Epoch)

	a.Lock()
	defer a.Unlock()

	if a.refCount > 0 {
		// Wake up the worker so it can adjust it's lambdaP.
		a.opCh <- &opNewDocument{doc}
	}
}

func (a *Account) nowUnix() uint64 {
	return uint64(time.Now().Unix())
}

// IsConnected returns true iff the account is connected.
func (a *Account) IsConnected() bool {
	a.Lock()
	defer a.Unlock()

	return a.isConnected
}

func (a *Account) InsecureKeyDiscovery() bool {
	return a.clientCfg.InsecureKeyDiscovery
}

func (s *Store) newAccount(id string, cfg *config.Account, pCfg *proxy.Config) (*Account, error) {
	a := new(Account)
	a.s = s
	a.log = s.logBackend.GetLogger("account:" + id)
	a.onRecvCh = make(chan interface{}, 1)
	a.opCh = make(chan workerOp, 8) // Workaround minclient#1.
	a.id = id
	a.refCount = 1 // Store holds a reference.

	// Initialize the per-account directory.
	basePath := filepath.Join(s.cfg.Proxy.DataDir, id)
	if err := utils.MkDataDir(basePath); err != nil {
		return nil, err
	}

	// Initialize the cryptographic keys.
	if err := a.initKeys(cfg, basePath); err != nil {
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
	if err := a.initDatabase(basePath); err != nil {
		return nil, err
	}

	// Configure and bring up the minclient instance.
	a.clientCfg = &minclient.ClientConfig{
		User:                 cfg.User,
		Provider:             cfg.Provider,
		ProviderKeyPin:       cfg.ProviderKeyPin,
		LinkKey:              a.linkKey,
		LogBackend:           s.logBackend,
		PKIClient:            nil, // Set later.
		OnConnFn:             a.onConn,
		OnEmptyFn:            a.onEmpty,
		OnMessageFn:          a.onMessage,
		OnACKFn:              a.onSURB, // Defined in send.go.
		OnDocumentFn:         a.onDocument,
		DialContextFn:        pCfg.ToDialContext(id),
		MessagePollInterval:  time.Duration(a.s.cfg.Debug.PollingInterval) * time.Second,
		EnableTimeSync:       false, // Be explicit about it.
		PreferedTransports:   pCfg.PreferedTransports,
		InsecureKeyDiscovery: cfg.InsecureKeyDiscovery,
	}

	var err error
	a.authority, err = s.authorities.Get(cfg.Authority)
	if err != nil {
		return nil, err
	}
	a.clientCfg.PKIClient = a.authority.Client()

	a.client, err = minclient.New(a.clientCfg)
	if err != nil {
		return nil, err
	}

	// Start the workers.
	a.Go(a.worker)
	a.Go(a.recvWorker)

	isOk = true
	return a, nil
}
