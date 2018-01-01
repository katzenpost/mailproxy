// store.go - Provider store.
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

// Package account implements the provider account backend.
package account

import (
	"errors"
	"sync"

	"github.com/katzenpost/core/log"
	"github.com/katzenpost/mailproxy/config"
	"github.com/katzenpost/mailproxy/internal/authority"
	"github.com/katzenpost/mailproxy/internal/glue"
	"github.com/katzenpost/mailproxy/internal/pop3"
)

var (
	errInvalidID     = errors.New("account: invalid identifier")
	errNoSuchAccount = errors.New("account: no such account")
	errExists        = errors.New("account: provided id/account already exists")
)

// Store is a group of Account instances.
type Store struct {
	sync.Mutex

	cfg         *config.Config
	logBackend  *log.Backend
	authorities *authority.Store

	accounts map[string]*Account
}

// Set sets the Account identified by id, to a new Account parameterised by the
// provided config.Account cfg.
func (s *Store) Set(id string, cfg *config.Account) error {
	if id == "" {
		return errInvalidID
	}

	s.Lock()
	defer s.Unlock()

	if _, ok := s.accounts[id]; ok {
		return errExists
	}

	a, err := s.newAccount(id, cfg)
	if err != nil {
		return err
	}
	s.accounts[id] = a
	return nil
}

// Get returns the Account identified by id, after incrementing the reference
// count.
func (s *Store) Get(id string) (*Account, error) {
	s.Lock()
	defer s.Unlock()

	if id == "" {
		return nil, errNoSuchAccount
	}

	if a, ok := s.accounts[id]; ok {
		a.refCount++
		return a, nil
	}
	return nil, errNoSuchAccount
}

// NewSession creates a new pop3.BackendSession backed by the specified user,
// where the user is of the form `user@provider`.
func (s *Store) NewSession(user, pass []byte) (pop3.BackendSession, error) {
	a, err := s.Get(string(user))
	if err != nil {
		return nil, err
	}

	sess, err := a.newPOPSession()
	if err != nil {
		a.Deref()
		return nil, pop3.ErrBackendFail
	}
	return sess, nil
}

// Reset clears the existing Store instance, terminating clients associated
// with each account entry.
func (s *Store) Reset() {
	s.Lock()
	defer s.Unlock()

	for id, v := range s.accounts {
		v.doDeref()
		if v.refCount != 0 {
			panic("BUG: account: Account has non-zero refcount: " + id)
		}
	}
}

// NewStore constructs a new Store instance.
func NewStore(g glue.ProxyInternals) *Store {
	s := new(Store)
	s.cfg = g.Config()
	s.logBackend = g.LogBackend()
	s.authorities = g.Authorities()
	s.accounts = make(map[string]*Account)

	return s
}
