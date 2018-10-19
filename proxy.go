// proxy.go - Katzenpost client mailproxy.
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

// Package mailproxy implements a POP/SMTP to Katzenpost proxy server.
package mailproxy

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sync"

	"github.com/katzenpost/core/log"
	"github.com/katzenpost/core/thwack"
	"github.com/katzenpost/core/utils"
	"github.com/katzenpost/core/worker"
	"github.com/katzenpost/mailproxy/config"
	"github.com/katzenpost/mailproxy/event"
	"github.com/katzenpost/mailproxy/internal/account"
	"github.com/katzenpost/mailproxy/internal/authority"
	"github.com/katzenpost/mailproxy/internal/recipient"
	"gopkg.in/eapache/channels.v1"
	"gopkg.in/op/go-logging.v1"
)

// ErrGenerateOnly is the error returned when the server initialization
var ErrGenerateOnly = errors.New("mailproxy: GenerateOnly set")

// Proxy is a mail proxy server instance.
type Proxy struct {
	worker.Worker
	cfg *config.Config

	logBackend *log.Backend
	log        *logging.Logger

	accounts             *account.Store
	votingAuthorities    *authority.Store
	nonvotingAuthorities *authority.Store
	recipients           *recipient.Store
	popListener          *popListener
	smtpListener         *smtpListener
	eventListener        *eventListener
	management           *thwack.Server

	fatalErrCh chan error
	eventCh    channels.Channel
	haltedCh   chan interface{}
	haltOnce   sync.Once
	EventSink  chan event.Event
}

func (p *Proxy) initLogging() error {
	f := p.cfg.Logging.File
	if !p.cfg.Logging.Disable && p.cfg.Logging.File != "" {
		if !filepath.IsAbs(f) {
			f = filepath.Join(p.cfg.Proxy.DataDir, f)
		}
	}

	var err error
	p.logBackend, err = log.New(f, p.cfg.Logging.Level, p.cfg.Logging.Disable)
	if err == nil {
		p.log = p.logBackend.GetLogger("mailproxy")
	}
	return err
}

// Shutdown cleanly shuts down a given Proxy instance.
func (p *Proxy) Shutdown() {
	p.haltOnce.Do(func() { p.halt() })
}

// Wait waits till the Proxy is terminated for any reason.
func (p *Proxy) Wait() {
	<-p.haltedCh
}

func (p *Proxy) halt() {
	// WARNING: The ordering of operations here is deliberate, and should not
	// be altered without a deep understanding of how all the components fit
	// together.

	p.log.Noticef("Starting graceful shutdown.")

	if p.popListener != nil {
		p.popListener.Halt()
		p.popListener = nil
	}

	if p.smtpListener != nil {
		p.smtpListener.Halt()
		p.smtpListener = nil
	}

	if p.management != nil {
		p.management.Halt()
		p.management = nil
	}

	if p.accounts != nil {
		p.accounts.Reset()
		p.accounts = nil
	}

	if p.nonvotingAuthorities != nil || p.votingAuthorities != nil {
		p.nonvotingAuthorities.Reset()
		p.nonvotingAuthorities = nil
		p.votingAuthorities.Reset()
		p.votingAuthorities = nil
	}

	p.Halt()

	if p.eventListener != nil {
		p.eventListener.Halt()
		p.eventListener = nil
	}

	close(p.fatalErrCh)

	p.log.Noticef("Shutdown complete.")
	close(p.haltedCh)
}

// New returns a new Proxy instance parameterized with the specified
// configuration.
func New(cfg *config.Config) (*Proxy, error) {
	p := new(Proxy)
	p.cfg = cfg
	p.fatalErrCh = make(chan error)
	p.haltedCh = make(chan interface{})
	p.eventCh = channels.NewInfiniteChannel()
	g := &proxyGlue{p: p}

	// Do the early initialization and bring up logging.
	if err := utils.MkDataDir(p.cfg.Proxy.DataDir); err != nil {
		return nil, err
	}
	if err := utils.MkDataDir(p.cfg.Proxy.RecipientDir); err != nil {
		return nil, err
	}
	if err := p.initLogging(); err != nil {
		return nil, err
	}

	p.log.Noticef("Katzenpost is still pre-alpha.  DO NOT DEPEND ON IT FOR STRONG SECURITY OR ANONYMITY.")

	isOk := false
	defer func() {
		if !isOk {
			p.Shutdown()
		}
	}()

	// Start the fatal error watcher.
	go func() {
		err, ok := <-p.fatalErrCh
		if !ok {
			return
		}
		p.log.Warningf("Shutting down due to error: %v", err)
		p.Shutdown()
	}()

	if !p.cfg.Debug.GenerateOnly {
		p.initializeEventSink()
	}

	var err error
	// Bring the management interface online if enabled.
	if !p.cfg.Debug.GenerateOnly && p.cfg.Management.Enable {
		p.log.Noticef("Bringing managment interface online.")
		mgmtCfg := &thwack.Config{
			Net:         "unix",
			Addr:        p.cfg.Management.Path,
			ServiceName: "Katzenpost Mailproxy Management Interface",
			LogModule:   "mgmt",
			NewLoggerFn: p.logBackend.GetLogger,
		}
		if p.management, err = thwack.New(mgmtCfg); err != nil {
			p.log.Errorf("Failed to initialize management interface: %v", err)
			return nil, err
		}

		const shutdownCmd = "SHUTDOWN"
		p.management.RegisterCommand(shutdownCmd, func(c *thwack.Conn, l string) error {
			p.fatalErrCh <- fmt.Errorf("user requested shutdown via mgmt interface")
			return nil
		})
	}

	// Initialize the recipient public key store.
	p.recipients = recipient.New(p.cfg, p.management)
	for k, v := range p.cfg.Recipients {
		// Failures to add recipients are non-fatal.
		if err = p.recipients.Set(k, v); err != nil {
			p.log.Warningf("Failed to add recipient '%v' to store: %v", k, err)
		}
	}

	// Import recipient PEM-encoded identities
	if err = p.ScanRecipientDir(); err != nil {
		return nil, err
	}

	// Bring the authority cache online.
	p.votingAuthorities = authority.NewStore(p.logBackend, p.cfg.UpstreamProxyConfig())
	for k, v := range p.cfg.VotingAuthorityMap() {
		if err = p.votingAuthorities.Set(k, v); err != nil {
			p.log.Errorf("Failed to add authority '%v' to store: %v", k, err)
			return nil, err
		}
		p.log.Debugf("Added authority '%v'.", k)
	}

	p.nonvotingAuthorities = authority.NewStore(p.logBackend, p.cfg.UpstreamProxyConfig())
	for k, v := range p.cfg.NonvotingAuthorityMap() {
		if err = p.nonvotingAuthorities.Set(k, v); err != nil {
			p.log.Errorf("Failed to add authority '%v' to store: %v", k, err)
			return nil, err
		}
		p.log.Debugf("Added authority '%v'.", k)
	}

	// Bring the accounts online.
	p.accounts = account.NewStore(g)
	for k, v := range p.cfg.AccountMap() {
		if err = p.accounts.Set(k, v); err != nil {
			p.log.Errorf("Failed to add account '%v' to store: %v", k, err)
			return nil, err
		}
		p.log.Debugf("Added account '%v'.", k)
	}

	// No need to bring the listeners online if we are going to terminate
	// immediately.
	if p.cfg.Debug.GenerateOnly {
		return nil, ErrGenerateOnly
	}

	// Bring the EventSink listener online.
	p.log.Debug("Starting EventSink listener.")
	p.eventListener = newEventListener(p)

	if !p.cfg.Proxy.NoLaunchListeners {
		// Bring the POP3 interface online.
		if p.popListener, err = newPOPListener(p); err != nil {
			p.log.Errorf("Failed to start POP3 listener: %v", err)
			return nil, err
		}

		// Bring the SMTP interface online.
		if p.smtpListener, err = newSMTPListener(p); err != nil {
			p.log.Errorf("Failed to start SMTP listener: %v", err)
			return nil, err
		}
	} else {
		p.log.Debugf("Skipping POP3/SMTP listener initialization.")
	}

	// Start listening on the management if enabled, now that all subsystems
	// have had the opportunity to register commands.
	if p.management != nil {
		const cmdQueryRecipient = "QUERY_RECIPIENT"

		p.management.RegisterCommand(cmdQueryRecipient, p.onQueryRecipient)
		p.management.Start()
	}

	isOk = true
	return p, nil
}

// ScanRecipientDir looks for for PEM-encoded identities in the ReceipientDir and imports into the recipient Store.
func (p *Proxy) ScanRecipientDir() error {
	p.log.Noticef("Scanning RecipientDir for identities.")
	path := p.cfg.Proxy.RecipientDir
	err := filepath.Walk(path, func(pth string, info os.FileInfo, err error) error {
		switch pth {
		case path:
		default:
			err := p.recipients.LoadFromPEM(pth)
			if err != nil {
				return err
			}
		}
		return nil
	})
	return err
}

type proxyGlue struct {
	p *Proxy
}

func (g *proxyGlue) Config() *config.Config {
	return g.p.cfg
}

func (g *proxyGlue) LogBackend() *log.Backend {
	return g.p.logBackend
}

func (g *proxyGlue) NonvotingAuthorities() *authority.Store {
	return g.p.nonvotingAuthorities
}

func (g *proxyGlue) VotingAuthorities() *authority.Store {
	return g.p.votingAuthorities
}

func (g *proxyGlue) EventCh() chan<- interface{} {
	return g.p.eventCh.In()
}

func (g *proxyGlue) FatalErrCh() chan<- error {
	return g.p.fatalErrCh
}
