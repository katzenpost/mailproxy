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
	"path/filepath"
	"sync"

	"github.com/katzenpost/core/log"
	"github.com/katzenpost/core/thwack"
	"github.com/katzenpost/core/utils"
	"github.com/katzenpost/mailproxy/config"
	"github.com/katzenpost/mailproxy/internal/account"
	"github.com/katzenpost/mailproxy/internal/authority"
	"github.com/katzenpost/mailproxy/internal/imf"
	"github.com/katzenpost/mailproxy/internal/recipient"
	"gopkg.in/op/go-logging.v1"
)

// ErrGenerateOnly is the error returned when the server initialization
var ErrGenerateOnly = errors.New("mailproxy: GenerateOnly set")

// Proxy is a mail proxy server instance.
type Proxy struct {
	cfg *config.Config

	logBackend *log.Backend
	log        *logging.Logger

	accounts     *account.Store
	authorities  *authority.Store
	recipients   *recipient.Store
	popListener  *popListener
	smtpListener *smtpListener
	management   *thwack.Server

	fatalErrCh chan error
	haltedCh   chan interface{}
	haltOnce   sync.Once
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

// SendMessage sends a message to a specified destination
func (p *Proxy) SendMessage(senderID, recipientID string, payload []byte) error {
	accID, _, _, err := p.recipients.Normalize(senderID)
	if err != nil {
		p.log.Warningf("Invalid sender identity '%v': %v", senderID, err)
		return err
	}
	acc, err := p.accounts.Get(accID)
	if err != nil {
		p.log.Warningf("Sender identity ('%v') does not specify a valid account: %v", accID, err)
		return err
	}
	defer acc.Deref()
	rcptID, local, domain, err := p.recipients.Normalize(recipientID)
	if err != nil {
		p.log.Warningf("Invalid recipient identity argument '%v': %v", recipientID, err)
		return err
	}
	rcpt := &account.Recipient{
		ID:        rcptID,
		User:      local,
		Provider:  domain,
		PublicKey: p.recipients.Get(rcptID),
	}
	if rcpt.PublicKey == nil {
		p.log.Warningf("Recipient identity ('%v') does not specify a known recipient.", rcptID)
		return errors.New("Recipient identity unknown.")
	}
	// Parse the message payload so that headers can be manipulated,
	// and ensure that there is a Message-ID header, and prepend the
	// "Received" header.
	entity, err := imf.BytesToEntity(payload)
	if err != nil {
		return err
	}
	imf.AddMessageID(entity)
	viaESMTP := false
	imf.AddReceived(entity, true, viaESMTP)
	isUnreliable, err := imf.IsUnreliable(entity)
	if err != nil {
		return err
	}
	// Re-serialize the IMF message now to apply the new headers,
	// and canonicalize the line endings.
	payloadIMF, err := imf.EntityToBytes(entity)
	if err != nil {
		return err
	}
	if err = acc.EnqueueMessage(rcpt, payloadIMF, isUnreliable); err != nil {
		p.log.Errorf("Failed to enqueue for '%v': %v", rcpt, err)
		return err
	}
	return nil
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

	if p.authorities != nil {
		p.authorities.Reset()
		p.authorities = nil
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
	g := &proxyGlue{p: p}

	// Do the early initialization and bring up logging.
	if err := utils.MkDataDir(p.cfg.Proxy.DataDir); err != nil {
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

	var err error
	// Bring the management interface online if enabled.
	if !p.cfg.Debug.GenerateOnly && p.cfg.Management.Enable {
		p.log.Noticef("bringing managment interface online")
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
	p.recipients = recipient.New(p.cfg.Debug, p.management)
	for k, v := range p.cfg.Recipients {
		// Failures to add recipients are non-fatal.
		if err = p.recipients.Set(k, v); err != nil {
			p.log.Warningf("Failed to add recipient '%v' to store: %v", k, err)
		}
	}

	// Bring the authority cache online.
	p.authorities = authority.NewStore(p.logBackend)
	for k, v := range p.cfg.AuthorityMap() {
		if err = p.authorities.Set(k, v); err != nil {
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

	// If POP3 and SMTP proxy were specified
	if p.cfg.Proxy == nil {
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
	}

	// Start listening on the management if enabled, now that all subsystems
	// have had the opportunity to register commands.
	if p.management != nil {
		p.management.Start()
	}

	isOk = true
	return p, nil
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

func (g *proxyGlue) Authorities() *authority.Store {
	return g.p.authorities
}

func (g *proxyGlue) FatalErrCh() chan<- error {
	return g.p.fatalErrCh
}
