// smtp_listener.go - SMTP listener.
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

package mailproxy

import (
	"bytes"
	"encoding/hex"
	"fmt"
	"net"
	"sync/atomic"

	"github.com/katzenpost/core/crypto/ecdh"
	"github.com/katzenpost/core/worker"
	"github.com/katzenpost/mailproxy/internal/account"
	"github.com/katzenpost/mailproxy/internal/imf"
	"github.com/op/go-logging"
	"github.com/siebenmann/smtpd"
)

var smtpdCfg = smtpd.Config{
	LocalName: "localhost",
	SftName:   "Katzenpost",
	SayTime:   false,
}

type smtpListener struct {
	worker.Worker

	p   *Proxy
	l   net.Listener
	log *logging.Logger

	connID uint64
}

func (l *smtpListener) Halt() {
	// Close the listener and wait for the workers to return.
	l.l.Close()
	l.Worker.Halt()
}

func (l *smtpListener) worker() {
	addr := l.l.Addr()
	l.log.Noticef("Listening on: %v", addr)
	defer func() {
		l.log.Noticef("Stopping listening on: %v", addr)
		l.l.Close() // Usually redundant, but harmless.
	}()
	for {
		conn, err := l.l.Accept()
		if err != nil {
			if e, ok := err.(net.Error); ok && !e.Temporary() {
				l.log.Errorf("Critical accept failure: %v", err)
				return
			}
			continue
		}

		l.onNewConn(conn)
	}

	// NOTREACHED
}

func (l *smtpListener) onNewConn(conn net.Conn) error {
	l.log.Debugf("Accepted new connection: %v", conn.RemoteAddr())

	s := new(smtpSession)
	s.l = l
	s.id = atomic.AddUint64(&l.connID, 1)
	s.log = l.p.logBackend.GetLogger(fmt.Sprintf("SMTP:%d", s.id))
	s.nConn = conn
	s.sConn = smtpd.NewConn(conn, smtpdCfg, s)

	l.Go(func() { s.worker() })
	return nil
}

func newSMTPListener(p *Proxy) (*smtpListener, error) {
	l := new(smtpListener)
	l.p = p
	l.log = p.logBackend.GetLogger("listener/SMTP")

	var err error
	l.l, err = net.Listen("tcp", p.cfg.Proxy.SMTPAddress)
	if err != nil {
		return nil, err
	}

	l.Go(l.worker)
	return l, nil
}

type smtpSession struct {
	l *smtpListener

	log *logging.Logger

	nConn net.Conn
	sConn *smtpd.Conn
	id    uint64
}

func (s *smtpSession) worker() {
	defer s.nConn.Close()

	env := &smtpEnvelope{}
	defer env.Reset() // This holds an account.Account, which is refcounted.

evLoop:
	for {
		ev := s.sConn.Next()
		switch ev.What {
		case smtpd.DONE, smtpd.ABORT:
			break evLoop
		case smtpd.COMMAND:
			// Check for cancelation.  This assumes the peer is going
			// to be sending commands in a timely manner, which seems
			// reasonable in the context of a local mail proxy.
			select {
			case <-s.l.HaltCh():
				s.sConn.RejectMsg("Server shutting down")
				break evLoop
			default:
			}

			// Conn.Next() will enforce command ordering, so this
			// can just accumulate based on the command, resetting
			// as appropriate.
			switch ev.Cmd {
			case smtpd.MAILFROM:
				accID, _, _, err := s.l.p.recipients.Normalize(ev.Arg)
				if err != nil {
					s.log.Warningf("Invalid MAIL FROM argument '%v': %v", ev.Arg, err)
					s.sConn.Reject()
					break
				}
				acc, err := s.l.p.accounts.Get(accID)
				if err != nil {
					s.log.Warningf("MAIL FROM ('%v') does not specify a valid account: %v", accID, err)
					s.sConn.Reject()
					break
				}
				s.log.Debugf("Set account: '%v'", accID)
				env.SetAccount(acc) // Takes ownership of the acc ref count.
			case smtpd.RCPTTO:
				rcptID, local, domain, err := s.l.p.recipients.Normalize(ev.Arg)
				if err != nil {
					s.log.Warningf("Invalid RCPT TO argument '%v': %v", ev.Arg, err)
					s.sConn.Reject()
					break
				}
				rcpt := &smtpRecipient{
					id:        rcptID,
					recipient: local,
					provider:  domain,
					pubKey:    s.l.p.recipients.Get(rcptID),
				}
				if rcpt.pubKey == nil {
					s.log.Warningf("RCPT TO ('%v') does not specify a known recipient.", rcptID)
					s.sConn.Reject()
					break
				}
				s.log.Debugf("Added recipient: '%v'", rcptID)
				env.AddRecipient(rcpt)
			case smtpd.DATA:
			case smtpd.HELO, smtpd.EHLO, smtpd.RSET:
				env.Reset()
			default:
				s.log.Errorf("Invalid command: %v", ev.Cmd)
				s.sConn.Reject()
				break evLoop
			}
		case smtpd.GOTDATA:
			entity, err := imf.BytesToEntity([]byte(ev.Arg))
			if err != nil {
				s.log.Errorf("Malformed IMF: %v", err)
				env.Reset()
				s.sConn.Reject()
				break
			}

			// Add the headers that normal MTAs will too.
			imf.AddMessageID(entity)
			// XXX: Received header.

			// Re-serialize the IMF message now to apply the new headers,
			// and canonicalize the line endings.
			payload, err := imf.EntityToBytes(entity)
			if err != nil {
				s.log.Errorf("Failed to re-serialize IMF: %v", err)
				env.Reset()
				s.sConn.Reject()
				break
			}

			s.log.Debugf("DATA: %v", hex.Dump(payload))
			env.SetPayload(payload)

			// XXX: Do something with the completed envelope.
			env.DedupRecipients()

			env.Reset()
		default:
			s.log.Errorf("Invalid event: %v", ev)
			break evLoop
		}
	}

	s.log.Debugf("Connection terminated.")
}

func (s *smtpSession) Write(p []byte) (n int, err error) {
	// This is used to adapt the smtpd package's idea of logging to our
	// leveled logging interface.

	if len(p) == 0 {
		return 0, nil
	}

	logType := p[0]
	if logType == 'r' || logType == 'w' {
		// Keep the prefix for network read/write debug logs.
		s.log.Debug(string(p))
		return len(p), nil
	}

	logMsg := string(bytes.TrimSpace(p[1:]))
	if len(logMsg) == 0 {
		return len(p), nil
	}
	switch logType {
	case '#':
		s.log.Notice(logMsg)
	case '!':
		s.log.Error(logMsg)
	default:
		// Should never happen, according to the package docs.
		s.log.Debugf("Unknown log type '%v': %v", logType, logMsg)
	}

	return len(p), nil
}

type smtpRecipient struct {
	id        string
	recipient string
	provider  string
	pubKey    *ecdh.PublicKey
}

type smtpEnvelope struct {
	account    *account.Account
	recipients []*smtpRecipient
	payload    []byte
}

func (e *smtpEnvelope) SetAccount(a *account.Account) {
	if e.account != nil {
		e.account.Deref()
	}
	e.account = a
}

func (e *smtpEnvelope) SetPayload(p []byte) {
	e.payload = p
}

func (e *smtpEnvelope) AddRecipient(r *smtpRecipient) {
	e.recipients = append(e.recipients, r)
}

func (e *smtpEnvelope) DedupRecipients() {
	newR := make([]*smtpRecipient, 0, len(e.recipients))

	dedupMap := make(map[string]bool)
	for _, v := range e.recipients {
		if !dedupMap[v.id] {
			dedupMap[v.id] = true
			newR = append(newR, v)
		}
	}
	e.recipients = newR
}

func (e *smtpEnvelope) Reset() {
	e.SetAccount(nil)
	e.recipients = nil
	e.SetPayload(nil)
}
