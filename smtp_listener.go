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
	"errors"
	"fmt"
	"net"
	"sync/atomic"

	"github.com/katzenpost/core/worker"
	"github.com/katzenpost/mailproxy/internal/account"
	"github.com/katzenpost/mailproxy/internal/imf"
	"github.com/siebenmann/smtpd"
	"gopkg.in/op/go-logging.v1"
)

var (
	smtpdCfg = smtpd.Config{
		LocalName: imf.LocalName,
		SftName:   "Katzenpost",
		SayTime:   false,
	}

	errEnqueueAllFailed = errors.New("enqueue failed for ALL recipients, rejecting")
)

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

	var viaESMTP bool
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
			case smtpd.HELO:
				viaESMTP = false
				env.Reset()
			case smtpd.EHLO:
				viaESMTP = true
				env.Reset()
			case smtpd.RSET:
				env.Reset()
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
				env.SetAccount(accID, acc) // Takes ownership of the acc ref count.
			case smtpd.RCPTTO:
				rcptID, local, domain, err := s.l.p.recipients.Normalize(ev.Arg)
				if err != nil {
					s.log.Warningf("Invalid RCPT TO argument '%v': %v", ev.Arg, err)
					s.sConn.Reject()
					break
				}
				rcpt := &account.Recipient{
					ID:        rcptID,
					User:      local,
					Provider:  domain,
					PublicKey: s.l.p.recipients.Get(rcptID),
				}
				if rcpt.PublicKey == nil {
					s.log.Warningf("RCPT TO ('%v') does not specify a known recipient.", rcptID)
					s.sConn.Reject()
					break
				}
				s.log.Debugf("Added recipient: '%v'", rcptID)
				env.AddRecipient(rcpt)
			case smtpd.DATA:
			default:
				s.log.Errorf("Invalid command: %v", ev.Cmd)
				s.sConn.Reject()
				break evLoop
			}
		case smtpd.GOTDATA:
			if err := s.onGotData(env, []byte(ev.Arg), viaESMTP); err != nil {
				s.log.Errorf("Failed to handle received message: %v", err)
				s.sConn.Reject()
			}
		default:
			s.log.Errorf("Invalid event: %v", ev)
			break evLoop
		}
	}

	s.log.Debugf("Connection terminated.")
}

func (s *smtpSession) onGotData(env *smtpEnvelope, b []byte, viaESMTP bool) error {
	defer env.Reset()

	// De-duplicate the recipients.
	env.DedupRecipients()
	if len(env.recipients) == 0 {
		return nil
	}

	// Parse the message payload so that headers can be manipulated,
	// and ensure that there is a Message-ID header, and prepend the
	// "Received" header.
	entity, err := imf.BytesToEntity(b)
	if err != nil {
		return err
	}
	imf.AddMessageID(entity)
	imf.AddReceived(entity, true, viaESMTP)
	isUnreliable, err := imf.IsUnreliable(entity)
	if err != nil {
		return err
	}

	// Re-serialize the IMF message now to apply the new headers,
	// and canonicalize the line endings.
	payload, err := imf.EntityToBytes(entity)
	if err != nil {
		return err
	}

	// TODO: It is probably worth grouping all recipients of a given message
	// into a single send queue entry instead of creating a queue entry for
	// each recipient, but this is a far more simple approach, and unlike
	// traditional MTAs, mailproxy is only going to be servicing a single
	// user with a comparatively low volume of mail anyway.
	failed := make(map[string]error)
	var enqueued []string
	for _, recipient := range env.recipients {
		// Add the message to the send queue.
		if err = env.account.EnqueueMessage(recipient, payload, isUnreliable); err != nil {
			s.log.Errorf("Failed to enqueue for '%v': %v", recipient, err)
			failed[recipient.ID] = err
			continue
		} else {
			enqueued = append(enqueued, recipient.ID)
		}
	}

	switch len(failed) {
	case 0:
		return nil
	case len(env.recipients):
		// Technically I think I'm supposed to create a bounce message,
		// but that's silly when I can just reject the SMTP transaction.
		//
		// LMTP fully supports rejecting at send time on a per-recipient
		// basis, but we need to use SMTP, unfortunately.
		return errEnqueueAllFailed
	default:
	}

	// Generate a multipart/report indicating which recipients failed.
	report, err := imf.NewEnqueueFailure(env.accountID, enqueued, failed, entity.Header)
	if err != nil {
		return err
	}
	return env.account.StoreReport(report)
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

type smtpEnvelope struct {
	account    *account.Account
	recipients []*account.Recipient
	accountID  string
}

func (e *smtpEnvelope) SetAccount(id string, a *account.Account) {
	if e.account != nil {
		e.account.Deref()
	}
	e.account = a
	e.accountID = id
}

func (e *smtpEnvelope) AddRecipient(r *account.Recipient) {
	e.recipients = append(e.recipients, r)
}

func (e *smtpEnvelope) DedupRecipients() {
	newR := make([]*account.Recipient, 0, len(e.recipients))

	dedupMap := make(map[string]bool)
	for _, v := range e.recipients {
		if !dedupMap[v.ID] {
			dedupMap[v.ID] = true
			newR = append(newR, v)
		}
	}
	e.recipients = newR
}

func (e *smtpEnvelope) Reset() {
	e.SetAccount("", nil)
	e.recipients = nil
}
