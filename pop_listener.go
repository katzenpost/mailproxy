// pop_listener.go - POP3 listener.
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
	"net"

	"github.com/katzenpost/core/worker"
	"github.com/katzenpost/mailproxy/internal/pop3"
	"github.com/op/go-logging"
)

type popListener struct {
	worker.Worker

	p   *Proxy
	l   net.Listener
	log *logging.Logger
}

func (l *popListener) Halt() {
	// Close the listener and wait for the worker(s) to return.
	l.l.Close()
	l.Worker.Halt()

	// TODO: Force close all POP3 sessions somehow.
}

func (l *popListener) worker() {
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

		rAddr := conn.RemoteAddr()
		l.log.Debugf("Accepted new connection: %v", rAddr)
		l.Go(func() { l.connWorker(conn, rAddr) })
	}

	// NOTREACHED
}

func (l *popListener) connWorker(conn net.Conn, addr net.Addr) {
	session := pop3.NewSession(conn, l.p.accounts)
	session.Serve()

	l.log.Debugf("Connection terminated: %v", addr)
}

func newPOPListener(p *Proxy) (*popListener, error) {
	l := new(popListener)
	l.p = p
	l.log = p.logBackend.GetLogger("listener/POP3")

	var err error
	l.l, err = net.Listen("tcp", p.cfg.Proxy.POP3Address)
	if err != nil {
		return nil, err
	}

	l.Go(l.worker)
	return l, nil
}
