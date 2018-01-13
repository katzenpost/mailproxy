// worker.go - Per-account periodic worker.
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

package account

import (
	"math"
	"time"

	"github.com/katzenpost/core/crypto/rand"
)

type workerOp interface{}

type opIsEmpty struct{}

type opConnStatusChanged struct {
	isConnected bool
}

func (a *Account) worker() {
	const maxDuration = math.MaxInt64

	tau := a.s.cfg.Debug.TransmitTau
	mRng := rand.NewMath()
	isConnected := false
	wakeInterval := time.Duration(maxDuration)
	timer := time.NewTimer(wakeInterval)
	defer timer.Stop()

	for {
		var timerFired bool
		var qo workerOp
		select {
		case <-a.HaltCh():
			return
		case <-timer.C:
			timerFired = true
		case qo = <-a.opCh:
		}

		if timerFired {
			// It is time to send another block if one exists.
			if isConnected { // Suppress spurious wakeups.
				if err := a.sendNextBlock(); err != nil {
					a.log.Warningf("Failed to send queued block: %v", err)
				}
			}
		} else {
			switch op := qo.(type) {
			case *opIsEmpty:
				a.emptyAt = time.Now()
				a.doDedupGC()
				a.doFragsSweep()
				a.doSendGC()
				continue
			case *opConnStatusChanged:
				if isConnected = op.isConnected; isConnected {
					const skewWarnDelta = 2 * time.Minute
					a.onlineAt = time.Now()

					skew := a.client.ClockSkew()
					absSkew := skew
					if absSkew < 0 {
						absSkew = -absSkew
					}
					if absSkew > skewWarnDelta {
						// Should this do more than just warn?  Should this
						// use skewed time?  I don't know.
						a.log.Warningf("The observed time difference between the host and provider clocks is '%v'.  Correct your system time.", skew)
					} else {
						a.log.Debugf("Clock skew vs provider: %v", skew)
					}
				}
			default:
				a.log.Warningf("BUG: Worker received nonsensical op: %T", op)
			}
		}
		if isConnected {
			// In a perfect world, this would probably send both cover
			// traffic and payload at a fixed interval.  However I currently
			// view this as impractical for a few reasons.
			//
			//  * It is unclear to me what a good "fixed" interval will be
			//    such that sufficient useful cover traffic is generated,
			//    while neither overloading the network nor making mobile
			//    users cry, while allowing for sufficient goodput.
			//
			//  * Fixed intervals leak information via the jitter.
			//
			// Until someone comes up with satesfactory answers to both
			// questions, an alternate strategy will be used that attempts
			// to mimimize information leakage, while also being capable
			// of being tuned as required.
			wakeInterval = time.Duration(tau+mRng.Intn(tau*2)) * time.Millisecond
		} else {
			wakeInterval = maxDuration
		}
		if !timerFired && !timer.Stop() {
			<-timer.C
		}
		timer.Reset(wakeInterval)
	}

	// NOTREACHED
}
