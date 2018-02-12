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
	"github.com/katzenpost/core/pki"
)

type workerOp interface{}

type opIsEmpty struct{}

type opConnStatusChanged struct {
	isConnected bool
}

type opNewDocument struct {
	doc *pki.Document
}

func (a *Account) worker() {
	const (
		maxDuration = math.MaxInt64
		minInterval = 1000 // 1000 ms
	)

	lambdaP := 0.00001
	maxInterval := uint64(rand.ExpQuantile(lambdaP, 0.99999))
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
				// TODO: This needs to figure out if no block was sent,
				// and send cover traffic.
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
				// Note: a.isConnected isn't used in favor of passing the
				// value via an op, to save on locking headaches.
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
			case *opNewDocument:
				// Update the idea of lambdaP from the PKI document.
				if newLambdaP := op.doc.LambdaP; newLambdaP != lambdaP {
					a.log.Debugf("Updated lambdaP: %v", newLambdaP)
					lambdaP = newLambdaP
				}
				if newMaxInterval := op.doc.MaxInterval; newMaxInterval != maxInterval {
					if newMaxInterval < minInterval {
						a.log.Debugf("Ignoring pathologically small maxInterval: %v", newMaxInterval)
						continue
					}
					a.log.Debugf("Updated maxInterval: %v", newMaxInterval)
					maxInterval = newMaxInterval
				}
			default:
				a.log.Warningf("BUG: Worker received nonsensical op: %T", op)
			}
		}
		if isConnected {
			// Per section 4.1.2 of the Loopix paper:
			//
			//   Users emit payload messages following a Poisson
			//   distribution with parameter lambdaP. All messages
			//   scheduled for sending by the user are placed within
			//   a first-in first-out buffer. According to a Poisson
			//   process, a single message is popped out of the buffer
			//   and sent, or a drop cover message is sent in case the
			//   buffer is empty. Thus, from an adversarial perspective,
			//   there is always traffic emitted modeled by Pois(lambdaP).
			wakeMsec := uint64(rand.Exp(mRng, lambdaP)) + minInterval
			switch {
			case wakeMsec > maxInterval:
				wakeMsec = maxInterval
			default:
			}

			wakeInterval = time.Duration(wakeMsec) * time.Millisecond
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
