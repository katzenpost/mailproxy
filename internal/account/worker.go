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

	"github.com/katzenpost/core/constants"
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
		serviceLoop = "loop"
	)

	// Intentionally use super conservative values for the send scheduling
	// if the PKI happens to not specify any.
	sendLambda := 0.00001
	sendMaxInterval := uint64(rand.ExpQuantile(sendLambda, 0.99999))

	mRng := rand.NewMath()
	wakeInterval := time.Duration(maxDuration)
	timer := time.NewTimer(wakeInterval)
	defer timer.Stop()

	var isConnected, hasLoopService bool
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
				// Attempt to send user data first, if any exists.
				didSend, err := a.sendNextBlock()
				if err != nil {
					a.log.Warningf("Failed to send queued block: %v", err)
				} else if !didSend && hasLoopService {
					var coverPayload [constants.UserForwardPayloadLength]byte

					// Send cover traffic via the loop service instead.
					if err = a.sendInternalKaetzchenRequest(serviceLoop, a.clientCfg.Provider, coverPayload[:], true); err != nil {
						a.log.Warningf("Failed to send cover traffic: %v", err)
					}
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
				// Update the Send[Lambda,MaxInterval] parameters from
				// the PKI document.
				if newSendLambda := op.doc.LambdaP; newSendLambda != sendLambda {
					a.log.Debugf("Updated SendLambda: %v", newSendLambda)
					sendLambda = newSendLambda
				}
				if newSendMaxInterval := op.doc.LambdaPMaxDelay; newSendMaxInterval != sendMaxInterval {
					a.log.Debugf("Updated SendMaxInterval: %v", newSendMaxInterval)
					sendMaxInterval = newSendMaxInterval
				}

				// Determine if it is possible to send cover traffic.
				if ep, err := a.getServiceEndpoint(op.doc, a.clientCfg.Provider, serviceLoop); err != nil {
					a.log.Debugf("Failed to find loop service: %v", err)
					hasLoopService = false
				} else {
					a.log.Debugf("Provider has loop service: '%v'", ep)
					hasLoopService = true
				}

				// Override sending decoy traffic based on config.
				if !a.s.cfg.Debug.SendDecoyTraffic {
					a.log.Debugf("Client decoy traffic disabled via config.")
					hasLoopService = false
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
			wakeMsec := uint64(rand.Exp(mRng, sendLambda))
			switch {
			case wakeMsec > sendMaxInterval:
				wakeMsec = sendMaxInterval
			default:
			}

			wakeInterval = time.Duration(wakeMsec) * time.Millisecond
			a.log.Debugf("wakeInterval: %v", wakeInterval)
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
