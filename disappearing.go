// mautrix-signal - A Matrix-signal puppeting bridge.
// Copyright (C) 2023 Scott Weber
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU Affero General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.
//
// This program is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
// GNU Affero General Public License for more details.
//
// You should have received a copy of the GNU Affero General Public License
// along with this program.  If not, see <https://www.gnu.org/licenses/>.

package main

import (
	"context"
	"fmt"
	"time"

	"github.com/rs/zerolog"
	"maunium.net/go/mautrix"
	"maunium.net/go/mautrix/id"

	"go.mau.fi/mautrix-signal/database"
)

type DisappearingMessagesManager struct {
	DB                *database.Database
	Log               zerolog.Logger
	Bridge            *SignalBridge
	checkMessagesChan chan struct{}
}

func (dmm *DisappearingMessagesManager) ScheduleDisappearingForRoom(roomID id.RoomID) {
	dmm.Log.Debug().Msgf("Scheduling disappearing messages for %s", roomID)
	disappearingMessages := dmm.DB.DisappearingMessage.GetUnscheduledForRoom(roomID)
	for _, disappearingMessage := range disappearingMessages {
		dmm.Log.Debug().Msgf("Scheduling disappearing message %s", disappearingMessage.EventID)
		disappearingMessage.StartExpirationTimer()
	}

	// Tell the disappearing messages loop to check again
	dmm.checkMessagesChan <- struct{}{}
}

func (dmm *DisappearingMessagesManager) StartDisappearingLoop(ctx context.Context) {
	dmm.checkMessagesChan = make(chan struct{}, 1)
	go func() {
		for {
			dmm.redactExpiredMessages()

			duration := 10 * time.Minute // Check again in 10 minutes just in case
			nextMsg := dmm.DB.DisappearingMessage.GetNextScheduledMessage()
			if nextMsg != nil {
				dmm.Log.Debug().Msgf("Next message to expire is %s in %s", nextMsg.EventID, nextMsg.ExpireAt.Sub(time.Now()))
				duration = nextMsg.ExpireAt.Sub(time.Now())
			}

			select {
			case <-time.After(duration):
				// We should have at least one expired message now, so we should check again
				dmm.Log.Debug().Msgf("Duration (%s) is up, checking for expired messages", duration)
			case <-dmm.checkMessagesChan:
				// There are new messages in the DB, so we should check again
				dmm.Log.Debug().Msg("New messages in DB, checking again")
			case <-ctx.Done():
				// We've been told to stop
				dmm.Log.Debug().Msg("Stopping disappearing messages loop")
				return
			}
		}
	}()
}

func (dmm *DisappearingMessagesManager) redactExpiredMessages() {
	// Get all expired messages and redact them
	expiredMessages := dmm.DB.DisappearingMessage.GetExpiredMessages()

	for _, msg := range expiredMessages {
		portal := dmm.Bridge.GetPortalByMXID(msg.RoomID)
		if portal == nil {
			dmm.Log.Warn().Msgf("Failed to redact message %s in room %s: portal not found", msg.EventID, msg.RoomID)
			return
		}
		// Redact the message
		_, err := portal.MainIntent().RedactEvent(msg.RoomID, msg.EventID, mautrix.ReqRedact{
			Reason: "Message expired",
			TxnID:  fmt.Sprintf("mxsig_disappear_%s", msg.EventID),
		})
		if err != nil {
			portal.log.Warn().Msgf("Failed to make %s disappear: %v", msg.EventID, err)
		} else {
			portal.log.Debug().Msgf("Disappeared %s", msg.EventID)
		}
		msg.Delete()
	}
}

func (dmm *DisappearingMessagesManager) AddDisappearingMessage(eventID id.EventID, roomID id.RoomID, expireInSeconds int64, startTimerNow bool) {
	if expireInSeconds == 0 {
		dmm.Log.Debug().Msgf("Not adding disappearing message %s: expireIn is 0", eventID)
		return
	}
	dmm.Log.Debug().Msgf("Adding disappearing message %s", eventID)
	expireAt := time.Time{}
	if startTimerNow {
		expireAt = time.Now().Add(time.Duration(expireInSeconds) * time.Second)
	}
	disappearingMessage := dmm.DB.DisappearingMessage.NewWithValues(roomID, eventID, expireInSeconds, expireAt)
	disappearingMessage.Insert(nil)

	if startTimerNow {
		// Tell the disappearing messages loop to check again
		dmm.checkMessagesChan <- struct{}{}
	}
}
