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

func (dmm *DisappearingMessagesManager) ScheduleDisappearingForRoom(ctx context.Context, roomID id.RoomID) {
	log := dmm.Log.With().Stringer("room_id", roomID).Logger()
	disappearingMessages, err := dmm.DB.DisappearingMessage.GetUnscheduledForRoom(ctx, roomID)
	if err != nil {
		log.Err(err).Msg("Failed to get unscheduled disappearing messages")
		return
	}
	for _, disappearingMessage := range disappearingMessages {
		err = disappearingMessage.StartExpirationTimer(ctx)
		if err != nil {
			log.Err(err).Msg("Failed to schedule disappearing message")
		} else {
			log.Debug().
				Str("event_id", disappearingMessage.EventID.String()).
				Time("expire_at", disappearingMessage.ExpireAt).
				Msg("Scheduling disappearing message")
		}
	}

	// Tell the disappearing messages loop to check again
	dmm.checkMessagesChan <- struct{}{}
}

func (dmm *DisappearingMessagesManager) StartDisappearingLoop(ctx context.Context) {
	dmm.checkMessagesChan = make(chan struct{}, 1)
	go func() {
		log := dmm.Log.With().Str("action", "loop").Logger()
		ctx = log.WithContext(ctx)
		for {
			dmm.redactExpiredMessages(ctx)

			duration := 10 * time.Minute // Check again in 10 minutes just in case
			nextMsg, err := dmm.DB.DisappearingMessage.GetNextScheduledMessage(ctx)
			if err != nil {
				if ctx.Err() != nil {
					return
				}
				log.Err(err).Msg("Failed to get next disappearing message")
				continue
			} else if nextMsg != nil {
				duration = nextMsg.ExpireAt.Sub(time.Now())
			}

			select {
			case <-time.After(duration):
			case <-dmm.checkMessagesChan:
			case <-ctx.Done():
				return
			}
		}
	}()
}

func (dmm *DisappearingMessagesManager) redactExpiredMessages(ctx context.Context) {
	log := zerolog.Ctx(ctx)
	expiredMessages, err := dmm.DB.DisappearingMessage.GetExpiredMessages(ctx)
	if err != nil {
		log.Err(err).Msg("Failed to get expired disappearing messages")
		return
	}

	for _, msg := range expiredMessages {
		portal := dmm.Bridge.GetPortalByMXID(msg.RoomID)
		if portal == nil {
			log.Warn().Stringer("event_id", msg.EventID).Stringer("room_id", msg.RoomID).Msg("Failed to redact message: portal not found")
			err = msg.Delete(ctx)
			if err != nil {
				log.Err(err).
					Str("event_id", msg.EventID.String()).
					Msg("Failed to delete disappearing message row in database")
			}
			continue
		}
		_, err = portal.MainIntent().RedactEvent(ctx, msg.RoomID, msg.EventID, mautrix.ReqRedact{
			Reason: "Message expired",
			TxnID:  fmt.Sprintf("mxsg_disappear_%s", msg.EventID),
		})
		if err != nil {
			log.Err(err).
				Str("event_id", msg.EventID.String()).
				Str("room_id", msg.RoomID.String()).
				Msg("Failed to redact message")
		} else {
			log.Err(err).
				Str("event_id", msg.EventID.String()).
				Str("room_id", msg.RoomID.String()).
				Msg("Redacted message")
		}
		err = msg.Delete(ctx)
		if err != nil {
			log.Err(err).
				Str("event_id", msg.EventID.String()).
				Msg("Failed to delete disappearing message row in database")
		}
	}
}

func (dmm *DisappearingMessagesManager) AddDisappearingMessage(ctx context.Context, eventID id.EventID, roomID id.RoomID, expireIn time.Duration, startTimerNow bool) {
	if expireIn == 0 {
		return
	}
	var expireAt time.Time
	if startTimerNow {
		expireAt = time.Now().Add(expireIn)
	}
	disappearingMessage := dmm.DB.DisappearingMessage.NewWithValues(roomID, eventID, expireIn, expireAt)
	err := disappearingMessage.Insert(ctx)
	if err != nil {
		zerolog.Ctx(ctx).Err(err).Stringer("event_id", eventID).
			Msg("Failed to add disappearing message to database")
		return
	}
	zerolog.Ctx(ctx).Debug().Stringer("event_id", eventID).
		Msg("Added disappearing message row to database")
	if startTimerNow {
		// Tell the disappearing messages loop to check again
		dmm.checkMessagesChan <- struct{}{}
	}
}
