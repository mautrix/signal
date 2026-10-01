// mautrix-signal - A Matrix-Signal puppeting bridge.
// Copyright (C) 2026 Killian Lelong
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

package connector

import (
	"context"
	"errors"
	"time"

	"github.com/google/uuid"
	"github.com/rs/zerolog"
	"maunium.net/go/mautrix/bridgev2/database"

	"go.mau.fi/mautrix-signal/pkg/signalid"
	"go.mau.fi/mautrix-signal/pkg/signalmeow/protobuf/signalpb"

	"maunium.net/go/mautrix/bridgev2"
)

func (s *SignalClient) startViewOnceTimers(ctx context.Context, portal *bridgev2.Portal, readUpTo, readAt time.Time) error {
	messages, err := s.Main.Bridge.DB.DisappearingMessage.QueryMany(ctx, `
		SELECT bridge_id, mx_room, mxid, timestamp, 'view_limited', timer, $1+timer
		FROM disappearing_message WHERE bridge_id=$2 AND mx_room=$3 AND type IN ('after_read', 'view_limited') AND timer>0 AND disappear_at>$1+timer AND timestamp<=$4
		AND EXISTS (SELECT 1 FROM message m WHERE m.bridge_id=$2 AND m.mxid=disappearing_message.mxid
			AND m.room_id=$5 AND m.room_receiver=$6 AND CAST(m.metadata->>'view_once' AS TEXT) IN ('true', '1'))`,
		readAt.UnixNano(), s.Main.Bridge.ID, portal.MXID, readUpTo.UnixNano(), portal.ID, portal.Receiver)
	if err != nil {
		return err
	}
	for _, msg := range messages {
		if err = s.Main.Bridge.DisappearLoop.Add(ctx, msg); err != nil {
			return err
		}
	}
	return nil
}

var (
	_ bridgev2.RemotePostHandler                  = (*Bv2ChatEvent)(nil)
	_ bridgev2.ViewLimitedMediaHandlingNetworkAPI = (*SignalClient)(nil)
)

func (evt *Bv2ChatEvent) PostHandle(ctx context.Context, portal *bridgev2.Portal) {
	msg, ok := evt.Event.(*signalpb.DataMessage)
	if !ok || !msg.GetIsViewOnce() || portal.Receiver == "" {
		return
	}
	opened, err := evt.s.Client.Store.ViewOnceStore.IsViewOnceOpened(ctx, evt.Info.Sender, msg.GetTimestamp())
	if err == nil && opened {
		err = evt.s.expireOpenedViewOnce(ctx, portal, evt.Info.Sender, msg.GetTimestamp())
	}
	if err != nil {
		zerolog.Ctx(ctx).Err(err).Msg("Failed to expire opened view-once message after delivery")
	}
}

func (s *SignalClient) expireOpenedViewOnce(ctx context.Context, portal *bridgev2.Portal, sender uuid.UUID, timestamp uint64) error {
	messages, err := s.Main.Bridge.DB.Message.GetAllPartsByID(ctx, s.UserLogin.ID, signalid.MakeMessageID(sender, timestamp))
	if err != nil {
		return err
	}
	if len(messages) == 0 {
		return nil
	}
	if portal == nil {
		portal, err = s.Main.Bridge.GetExistingPortalByKey(ctx, messages[0].Room)
		if err != nil || portal == nil {
			return err
		}
	}
	for _, msg := range messages {
		if !msg.Metadata.(*signalid.MessageMetadata).ViewOnce {
			continue
		}
		if err = s.Main.Bridge.DisappearLoop.Add(ctx, &database.DisappearingMessage{
			RoomID: portal.MXID, EventID: msg.MXID, Timestamp: msg.Timestamp,
			DisappearingSetting: database.DisappearingSetting{Type: "view_limited", DisappearAt: time.Now()},
		}); err != nil {
			return err
		}
	}
	return s.Client.Store.ViewOnceStore.MarkViewOnceHandled(ctx, sender, timestamp)
}

func (s *SignalClient) retryViewOnceExpiry(ctx context.Context) {
	ticker := time.NewTicker(5 * time.Second)
	defer ticker.Stop()
	for ctx.Err() == nil {
		if err := s.reconcileViewOnceExpiry(ctx); err != nil && ctx.Err() == nil {
			zerolog.Ctx(ctx).Err(err).Msg("Failed to retry view-once expiry")
		}
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
		}
	}
}

func (s *SignalClient) reconcileViewOnceExpiry(ctx context.Context) error {
	opens, err := s.Client.Store.ViewOnceStore.GetPendingViewOnceOpens(ctx)
	if err != nil {
		return err
	}
	for _, opened := range opens {
		if ctx.Err() != nil {
			return ctx.Err()
		}
		err = errors.Join(err, s.expireOpenedViewOnce(ctx, nil, opened.Sender, opened.Timestamp))
	}
	return err
}
