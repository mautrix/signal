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
	"time"

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
