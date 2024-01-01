// mautrix-signal - A Matrix-signal puppeting bridge.
// Copyright (C) 2023 Scott Weber, Tulir Asokan
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

package database

import (
	"context"
	"database/sql"
	"time"

	"go.mau.fi/util/dbutil"
	"maunium.net/go/mautrix/id"
)

const (
	getUnscheduledDisappearingMessagesForRoomQuery = `
		SELECT room_id, mxid, expiration_seconds, expiration_ts
		FROM disappearing_message WHERE expiration_ts IS NULL AND room_id = $1
	`
	getExpiredDisappearingMessagesQuery = `
		SELECT room_id, mxid, expiration_seconds, expiration_ts
		FROM disappearing_message WHERE expiration_ts IS NOT NULL AND expiration_ts <= $1
	`
	getNextDisappearingMessageQuery = `
		SELECT room_id, mxid, expiration_seconds, expiration_ts
		FROM disappearing_message WHERE expiration_ts IS NOT NULL ORDER BY expiration_ts ASC LIMIT 1
	`
	insertDisappearingMessageQuery = `
		INSERT INTO disappearing_message (room_id, mxid, expiration_seconds, expiration_ts) VALUES ($1, $2, $3, $4)
	`
	updateDisappearingMessageQuery = `
		UPDATE disappearing_message SET expiration_ts=$2 WHERE mxid=$1
	`
	deleteDisappearingMessageQuery = `
		DELETE FROM disappearing_message WHERE mxid=$1
	`
)

type DisappearingMessageQuery struct {
	*dbutil.QueryHelper[*DisappearingMessage]
}

type DisappearingMessage struct {
	qh *dbutil.QueryHelper[*DisappearingMessage]

	RoomID   id.RoomID
	EventID  id.EventID
	ExpireIn time.Duration
	ExpireAt time.Time
}

func newDisappearingMessage(qh *dbutil.QueryHelper[*DisappearingMessage]) *DisappearingMessage {
	return &DisappearingMessage{qh: qh}
}

func (dmq *DisappearingMessageQuery) NewWithValues(roomID id.RoomID, eventID id.EventID, expireIn time.Duration, expireAt time.Time) *DisappearingMessage {
	return &DisappearingMessage{
		qh:       dmq.QueryHelper,
		RoomID:   roomID,
		EventID:  eventID,
		ExpireIn: expireIn,
		ExpireAt: expireAt,
	}
}

func (dmq *DisappearingMessageQuery) GetUnscheduledForRoom(ctx context.Context, roomID id.RoomID) ([]*DisappearingMessage, error) {
	return dmq.QueryMany(ctx, getUnscheduledDisappearingMessagesForRoomQuery, roomID)
}

func (dmq *DisappearingMessageQuery) GetExpiredMessages(ctx context.Context) ([]*DisappearingMessage, error) {
	return dmq.QueryMany(ctx, getExpiredDisappearingMessagesQuery, time.Now().Unix()+1)
}

func (dmq *DisappearingMessageQuery) GetNextScheduledMessage(ctx context.Context) (*DisappearingMessage, error) {
	return dmq.QueryOne(ctx, getNextDisappearingMessageQuery)
}

func (msg *DisappearingMessage) Scan(row dbutil.Scannable) (*DisappearingMessage, error) {
	var expireIn int64
	var expireAt sql.NullInt64
	err := row.Scan(&msg.RoomID, &msg.EventID, &expireIn, &expireAt)
	if err != nil {
		return nil, err
	}
	msg.ExpireIn = time.Duration(expireIn) * time.Second
	if expireAt.Valid {
		msg.ExpireAt = time.Unix(expireAt.Int64, 0)
	}
	return msg, nil
}

func (msg *DisappearingMessage) sqlVariables() []any {
	var expireAt sql.NullInt64
	if !msg.ExpireAt.IsZero() {
		expireAt.Valid = true
		expireAt.Int64 = msg.ExpireAt.Unix()
	}
	return []any{msg.RoomID, msg.EventID, int64(msg.ExpireIn.Seconds()), expireAt}
}

func (msg *DisappearingMessage) Insert(ctx context.Context) error {
	return msg.qh.Exec(ctx, insertDisappearingMessageQuery, msg.sqlVariables()...)
}

func (msg *DisappearingMessage) StartExpirationTimer(ctx context.Context) error {
	msg.ExpireAt = time.Now().Add(msg.ExpireIn)
	return msg.qh.Exec(ctx, updateDisappearingMessageQuery, msg.EventID, msg.ExpireAt.Unix())
}

func (msg *DisappearingMessage) Delete(ctx context.Context) error {
	return msg.qh.Exec(ctx, deleteDisappearingMessageQuery, msg.EventID)
}
