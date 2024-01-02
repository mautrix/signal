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
	"fmt"
	"strings"

	"github.com/google/uuid"
	"github.com/lib/pq"
	"go.mau.fi/util/dbutil"
	"maunium.net/go/mautrix/id"
)

const (
	getMessageByMXIDQuery = `
		SELECT sender, timestamp, part_index, signal_chat_id, signal_receiver, mxid, mx_room FROM message
		WHERE mxid=$1
	`
	getMessagePartBySignalIDQuery = `
        SELECT sender, timestamp, part_index, signal_chat_id, signal_receiver, mxid, mx_room FROM message
        WHERE sender=$1 AND timestamp=$2 AND part_index=$3 AND signal_receiver=$4
	`
	getLastMessagePartBySignalIDQuery = `
        SELECT sender, timestamp, part_index, signal_chat_id, signal_receiver, mxid, mx_room FROM message
        WHERE sender=$1 AND timestamp=$2 AND signal_receiver=$3
        ORDER BY part_index DESC LIMIT 1
	`
	getAllMessagePartsBySignalIDQuery = `
        SELECT sender, timestamp, part_index, signal_chat_id, signal_receiver, mxid, mx_room FROM message
        WHERE sender=$1 AND timestamp=$2 AND signal_receiver=$3
	`
	getMessageLastPartBySignalIDWithUnknownReceiverQuery = `
        SELECT sender, timestamp, part_index, signal_chat_id, signal_receiver, mxid, mx_room FROM message
        WHERE sender=$1 AND timestamp=$2 AND (signal_receiver=$3 OR signal_receiver='00000000-0000-0000-0000-000000000000')
        ORDER BY part_index DESC LIMIT 1
	`
	getManyMessagesBySignalIDQueryPostgres = `
		SELECT sender, timestamp, part_index, signal_chat_id, signal_receiver, mxid, mx_room FROM message
		WHERE sender=$1 AND (signal_receiver=$2 OR signal_receiver=$3) AND timestamp=ANY($4)
		ORDER BY timestamp DESC, part_index DESC
	`
	getManyMessagesBySignalIDQuerySQLite = `
		SELECT sender, timestamp, part_index, signal_chat_id, signal_receiver, mxid, mx_room FROM message
		WHERE sender=?1 AND (signal_receiver=?2 OR signal_receiver=?3) AND timestamp IN (?4)
		ORDER BY timestamp DESC, part_index DESC
	`
	getFirstBeforeQuery = `
		SELECT sender, timestamp, part_index, signal_chat_id, signal_receiver, mxid, mx_room FROM message
		WHERE mx_room=$1 AND timestamp <= $2
		ORDER BY timestamp DESC
		LIMIT 1
	`
	insertMessageQuery = `
		INSERT INTO message (sender, timestamp, part_index, signal_chat_id, signal_receiver, mxid, mx_room)
		VALUES ($1, $2, $3, $4, $5, $6, $7)
	`
	deleteMessageQuery = `
        DELETE FROM message
        WHERE sender=$1 AND timestamp=$2 AND part_index=$3 AND signal_receiver=$4
	`
)

type MessageQuery struct {
	*dbutil.QueryHelper[*Message]
}

type Message struct {
	qh *dbutil.QueryHelper[*Message]

	Sender    uuid.UUID
	Timestamp uint64
	PartIndex int

	SignalChatID   string
	SignalReceiver uuid.UUID

	MXID   id.EventID
	RoomID id.RoomID
}

func newMessage(qh *dbutil.QueryHelper[*Message]) *Message {
	return &Message{qh: qh}
}

func (mq *MessageQuery) GetByMXID(ctx context.Context, mxid id.EventID) (*Message, error) {
	return mq.QueryOne(ctx, getMessageByMXIDQuery, mxid)
}

func (mq *MessageQuery) GetBySignalID(ctx context.Context, sender uuid.UUID, timestamp uint64, partIndex int, receiver uuid.UUID) (*Message, error) {
	return mq.QueryOne(ctx, getMessagePartBySignalIDQuery, sender, timestamp, partIndex, receiver)
}

func (mq *MessageQuery) GetLastPartBySignalID(ctx context.Context, sender uuid.UUID, timestamp uint64, receiver uuid.UUID) (*Message, error) {
	return mq.QueryOne(ctx, getLastMessagePartBySignalIDQuery, sender, timestamp, receiver)
}

func (mq *MessageQuery) GetAllPartsBySignalID(ctx context.Context, sender uuid.UUID, timestamp uint64, receiver uuid.UUID) ([]*Message, error) {
	return mq.QueryMany(ctx, getAllMessagePartsBySignalIDQuery, sender, timestamp, receiver)
}

func (mq *MessageQuery) GetLastPartBySignalIDWithUnknownReceiver(ctx context.Context, sender uuid.UUID, timestamp uint64, receiver uuid.UUID) (*Message, error) {
	return mq.QueryOne(ctx, getMessageLastPartBySignalIDWithUnknownReceiverQuery, sender, timestamp, receiver)
}

func (mq *MessageQuery) GetManyBySignalID(ctx context.Context, sender uuid.UUID, timestamps []uint64, receiver uuid.UUID, strictReceiver bool) ([]*Message, error) {
	receiver2 := uuid.Nil
	if strictReceiver {
		receiver2 = receiver
	}
	if mq.GetDB().Dialect == dbutil.Postgres {
		int64Array := make([]int64, len(timestamps))
		for i, timestamp := range timestamps {
			int64Array[i] = int64(timestamp)
		}
		return mq.QueryMany(ctx, getManyMessagesBySignalIDQueryPostgres, sender, receiver, receiver2, pq.Array(int64Array))
	} else {
		const varargIndex = 3
		arguments := make([]any, len(timestamps)+varargIndex)
		placeholders := make([]string, len(timestamps))
		arguments[0] = sender
		arguments[1] = receiver
		arguments[2] = receiver2
		for i, timestamp := range timestamps {
			arguments[i+varargIndex] = timestamp
			placeholders[i] = fmt.Sprintf("?%d", i+varargIndex+1)
		}
		return mq.QueryMany(ctx, strings.Replace(getManyMessagesBySignalIDQuerySQLite, fmt.Sprintf("?%d", varargIndex+1), strings.Join(placeholders, ", ?"), 1), arguments...)
	}
}

func (msg *Message) Scan(row dbutil.Scannable) (*Message, error) {
	return dbutil.ValueOrErr(msg, row.Scan(
		&msg.Sender, &msg.Timestamp, &msg.PartIndex, &msg.SignalChatID, &msg.SignalReceiver, &msg.MXID, &msg.RoomID,
	))
}

func (msg *Message) sqlVariables() []any {
	return []any{msg.Sender, msg.Timestamp, msg.PartIndex, msg.SignalChatID, msg.SignalReceiver, msg.MXID, msg.RoomID}
}

func (msg *Message) Insert(ctx context.Context) error {
	return msg.qh.Exec(ctx, insertMessageQuery, msg.sqlVariables()...)
}

func (msg *Message) Delete(ctx context.Context) error {
	return msg.qh.Exec(ctx, deleteMessageQuery, msg.Sender, msg.Timestamp, msg.PartIndex, msg.SignalReceiver)
}
