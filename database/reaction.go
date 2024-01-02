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

	"github.com/google/uuid"
	"go.mau.fi/util/dbutil"
	"maunium.net/go/mautrix/id"
)

const (
	getReactionByMXIDQuery     = `SELECT msg_author, msg_timestamp, author, emoji, signal_chat_id, signal_receiver, mxid, mx_room FROM reaction WHERE mxid=$1`
	getReactionBySignalIDQuery = `SELECT msg_author, msg_timestamp, author, emoji, signal_chat_id, signal_receiver, mxid, mx_room FROM reaction WHERE msg_author=$1 AND msg_timestamp=$2 AND author=$3 AND signal_receiver=$4`
	insertReactionQuery        = `
		INSERT INTO reaction (msg_author, msg_timestamp, author, emoji, signal_chat_id, signal_receiver, mxid, mx_room)
		VALUES ($1, $2, $3, $4, $5, $6, $7, $8)
	`
	updateReactionQuery = `
		UPDATE reaction
		SET mxid=$1, emoji=$2
		WHERE msg_author=$3 AND msg_timestamp=$4 AND author=$5 AND signal_receiver=$6
	`
	deleteReactionQuery = `
		DELETE FROM reaction WHERE msg_author=$1 AND msg_timestamp=$2 AND author=$3 AND signal_receiver=$4
	`
)

type ReactionQuery struct {
	*dbutil.QueryHelper[*Reaction]
}

func newReaction(qh *dbutil.QueryHelper[*Reaction]) *Reaction {
	return &Reaction{qh: qh}
}

type Reaction struct {
	qh *dbutil.QueryHelper[*Reaction]

	MsgAuthor    uuid.UUID
	MsgTimestamp uint64
	Author       uuid.UUID
	Emoji        string

	SignalChatID   string
	SignalReceiver uuid.UUID

	MXID   id.EventID
	RoomID id.RoomID
}

func (rq *ReactionQuery) GetByMXID(ctx context.Context, mxid id.EventID) (*Reaction, error) {
	return rq.QueryOne(ctx, getReactionByMXIDQuery, mxid)
}

func (rq *ReactionQuery) GetBySignalID(ctx context.Context, msgAuthor uuid.UUID, msgTimestamp uint64, author, signalReceiver uuid.UUID) (*Reaction, error) {
	return rq.QueryOne(ctx, getReactionBySignalIDQuery, msgAuthor, msgTimestamp, author, signalReceiver)
}

func (r *Reaction) Scan(row dbutil.Scannable) (*Reaction, error) {
	return dbutil.ValueOrErr(r, row.Scan(
		&r.MsgAuthor, &r.MsgTimestamp, &r.Author, &r.Emoji, &r.SignalChatID, &r.SignalReceiver, &r.MXID, &r.RoomID,
	))
}

func (r *Reaction) sqlVariables() []any {
	return []any{
		r.MsgAuthor, r.MsgTimestamp, r.Author, r.Emoji, r.SignalChatID, r.SignalReceiver, r.MXID, r.RoomID,
	}
}

func (r *Reaction) Insert(ctx context.Context) error {
	return r.qh.Exec(ctx, insertReactionQuery, r.sqlVariables()...)
}

func (r *Reaction) Update(ctx context.Context) error {
	return r.qh.Exec(ctx, updateReactionQuery, r.MXID, r.Emoji, r.MsgAuthor, r.MsgTimestamp, r.Author, r.SignalReceiver)
}

func (r *Reaction) Delete(ctx context.Context) error {
	return r.qh.Exec(ctx, deleteReactionQuery, r.MsgAuthor, r.MsgTimestamp, r.Author, r.SignalReceiver)
}
