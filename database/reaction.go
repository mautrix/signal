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

package database

import (
	"database/sql"
	"errors"

	"go.mau.fi/util/dbutil"
	log "maunium.net/go/maulogger/v2"
	"maunium.net/go/mautrix/id"
)

type ReactionQuery struct {
	db  *Database
	log log.Logger
}

func (mq *ReactionQuery) New() *Reaction {
	return &Reaction{
		db:  mq.db,
		log: mq.log,
	}
}

type Reaction struct {
	db  *Database
	log log.Logger

	MXID   id.EventID
	MXRoom id.RoomID

	SignalChatID   string
	SignalReceiver string

	Author       string
	MsgAuthor    string
	MsgTimestamp uint64
	Emoji        string
}

func (r *Reaction) Insert(txn dbutil.Execable) {
	if txn == nil {
		txn = r.db
	}
	_, err := txn.Exec(`
		INSERT INTO reaction (mxid, mx_room, signal_chat_id, signal_receiver, author, msg_author, msg_timestamp, emoji)
		VALUES ($1, $2, $3, $4, $5, $6, $7, $8)
	`,
		r.MXID.String(), r.MXRoom, r.SignalChatID, r.SignalReceiver, r.Author, r.MsgAuthor, r.MsgTimestamp, r.Emoji,
	)
	r.log.Debugfln("Inserting reaction", r.MXID, r.MXRoom, r.SignalChatID, r.SignalReceiver, r.Author, r.MsgAuthor, r.MsgTimestamp, r.Emoji)
	if err != nil {
		r.log.Warnfln("Failed to insert %s, %s: %v", r.SignalChatID, r.MXID, err)
	}
}

func (r *Reaction) Delete(txn dbutil.Execable) {
	if txn == nil {
		txn = r.db
	}
	_, err := txn.Exec(`
        DELETE FROM reaction
        WHERE signal_chat_id=$1 AND signal_receiver=$2 AND author=$3 AND msg_author=$4 AND msg_timestamp=$5
	`,
		r.SignalChatID, r.SignalReceiver, r.Author, r.MsgAuthor, r.MsgTimestamp,
	)
	if err != nil {
		r.log.Warnfln("Failed to delete %s, %s: %v", r.SignalChatID, r.MXID, err)
	}
}

func (r *Reaction) Scan(row dbutil.Scannable) *Reaction {
	err := row.Scan(&r.MXID, &r.MXRoom, &r.SignalChatID, &r.SignalReceiver, &r.Author, &r.MsgAuthor, &r.MsgTimestamp, &r.Emoji)
	if err != nil {
		if !errors.Is(err, sql.ErrNoRows) {
			r.log.Errorln("Database scan failed:", err)
		}
		return nil
	}
	return r
}

func (rq *ReactionQuery) maybeScan(row *sql.Row) *Reaction {
	if row == nil {
		return nil
	}
	return rq.New().Scan(row)
}

func (rq *ReactionQuery) GetByMXID(mxid id.EventID, roomID id.RoomID) *Reaction {
	const getReactionByMXIDQuery = `
		SELECT mxid, mx_room, signal_chat_id, signal_receiver, author, msg_author, msg_timestamp, emoji FROM reaction
		WHERE mxid=$1 and mx_room=$2
	`
	return rq.maybeScan(rq.db.QueryRow(getReactionByMXIDQuery, mxid, roomID))
}

func (rq *ReactionQuery) GetBySignalID(signalChatID string, signalReceiver string, author string, msgAuthor string, msgTimestamp uint64) *Reaction {
	const getReactionBySignalIDQuery = `
		SELECT mxid, mx_room, signal_chat_id, signal_receiver, author, msg_author, msg_timestamp, emoji FROM reaction
        WHERE signal_chat_id=$1 AND signal_receiver=$2 AND author=$3 AND msg_author=$4 AND msg_timestamp=$5
	`
	return rq.maybeScan(rq.db.QueryRow(getReactionBySignalIDQuery, signalChatID, signalReceiver, author, msgAuthor, msgTimestamp))
}
