package database

import (
	"database/sql"
	"errors"

	log "maunium.net/go/maulogger/v2"
	"maunium.net/go/mautrix/id"
	"maunium.net/go/mautrix/util/dbutil"
)

type MessageQuery struct {
	db  *Database
	log log.Logger
}

func (mq *MessageQuery) New() *Message {
	return &Message{
		db:  mq.db,
		log: mq.log,
	}
}

type Message struct {
	db  *Database
	log log.Logger

	MXID           id.EventID
	MXRoom         id.RoomID
	Sender         string
	Timestamp      uint64
	SignalChatID   string
	SignalReceiver string
}

const (
	getAllMessagesQuery = `
		SELECT mxid, mx_room, sender, timestamp, signal_chat_id, signal_receiver FROM message
		WHERE signal_chat_id=$1 AND signal_receiver=$2
	`
	getMessageByMXIDQuery = `
		SELECT mxid, mx_room, sender, timestamp, signal_chat_id, signal_receiver FROM message
		WHERE mxid=$1
	`
	getMessagesBySignalIDQuery = `
        SELECT mxid, mx_room, sender, timestamp, signal_chat_id, signal_receiver FROM message
        WHERE sender=$1 AND timestamp=$2 AND signal_chat_id=$3 AND signal_receiver=$4
	`
	findBySenderAndTimestampQuery = `
		SELECT mxid, mx_room, sender, timestamp, signal_chat_id, signal_receiver FROM message
		WHERE sender=$1 AND timestamp=$2
	`
	getFirstBeforeQuery = `
		SELECT mxid, mx_room, sender, timestamp, signal_chat_id, signal_receiver FROM message
		WHERE mx_room=$1 AND timestamp <= $2
		ORDER BY timestamp DESC
		LIMIT 1
	`
)

func (msg *Message) Insert(txn dbutil.Execable) {
	if txn == nil {
		txn = msg.db
	}
	_, err := txn.Exec(`
		INSERT INTO message (mxid, mx_room, sender, timestamp, signal_chat_id, signal_receiver)
		VALUES ($1, $2, $3, $4, $5, $6)
	`,
		msg.MXID.String(), msg.MXRoom, msg.Sender, msg.Timestamp, msg.SignalChatID, msg.SignalReceiver)
	msg.log.Debugfln("Inserting message", msg.MXID, msg.MXRoom, msg.Sender, msg.Timestamp, msg.SignalChatID, msg.SignalReceiver)
	if err != nil {
		msg.log.Warnfln("Failed to insert %s, %s: %v", msg.SignalChatID, msg.MXID, err)
	}
}

func (msg *Message) Delete(txn dbutil.Execable) {
	if txn == nil {
		txn = msg.db
	}
	_, err := txn.Exec(`
        DELETE FROM message
        WHERE sender=$1 AND timestamp=$2 AND signal_chat_id=$3 AND signal_receiver=$4
	`,
		msg.Sender, msg.Timestamp, msg.SignalChatID, msg.SignalReceiver)
	if err != nil {
		msg.log.Warnfln("Failed to delete %s, %s: %v", msg.SignalChatID, msg.MXID, err)
	}
}

func (msg *Message) Scan(row dbutil.Scannable) *Message {
	var timestamp sql.NullInt64
	var signalChatID, signalReceiver sql.NullString
	err := row.Scan(
		&msg.MXID,
		&msg.MXRoom,
		&msg.Sender,
		&timestamp,
		&signalChatID,
		&signalReceiver,
	)
	if err != nil {
		if !errors.Is(err, sql.ErrNoRows) {
			msg.log.Errorln("Database scan failed:", err)
		}
		return nil
	}
	msg.Timestamp = uint64(timestamp.Int64)
	msg.SignalChatID = signalChatID.String
	msg.SignalReceiver = signalReceiver.String
	return msg
}

func (mq *MessageQuery) maybeScan(row *sql.Row) *Message {
	if row == nil {
		return nil
	}
	return mq.New().Scan(row)
}

func (mq *MessageQuery) DeleteAll(roomID string) {
	_, err := mq.db.Exec(`
		DELETE FROM message WHERE mx_room=$1
	`, roomID)
	if err != nil {
		mq.log.Warnfln("Failed to delete messages in %s: %v", roomID, err)
	}
}

func (mq *MessageQuery) GetAll(chatID string, receiver string) (messages []*Message) {
	rows, err := mq.db.Query(getAllMessagesQuery, chatID, receiver)
	if err != nil || rows == nil {
		return nil
	}
	for rows.Next() {
		messages = append(messages, mq.New().Scan(rows))
	}
	return
}

func (mq *MessageQuery) GetByMXID(mxid id.EventID) *Message {
	return mq.maybeScan(mq.db.QueryRow(getMessageByMXIDQuery, mxid))
}

func (mq *MessageQuery) GetBySignalID(sender string, timestamp uint64, chatID string, receiver string) *Message {
	return mq.maybeScan(mq.db.QueryRow(getMessagesBySignalIDQuery, sender, timestamp, chatID, receiver))
}

func (mq *MessageQuery) FindByTimestamps(timestamps []uint64) []*Message {
	var messages []*Message
	var rows dbutil.Rows
	var err error

	if mq.db.Dialect == dbutil.Postgres {
		rows, err = mq.db.Query(`
			SELECT mxid, mx_room, sender, timestamp, signal_chat_id, signal_receiver FROM message
			WHERE timestamp=ANY($1)
			`, timestamps)
	} else {
		placeholders := ""
		for i := 0; i < len(timestamps); i++ {
			placeholders += "?"
		}
		rows, err = mq.db.Query(`
			SELECT mxid, mx_room, sender, timestamp, signal_chat_id, signal_receiver FROM message
			WHERE timestamp IN ($1)
			`, timestamps)
	}
	if err != nil {
		mq.log.Errorln("FindByTimestamps failed:", err)
	}
	for rows.Next() {
		messages = append(messages, mq.New().Scan(rows))
	}
	return messages
}

func (mq *MessageQuery) FindBySenderAndTimestamp(sender string, timestamp uint64) *Message {
	return mq.New().Scan(mq.db.QueryRow(findBySenderAndTimestampQuery, sender, timestamp))
}

func (mq *MessageQuery) GetFirstBefore(room string, timestamp uint64) *Message {
	return mq.maybeScan(mq.db.QueryRow(getFirstBeforeQuery, room, timestamp))
}
