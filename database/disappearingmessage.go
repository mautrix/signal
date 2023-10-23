package database

import (
	"database/sql"
	"errors"
	"time"

	"go.mau.fi/util/dbutil"
	log "maunium.net/go/maulogger/v2"

	"maunium.net/go/mautrix/id"
)

type DisappearingMessageQuery struct {
	db  *Database
	log log.Logger
}

func (dmq *DisappearingMessageQuery) New() *DisappearingMessage {
	return &DisappearingMessage{
		db:  dmq.db,
		log: dmq.log,
	}
}

func (dmq *DisappearingMessageQuery) NewWithValues(roomID id.RoomID, eventID id.EventID, expireInSeconds int64, expireAt time.Time) *DisappearingMessage {
	dm := &DisappearingMessage{
		db:              dmq.db,
		log:             dmq.log,
		RoomID:          roomID,
		EventID:         eventID,
		ExpireInSeconds: expireInSeconds,
		ExpireAt:        expireAt,
	}
	return dm
}

func (dmq *DisappearingMessageQuery) GetUnscheduledForRoom(roomID id.RoomID) (messages []*DisappearingMessage) {
	const getUnscheduledQuery = `
		SELECT room_id, mxid, expiration_seconds, expiration_ts FROM disappearing_message WHERE expiration_ts IS NULL AND room_id = $1
	`
	rows, err := dmq.db.Query(getUnscheduledQuery, roomID)
	if err != nil || rows == nil {
		dmq.log.Warnln("Failed to get unscheduled disappearing messages:", err)
		return nil
	}
	for rows.Next() {
		messages = append(messages, dmq.New().Scan(rows))
	}
	return
}

func (dmq *DisappearingMessageQuery) GetExpiredMessages() (messages []*DisappearingMessage) {
	const getExpiredQuery = `
		SELECT room_id, mxid, expiration_seconds, expiration_ts FROM disappearing_message WHERE expiration_ts IS NOT NULL AND expiration_ts <= $1
	`
	const wiggleRoom = 1
	rows, err := dmq.db.Query(getExpiredQuery, time.Now().Unix()+wiggleRoom)
	if err != nil || rows == nil {
		dmq.log.Warnln("Failed to get expired disappearing messages:", err)
		return nil
	}
	for rows.Next() {
		messages = append(messages, dmq.New().Scan(rows))
	}
	return
}

func (dmq *DisappearingMessageQuery) GetNextScheduledMessage() (message *DisappearingMessage) {
	const getNextScheduledQuery = `
		SELECT room_id, mxid, expiration_seconds, expiration_ts FROM disappearing_message WHERE expiration_ts IS NOT NULL ORDER BY expiration_ts ASC LIMIT 1
	`
	row := dmq.db.QueryRow(getNextScheduledQuery)
	if row == nil {
		return nil
	}
	return dmq.New().Scan(row)
}

type DisappearingMessage struct {
	db  *Database
	log log.Logger

	RoomID          id.RoomID
	EventID         id.EventID
	ExpireInSeconds int64
	ExpireAt        time.Time
}

func (msg *DisappearingMessage) Scan(row dbutil.Scannable) *DisappearingMessage {
	var expireIn int64
	var expireAt sql.NullInt64
	err := row.Scan(&msg.RoomID, &msg.EventID, &expireIn, &expireAt)
	if err != nil {
		if !errors.Is(err, sql.ErrNoRows) {
			msg.log.Errorln("Database scan failed:", err)
		}
		return nil
	}
	msg.ExpireInSeconds = expireIn
	if expireAt.Valid {
		msg.ExpireAt = time.Unix(expireAt.Int64, 0)
	}
	return msg
}

func (msg *DisappearingMessage) Insert(txn dbutil.Execable) {
	if txn == nil {
		txn = msg.db
	}
	var expireAt sql.NullInt64
	if !msg.ExpireAt.IsZero() {
		expireAt.Valid = true
		expireAt.Int64 = msg.ExpireAt.Unix()
	}
	_, err := txn.Exec(`INSERT INTO disappearing_message (room_id, mxid, expiration_seconds, expiration_ts) VALUES ($1, $2, $3, $4)`,
		msg.RoomID, msg.EventID, msg.ExpireInSeconds, expireAt)
	if err != nil {
		msg.log.Warnfln("Failed to insert %s/%s: %v", msg.RoomID, msg.EventID, err)
	}
}

func (msg *DisappearingMessage) StartExpirationTimer() {
	msg.ExpireAt = time.Now().Add(time.Duration(msg.ExpireInSeconds) * time.Second)
	_, err := msg.db.Exec("UPDATE disappearing_message SET expiration_ts=$1 WHERE room_id=$2 AND mxid=$3", msg.ExpireAt.Unix(), msg.RoomID, msg.EventID)
	if err != nil {
		msg.log.Warnfln("Failed to update %s/%s: %v", msg.RoomID, msg.EventID, err)
	}
}

func (msg *DisappearingMessage) Delete() {
	_, err := msg.db.Exec("DELETE FROM disappearing_message WHERE room_id=$1 AND mxid=$2", msg.RoomID, msg.EventID)
	if err != nil {
		msg.log.Warnfln("Failed to delete %s/%s: %v", msg.RoomID, msg.EventID, err)
	}
}
