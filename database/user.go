package database

import (
	"database/sql"

	log "maunium.net/go/maulogger/v2"

	"maunium.net/go/mautrix/id"
	"maunium.net/go/mautrix/util/dbutil"
)

type UserQuery struct {
	db  *Database
	log log.Logger
}

func (uq *UserQuery) New() *User {
	return &User{
		db:  uq.db,
		log: uq.log,
	}
}

type User struct {
	db  *Database
	log log.Logger

	MXID           id.UserID
	SignalUsername string
	SignalID       string
	ManagementRoom id.RoomID
	NoticeRoom     id.RoomID
}

func (u *User) Insert() error {
	q := `INSERT INTO "user" (mxid, username, uuid, management_room, notice_room) VALUES ($1, $2, $3, $4, $5)`
	_, err := u.db.Exec(q, u.MXID, u.SignalUsername, u.SignalID, u.ManagementRoom, u.NoticeRoom)
	return err
}

func (u *User) Update() error {
	q := `UPDATE "user" SET username=$1, uuid=$2, management_room=$3, notice_room=$4 WHERE mxid=$5`
	_, err := u.db.Exec(q, u.SignalUsername, u.SignalID, u.ManagementRoom, u.NoticeRoom, u.MXID)
	return err
}

func (u *User) Scan(row dbutil.Scannable) *User {
	err := row.Scan(&u.MXID, &u.SignalUsername, &u.SignalID, &u.ManagementRoom, &u.NoticeRoom)
	if err != nil {
		if err != sql.ErrNoRows {
			u.log.Errorln("Database scan failed:", err)
		}
		return nil
	}
	return u
}

func (uq *UserQuery) GetByMXID(mxid id.UserID) *User {
	q := `SELECT mxid, username, uuid, management_room, notice_room FROM "user" WHERE mxid=$1`
	row := uq.db.QueryRow(q, mxid)
	if row == nil {
		return nil
	}
	return uq.New().Scan(row)
}

func (uq *UserQuery) GetByUsername(username string) *User {
	q := `SELECT mxid, username, uuid, management_room, notice_room FROM "user" WHERE username=$1`
	row := uq.db.QueryRow(q, username)
	if row == nil {
		return nil
	}
	return uq.New().Scan(row)
}

func (uq *UserQuery) GetBySignalID(uuid string) *User {
	q := `SELECT mxid, username, uuid, management_room, notice_room FROM "user" WHERE uuid=$1`
	row := uq.db.QueryRow(q, uuid)
	if row == nil {
		return nil
	}
	return uq.New().Scan(row)
}

func (uq *UserQuery) AllLoggedIn() ([]*User, error) {
	q := `SELECT mxid, username, uuid, management_room, notice_room FROM "user" WHERE username IS NOT NULL`
	rows, err := uq.db.Query(q)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var users []*User
	for rows.Next() {
		u := uq.New()
		err := rows.Scan(&u.MXID, &u.SignalUsername, &u.SignalID, &u.ManagementRoom, &u.NoticeRoom)
		if err != nil {
			return nil, err
		}
		users = append(users, u)
	}
	return users, nil
}
