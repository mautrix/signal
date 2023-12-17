package database

import (
	"database/sql"

	"go.mau.fi/util/dbutil"
	log "maunium.net/go/maulogger/v2"
	"maunium.net/go/mautrix/id"
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
}

func (u *User) sqlVariables() []any {
	var username, signalID, managementRoom *string
	if u.SignalUsername != "" {
		username = &u.SignalUsername
	}
	if u.SignalID != "" {
		signalID = &u.SignalID
	}
	if u.ManagementRoom != "" {
		managementRoom = (*string)(&u.ManagementRoom)
	}
	return []any{u.MXID, username, signalID, managementRoom}
}

func (u *User) Insert() error {
	q := `INSERT INTO "user" (mxid, username, uuid, management_room) VALUES ($1, $2, $3, $4)`
	_, err := u.db.Exec(q, u.sqlVariables()...)
	return err
}

func (u *User) Update() error {
	q := `UPDATE "user" SET username=$2, uuid=$3, management_room=$4 WHERE mxid=$1`
	_, err := u.db.Exec(q, u.sqlVariables()...)
	return err
}

func (u *User) Scan(row dbutil.Scannable) *User {
	var username, managementRoom, signalID sql.NullString
	err := row.Scan(
		&u.MXID,
		&username,
		&signalID,
		&managementRoom,
	)
	if err != nil {
		if err != sql.ErrNoRows {
			u.log.Errorln("Database scan failed:", err)
		}
		return nil
	}
	u.SignalUsername = username.String
	u.SignalID = signalID.String
	u.ManagementRoom = id.RoomID(managementRoom.String)
	return u
}

func (uq *UserQuery) GetByMXID(mxid id.UserID) *User {
	q := `SELECT mxid, username, uuid, management_room FROM "user" WHERE mxid=$1`
	row := uq.db.QueryRow(q, mxid)
	if row == nil {
		return nil
	}
	return uq.New().Scan(row)
}

func (uq *UserQuery) GetByUsername(username string) *User {
	q := `SELECT mxid, username, uuid, management_room FROM "user" WHERE username=$1`
	row := uq.db.QueryRow(q, username)
	if row == nil {
		return nil
	}
	return uq.New().Scan(row)
}

func (uq *UserQuery) GetBySignalID(uuid string) *User {
	q := `SELECT mxid, username, uuid, management_room FROM "user" WHERE uuid=$1`
	row := uq.db.QueryRow(q, uuid)
	if row == nil {
		return nil
	}
	return uq.New().Scan(row)
}

func (uq *UserQuery) AllLoggedIn() []*User {
	q := `SELECT mxid, username, uuid, management_room FROM "user" WHERE username IS NOT NULL`
	rows, err := uq.db.Query(q)
	if err != nil {
		uq.log.Errorln("Database query failed:", err)
		return nil
	}
	defer rows.Close()

	var users []*User
	for rows.Next() {
		u := uq.New().Scan(rows)
		if u == nil {
			continue
		}
		users = append(users, u)
	}
	return users
}
