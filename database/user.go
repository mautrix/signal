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

func (u *User) Insert() error {
	q := `INSERT INTO "user" (mxid, username, uuid, management_room) VALUES ($1, $2, $3, $4)`
	_, err := u.db.Exec(q, u.MXID, u.SignalUsername, u.SignalID, u.ManagementRoom)
	return err
}

func (u *User) Update() error {
	q := `UPDATE "user" SET username=$1, uuid=$2, management_room=$3 WHERE mxid=$4`
	_, err := u.db.Exec(q, u.SignalUsername, u.SignalID, u.ManagementRoom, u.MXID)
	return err
}

func (u *User) Scan(row dbutil.Scannable) *User {
	var username, managementRoom sql.NullString
	err := row.Scan(
		&u.MXID,
		&username,
		&u.SignalID,
		&managementRoom,
	)
	if err != nil {
		if err != sql.ErrNoRows {
			u.log.Errorln("Database scan failed:", err)
		}
		return nil
	}
	u.SignalUsername = username.String
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

func (uq *UserQuery) AllLoggedIn() ([]*User, error) {
	q := `SELECT mxid, username, uuid, management_room FROM "user" WHERE username IS NOT NULL`
	rows, err := uq.db.Query(q)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var users []*User
	for rows.Next() {
		u := uq.New()
		err := rows.Scan(&u.MXID, &u.SignalUsername, &u.SignalID, &u.ManagementRoom)
		if err != nil {
			return nil, err
		}
		users = append(users, u)
	}
	return users, nil
}
