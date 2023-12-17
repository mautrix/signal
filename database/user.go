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
