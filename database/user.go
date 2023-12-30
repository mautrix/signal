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

	"github.com/google/uuid"
	"maunium.net/go/mautrix/id"

	"go.mau.fi/util/dbutil"
)

const (
	getUserByMXIDQuery       = `SELECT mxid, phone, uuid, management_room FROM "user" WHERE mxid=$1`
	getUserByPhoneQuery      = `SELECT mxid, phone, uuid, management_room FROM "user" WHERE phone=$1`
	getUserByUUIDQuery       = `SELECT mxid, phone, uuid, management_room FROM "user" WHERE uuid=$1`
	getAllLoggedInUsersQuery = `SELECT mxid, phone, uuid, management_room FROM "user" WHERE phone IS NOT NULL`
	insertUserQuery          = `INSERT INTO "user" (mxid, phone, uuid, management_room) VALUES ($1, $2, $3, $4)`
	updateUserQuery          = `UPDATE "user" SET phone=$2, uuid=$3, management_room=$4 WHERE mxid=$1`
)

type UserQuery struct {
	*dbutil.QueryHelper[*User]
}

type User struct {
	qh *dbutil.QueryHelper[*User]

	MXID           id.UserID
	SignalUsername string
	SignalID       uuid.UUID
	ManagementRoom id.RoomID
}

func newUser(qh *dbutil.QueryHelper[*User]) *User {
	return &User{qh: qh}
}

func (uq *UserQuery) GetByMXID(ctx context.Context, mxid id.UserID) (*User, error) {
	return uq.QueryOne(ctx, getUserByMXIDQuery, mxid)
}

func (uq *UserQuery) GetByPhone(ctx context.Context, phone string) (*User, error) {
	return uq.QueryOne(ctx, getUserByPhoneQuery, phone)
}

func (uq *UserQuery) GetBySignalID(ctx context.Context, uuid uuid.UUID) (*User, error) {
	return uq.QueryOne(ctx, getUserByUUIDQuery, uuid)
}

func (uq *UserQuery) GetAllLoggedIn(ctx context.Context) ([]*User, error) {
	return uq.QueryMany(ctx, getAllLoggedInUsersQuery)
}

func (u *User) sqlVariables() []any {
	var nu uuid.NullUUID
	nu.UUID = u.SignalID
	nu.Valid = u.SignalID != uuid.Nil
	return []any{u.MXID, dbutil.StrPtr(u.SignalUsername), nu, dbutil.StrPtr(u.ManagementRoom)}
}

func (u *User) Insert(ctx context.Context) error {
	return u.qh.Exec(ctx, insertUserQuery, u.sqlVariables()...)
}

func (u *User) Update(ctx context.Context) error {
	return u.qh.Exec(ctx, updateUserQuery, u.sqlVariables()...)
}

func (u *User) Scan(row dbutil.Scannable) (*User, error) {
	var phone, managementRoom sql.NullString
	var signalID uuid.NullUUID
	err := row.Scan(
		&u.MXID,
		&phone,
		&signalID,
		&u.ManagementRoom,
	)
	if err != nil {
		return nil, err
	}
	u.SignalUsername = phone.String
	u.SignalID = signalID.UUID
	u.ManagementRoom = id.RoomID(managementRoom.String)
	return u, nil
}
