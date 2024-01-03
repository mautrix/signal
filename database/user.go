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
	"sync"

	"github.com/google/uuid"
	"go.mau.fi/util/dbutil"
	"maunium.net/go/mautrix/id"
)

const (
	getUserByMXIDQuery       = `SELECT mxid, phone, uuid, management_room, space_room FROM "user" WHERE mxid=$1`
	getUserByPhoneQuery      = `SELECT mxid, phone, uuid, management_room, space_room FROM "user" WHERE phone=$1`
	getUserByUUIDQuery       = `SELECT mxid, phone, uuid, management_room, space_room FROM "user" WHERE uuid=$1`
	getAllLoggedInUsersQuery = `SELECT mxid, phone, uuid, management_room, space_room FROM "user" WHERE phone IS NOT NULL`
	insertUserQuery          = `INSERT INTO "user" (mxid, phone, uuid, management_room, space_room) VALUES ($1, $2, $3, $4, $5)`
	updateUserQuery          = `UPDATE "user" SET phone=$2, uuid=$3, management_room=$4, space_room=$5 WHERE mxid=$1`
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
	SpaceRoom      id.RoomID

	lastReadCache     map[PortalKey]uint64
	lastReadCacheLock sync.Mutex
	inSpaceCache      map[PortalKey]bool
	inSpaceCacheLock  sync.Mutex
}

func newUser(qh *dbutil.QueryHelper[*User]) *User {
	return &User{
		qh: qh,

		lastReadCache: make(map[PortalKey]uint64),
		inSpaceCache:  make(map[PortalKey]bool),
	}
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
	return []any{u.MXID, dbutil.StrPtr(u.SignalUsername), nu, dbutil.StrPtr(u.ManagementRoom), dbutil.StrPtr(u.SpaceRoom)}
}

func (u *User) Insert(ctx context.Context) error {
	return u.qh.Exec(ctx, insertUserQuery, u.sqlVariables()...)
}

func (u *User) Update(ctx context.Context) error {
	return u.qh.Exec(ctx, updateUserQuery, u.sqlVariables()...)
}

func (u *User) Scan(row dbutil.Scannable) (*User, error) {
	var phone, managementRoom, spaceRoom sql.NullString
	var signalID uuid.NullUUID
	err := row.Scan(
		&u.MXID,
		&phone,
		&signalID,
		&managementRoom,
		&spaceRoom,
	)
	if err != nil {
		return nil, err
	}
	u.SignalUsername = phone.String
	u.SignalID = signalID.UUID
	u.ManagementRoom = id.RoomID(managementRoom.String)
	u.SpaceRoom = id.RoomID(spaceRoom.String)
	return u, nil
}
