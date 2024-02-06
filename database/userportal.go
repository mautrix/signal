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
	"errors"

	"github.com/rs/zerolog"
)

const (
	getLastReadTSQuery = `SELECT last_read_ts FROM user_portal WHERE user_mxid=$1 AND portal_chat_id=$2 AND portal_receiver=$3`
	setLastReadTSQuery = `
		INSERT INTO user_portal (user_mxid, portal_chat_id, portal_receiver, last_read_ts) VALUES ($1, $2, $3, $4)
		ON CONFLICT (user_mxid, portal_chat_id, portal_receiver) DO UPDATE
			SET last_read_ts=excluded.last_read_ts WHERE user_portal.last_read_ts<excluded.last_read_ts
	`
	getIsInSpaceQuery = `SELECT in_space FROM user_portal WHERE user_mxid=$1 AND portal_chat_id=$2 AND portal_receiver=$3`
	setIsInSpaceQuery = `
		INSERT INTO user_portal (user_mxid, portal_chat_id, portal_receiver, in_space) VALUES ($1, $2, $3, true)
		ON CONFLICT (user_mxid, portal_chat_id, portal_receiver) DO UPDATE SET in_space=true
	`
)

func (u *User) GetLastReadTS(ctx context.Context, portal PortalKey) uint64 {
	u.lastReadCacheLock.Lock()
	defer u.lastReadCacheLock.Unlock()
	if cached, ok := u.lastReadCache[portal]; ok {
		return cached
	}
	var ts int64
	err := u.qh.GetDB().QueryRow(ctx, getLastReadTSQuery, u.MXID, portal.ChatID, portal.Receiver).Scan(&ts)
	if err != nil && !errors.Is(err, sql.ErrNoRows) {
		zerolog.Ctx(ctx).Err(err).
			Stringer("user_id", u.MXID).
			Any("portal_key", portal).
			Msg("Failed to query last read timestamp")
		return 0
	}
	u.lastReadCache[portal] = uint64(ts)
	return uint64(ts)
}

func (u *User) SetLastReadTS(ctx context.Context, portal PortalKey, ts uint64) {
	u.lastReadCacheLock.Lock()
	defer u.lastReadCacheLock.Unlock()
	err := u.qh.Exec(ctx, setLastReadTSQuery, u.MXID, portal.ChatID, portal.Receiver, int64(ts))
	if err != nil {
		zerolog.Ctx(ctx).Err(err).
			Stringer("user_id", u.MXID).
			Any("portal_key", portal).
			Msg("Failed to update last read timestamp")
	} else {
		zerolog.Ctx(ctx).Debug().
			Stringer("user_id", u.MXID).
			Any("portal_key", portal).
			Uint64("last_read_ts", ts).
			Msg("Updated last read timestamp of portal")
		u.lastReadCache[portal] = ts
	}
}

func (u *User) IsInSpace(ctx context.Context, portal PortalKey) bool {
	u.inSpaceCacheLock.Lock()
	defer u.inSpaceCacheLock.Unlock()
	if cached, ok := u.inSpaceCache[portal]; ok {
		return cached
	}
	var inSpace bool
	err := u.qh.GetDB().QueryRow(ctx, getIsInSpaceQuery, u.MXID, portal.ChatID, portal.Receiver).Scan(&inSpace)
	if err != nil && !errors.Is(err, sql.ErrNoRows) {
		zerolog.Ctx(ctx).Err(err).
			Stringer("user_id", u.MXID).
			Any("portal_key", portal).
			Msg("Failed to query in space status")
		return false
	}
	u.inSpaceCache[portal] = inSpace
	return inSpace
}

func (u *User) MarkInSpace(ctx context.Context, portal PortalKey) {
	u.inSpaceCacheLock.Lock()
	defer u.inSpaceCacheLock.Unlock()
	err := u.qh.Exec(ctx, setIsInSpaceQuery, u.MXID, portal.ChatID, portal.Receiver)
	if err != nil {
		zerolog.Ctx(ctx).Err(err).
			Stringer("user_id", u.MXID).
			Any("portal_key", portal).
			Msg("Failed to update in space status")
	} else {
		u.inSpaceCache[portal] = true
	}
}

func (u *User) RemoveInSpaceCache(key PortalKey) {
	u.inSpaceCacheLock.Lock()
	defer u.inSpaceCacheLock.Unlock()
	delete(u.inSpaceCache, key)
}
