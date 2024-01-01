// mautrix-signal - A Matrix-signal puppeting bridge.
// Copyright (C) 2023 Tulir Asokan
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

	"go.mau.fi/util/dbutil"
	"maunium.net/go/mautrix/id"
)

const (
	getLostPortalsQuery   = `SELECT chat_id, receiver, mxid FROM lost_portals`
	deleteLostPortalQuery = `DELETE FROM lost_portals WHERE mxid=$1`
)

type LostPortalQuery struct {
	*dbutil.QueryHelper[*LostPortal]
}

func (lpq *LostPortalQuery) GetAll(ctx context.Context) ([]*LostPortal, error) {
	return lpq.QueryMany(ctx, getLostPortalsQuery)
}

type LostPortal struct {
	qh *dbutil.QueryHelper[*LostPortal]

	ChatID   string
	Receiver string
	MXID     id.RoomID
}

func newLostPortal(qh *dbutil.QueryHelper[*LostPortal]) *LostPortal {
	return &LostPortal{qh: qh}
}

func (l *LostPortal) Scan(row dbutil.Scannable) (*LostPortal, error) {
	err := row.Scan(&l.ChatID, &l.Receiver, &l.MXID)
	return l, err
}

func (l *LostPortal) Delete(ctx context.Context) error {
	return l.qh.Exec(ctx, deleteLostPortalQuery, l.MXID)
}
