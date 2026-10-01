// mautrix-signal - A Matrix-signal puppeting bridge.
// Copyright (C) 2026 Killian Lelong
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

package store

import (
	"context"
	"time"

	"github.com/google/uuid"
	"go.mau.fi/util/dbutil"
)

type ViewOnceOpen struct {
	Sender    uuid.UUID
	Timestamp uint64
}

type ViewOnceStore interface {
	MarkViewOnceOpened(context.Context, uuid.UUID, uint64, bool) (syncPending bool, err error)
	MarkViewOnceSynced(context.Context, uuid.UUID, uint64) error
	IsViewOnceOpened(context.Context, uuid.UUID, uint64) (bool, error)
	MarkViewOnceHandled(context.Context, uuid.UUID, uint64) error
	GetPendingViewOnceOpens(context.Context) ([]*ViewOnceOpen, error)
}

var _ ViewOnceStore = (*sqlStore)(nil)

func (s *sqlStore) MarkViewOnceOpened(ctx context.Context, sender uuid.UUID, timestamp uint64, needsSync bool) (syncPending bool, err error) {
	err = s.db.QueryRow(ctx, `INSERT INTO signalmeow_view_once_open (account_id, sender, timestamp, sync_pending)
		VALUES ($1, $2, $3, $4) ON CONFLICT (account_id, sender, timestamp) DO UPDATE
		SET sync_pending=signalmeow_view_once_open.sync_pending AND excluded.sync_pending
		RETURNING sync_pending`, s.AccountID, sender, timestamp, needsSync).Scan(&syncPending)
	if err != nil {
		return false, err
	}
	cutoff := time.Now().Add(-45 * 24 * time.Hour).UnixMilli()
	_, err = s.db.Exec(ctx, `DELETE FROM signalmeow_view_once_open WHERE account_id=$1 AND timestamp<$2`,
		s.AccountID, cutoff)
	return syncPending && int64(timestamp) >= cutoff, err
}

func (s *sqlStore) IsViewOnceOpened(ctx context.Context, sender uuid.UUID, timestamp uint64) (bool, error) {
	var opened bool
	err := s.db.QueryRow(ctx, `SELECT EXISTS (SELECT 1 FROM signalmeow_view_once_open
		WHERE account_id=$1 AND sender=$2 AND timestamp=$3)`, s.AccountID, sender, timestamp).Scan(&opened)
	return opened, err
}

func (s *sqlStore) MarkViewOnceHandled(ctx context.Context, sender uuid.UUID, timestamp uint64) error {
	_, err := s.db.Exec(ctx, `UPDATE signalmeow_view_once_open SET handled=true WHERE account_id=$1 AND sender=$2 AND timestamp=$3`, s.AccountID, sender, timestamp)
	return err
}

func (s *sqlStore) GetPendingViewOnceOpens(ctx context.Context) ([]*ViewOnceOpen, error) {
	rows, err := s.db.Query(ctx, `SELECT sender, timestamp FROM signalmeow_view_once_open
		WHERE account_id=$1 AND handled=false AND timestamp >= $2`, s.AccountID, time.Now().Add(-45*24*time.Hour).UnixMilli())
	return dbutil.NewRowIterWithError(rows, func(row dbutil.Scannable) (*ViewOnceOpen, error) {
		var opened ViewOnceOpen
		err := row.Scan(&opened.Sender, &opened.Timestamp)
		return &opened, err
	}, err).AsList()
}

func (s *sqlStore) MarkViewOnceSynced(ctx context.Context, sender uuid.UUID, timestamp uint64) error {
	_, err := s.db.Exec(ctx, `UPDATE signalmeow_view_once_open SET sync_pending=false WHERE account_id=$1 AND sender=$2 AND timestamp=$3`, s.AccountID, sender, timestamp)
	return err
}
