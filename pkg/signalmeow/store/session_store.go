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

package store

import (
	"context"
	"database/sql"
	"errors"
	"fmt"

	"go.mau.fi/util/dbutil"

	"go.mau.fi/mautrix-signal/pkg/libsignalgo"
)

var _ SessionStore = (*scopedSQLStore)(nil)

const (
	loadSessionQuery  = `SELECT their_device_id, record FROM signalmeow_sessions WHERE account_id=$1 AND service_id=$2 AND their_service_id=$3 AND their_device_id=$4`
	storeSessionQuery = `
		INSERT INTO signalmeow_sessions (account_id, service_id, their_service_id, their_device_id, record)
		VALUES ($1, $2, $3, $4, $5)
		ON CONFLICT (account_id, service_id, their_service_id, their_device_id) DO UPDATE SET record=excluded.record
	`
	allSessionsQuery       = `SELECT their_device_id, record FROM signalmeow_sessions WHERE account_id=$1 AND service_id=$2 AND their_service_id=$3`
	removeSessionQuery     = `DELETE FROM signalmeow_sessions WHERE account_id=$1 AND service_id=$2 AND their_service_id=$3 AND their_device_id=$4`
	deleteAllSessionsQuery = "DELETE FROM signalmeow_sessions WHERE account_id=$1"
)

type SessionStore interface {
	libsignalgo.SessionStore
	ServiceScopedStore

	// AllSessionsForServiceID returns all sessions for the given service ID.
	AllSessionsForServiceID(ctx context.Context, theirID libsignalgo.ServiceID) ([]*libsignalgo.Address, []*libsignalgo.SessionRecord, error)
	// RemoveSession removes the session for the given address.
	RemoveSession(ctx context.Context, address *libsignalgo.Address) error
	// RemoveAllSessions removes all sessions for our ACI UUID
	RemoveAllSessions(ctx context.Context) error
}

func scanSessionRecord(row dbutil.Scannable) (int, *libsignalgo.SessionRecord, error) {
	var record []byte
	var deviceID int
	err := row.Scan(&deviceID, &record)
	if errors.Is(err, sql.ErrNoRows) {
		return 0, nil, nil
	} else if err != nil {
		return 0, nil, err
	}
	sessionRecord, err := libsignalgo.DeserializeSessionRecord(record)
	return deviceID, sessionRecord, err
}

func (s *scopedSQLStore) RemoveSession(ctx context.Context, address *libsignalgo.Address) error {
	theirServiceID, err := address.Name()
	if err != nil {
		return fmt.Errorf("failed to get their service ID: %w", err)
	}
	deviceID, err := address.DeviceID()
	if err != nil {
		return fmt.Errorf("failed to get their device ID: %w", err)
	}
	_, err = s.db.Exec(ctx, removeSessionQuery, s.AccountID, s.ServiceID, theirServiceID, deviceID)
	return err
}

func (s *scopedSQLStore) AllSessionsForServiceID(ctx context.Context, theirID libsignalgo.ServiceID) ([]*libsignalgo.Address, []*libsignalgo.SessionRecord, error) {
	rows, err := s.db.Query(ctx, allSessionsQuery, s.AccountID, s.ServiceID, theirID)
	if err != nil {
		return nil, nil, err
	}
	defer rows.Close()
	var records []*libsignalgo.SessionRecord
	var addresses []*libsignalgo.Address
	for rows.Next() {
		deviceID, record, err := scanSessionRecord(rows)
		if err != nil {
			return nil, nil, err
		}
		records = append(records, record)
		address, err := theirID.Address(uint(deviceID))
		if err != nil {
			return nil, nil, err
		}
		addresses = append(addresses, address)
	}
	return addresses, records, rows.Err()
}

func (s *scopedSQLStore) LoadSession(ctx context.Context, address *libsignalgo.Address) (*libsignalgo.SessionRecord, error) {
	theirServiceID, err := address.Name()
	if err != nil {
		return nil, fmt.Errorf("failed to get their service ID: %w", err)
	}
	deviceID, err := address.DeviceID()
	if err != nil {
		return nil, fmt.Errorf("failed to get their device ID: %w", err)
	}
	_, record, err := scanSessionRecord(s.db.QueryRow(ctx, loadSessionQuery, s.AccountID, s.ServiceID, theirServiceID, deviceID))
	return record, err
}

func (s *scopedSQLStore) StoreSession(ctx context.Context, address *libsignalgo.Address, record *libsignalgo.SessionRecord) error {
	theirServiceID, err := address.Name()
	if err != nil {
		return fmt.Errorf("failed to get their service ID: %w", err)
	}
	deviceID, err := address.DeviceID()
	if err != nil {
		return fmt.Errorf("failed to get their device ID: %w", err)
	}
	serialized, err := record.Serialize()
	if err != nil {
		return fmt.Errorf("failed to serialize session record: %w", err)
	}
	_, err = s.db.Exec(ctx, storeSessionQuery, s.AccountID, s.ServiceID, theirServiceID, deviceID, serialized)
	return err
}

func (s *scopedSQLStore) RemoveAllSessions(ctx context.Context) error {
	_, err := s.db.Exec(ctx, deleteAllSessionsQuery, s.AccountID)
	return err
}
