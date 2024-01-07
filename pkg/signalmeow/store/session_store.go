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

	"github.com/google/uuid"
	"go.mau.fi/util/dbutil"

	"go.mau.fi/mautrix-signal/pkg/libsignalgo"
)

var _ libsignalgo.SessionStore = (*SQLStore)(nil)
var _ SessionStoreExtras = (*SQLStore)(nil)

const (
	loadSessionQuery   = `SELECT their_device_id, record FROM signalmeow_sessions WHERE our_aci_uuid=$1 AND their_aci_uuid=$2 AND their_device_id=$3`
	storeSessionQuery  = `INSERT INTO signalmeow_sessions (our_aci_uuid, their_aci_uuid, their_device_id, record) VALUES ($1, $2, $3, $4) ON CONFLICT (our_aci_uuid, their_aci_uuid, their_device_id) DO UPDATE SET record=excluded.record`
	allSessionsQuery   = `SELECT their_device_id, record FROM signalmeow_sessions WHERE our_aci_uuid=$1 AND their_aci_uuid=$2`
	removeSessionQuery = `DELETE FROM signalmeow_sessions WHERE our_aci_uuid=$1 AND their_aci_uuid=$2 AND their_device_id=$3`
)

type SessionStoreExtras interface {
	// AllSessionsForUUID returns all sessions for the given UUID.
	AllSessionsForUUID(ctx context.Context, theirUUID uuid.UUID) ([]*libsignalgo.Address, []*libsignalgo.SessionRecord, error)
	// RemoveSession removes the session for the given address.
	RemoveSession(ctx context.Context, address *libsignalgo.Address) error
	// RemoveAllSessions removes all sessions for our ACI UUID
	RemoveAllSessions(ctx context.Context) error
}

func scanRecord(row dbutil.Scannable) (int, *libsignalgo.SessionRecord, error) {
	var record []byte
	var deviceId int
	err := row.Scan(&deviceId, &record)
	if errors.Is(err, sql.ErrNoRows) {
		return 0, nil, nil
	} else if err != nil {
		return 0, nil, err
	}
	sessionRecord, err := libsignalgo.DeserializeSessionRecord(record)
	return deviceId, sessionRecord, err
}

func (s *SQLStore) RemoveSession(ctx context.Context, address *libsignalgo.Address) error {
	theirUUID, err := address.Name()
	if err != nil {
		return fmt.Errorf("failed to get their UUID: %w", err)
	}
	deviceID, err := address.DeviceID()
	if err != nil {
		return fmt.Errorf("failed to get their device ID: %w", err)
	}
	_, err = s.db.Exec(ctx, removeSessionQuery, s.ACI, theirUUID, deviceID)
	return err
}

func (s *SQLStore) AllSessionsForUUID(ctx context.Context, theirUUID uuid.UUID) ([]*libsignalgo.Address, []*libsignalgo.SessionRecord, error) {
	rows, err := s.db.Query(ctx, allSessionsQuery, s.ACI, theirUUID)
	if err != nil {
		return nil, nil, err
	}
	defer rows.Close()
	var records []*libsignalgo.SessionRecord
	var addresses []*libsignalgo.Address
	for rows.Next() {
		deviceId, record, err := scanRecord(rows)
		if err != nil {
			return nil, nil, err
		}
		records = append(records, record)
		address, err := libsignalgo.NewUUIDAddress(theirUUID, uint(deviceId))
		if err != nil {
			return nil, nil, err
		}
		addresses = append(addresses, address)
	}
	return addresses, records, rows.Err()
}

func (s *SQLStore) LoadSession(ctx context.Context, address *libsignalgo.Address) (*libsignalgo.SessionRecord, error) {
	theirUUID, err := address.Name()
	if err != nil {
		return nil, fmt.Errorf("failed to get their UUID: %w", err)
	}
	deviceID, err := address.DeviceID()
	if err != nil {
		return nil, fmt.Errorf("failed to get their device ID: %w", err)
	}
	_, record, err := scanRecord(s.db.QueryRow(ctx, loadSessionQuery, s.ACI, theirUUID, deviceID))
	return record, err
}

func (s *SQLStore) StoreSession(ctx context.Context, address *libsignalgo.Address, record *libsignalgo.SessionRecord) error {
	theirUUID, err := address.Name()
	if err != nil {
		return fmt.Errorf("failed to get their UUID: %w", err)
	}
	deviceID, err := address.DeviceID()
	if err != nil {
		return fmt.Errorf("failed to get their device ID: %w", err)
	}
	serialized, err := record.Serialize()
	if err != nil {
		return fmt.Errorf("failed to serialize session record: %w", err)
	}
	_, err = s.db.Exec(ctx, storeSessionQuery, s.ACI, theirUUID, deviceID, serialized)
	return err
}

func (s *SQLStore) RemoveAllSessions(ctx context.Context) error {
	_, err := s.db.Exec(ctx, "DELETE FROM signalmeow_sessions WHERE our_aci_uuid=$1", s.ACI)
	return err
}
