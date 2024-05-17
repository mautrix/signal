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

var _ libsignalgo.SenderKeyStore = (*sqlStore)(nil)

const (
	loadSenderKeyQuery  = `SELECT key_record FROM signalmeow_sender_keys WHERE account_id=$1 AND sender_uuid=$2 AND sender_device_id=$3 AND distribution_id=$4`
	storeSenderKeyQuery = `INSERT INTO signalmeow_sender_keys (account_id, sender_uuid, sender_device_id, distribution_id, key_record) VALUES ($1, $2, $3, $4, $5) ON CONFLICT (account_id, sender_uuid, sender_device_id, distribution_id) DO UPDATE SET key_record=excluded.key_record`
)

func scanSenderKey(row dbutil.Scannable) (*libsignalgo.SenderKeyRecord, error) {
	var key []byte
	err := row.Scan(&key)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, nil
	} else if err != nil {
		return nil, err
	}
	return libsignalgo.DeserializeSenderKeyRecord(key)
}

func (s *sqlStore) LoadSenderKey(ctx context.Context, sender *libsignalgo.Address, distributionID uuid.UUID) (*libsignalgo.SenderKeyRecord, error) {
	senderUUID, err := sender.Name()
	if err != nil {
		return nil, fmt.Errorf("failed to get sender UUID: %w", err)
	}
	deviceID, err := sender.DeviceID()
	if err != nil {
		return nil, fmt.Errorf("failed to get sender device ID: %w", err)
	}
	return scanSenderKey(s.db.QueryRow(ctx, loadSenderKeyQuery, s.AccountID, senderUUID, deviceID, distributionID))
}

func (s *sqlStore) StoreSenderKey(ctx context.Context, sender *libsignalgo.Address, distributionID uuid.UUID, record *libsignalgo.SenderKeyRecord) error {
	senderUUID, err := sender.Name()
	if err != nil {
		return fmt.Errorf("failed to get sender UUID: %w", err)
	}
	deviceID, err := sender.DeviceID()
	if err != nil {
		return fmt.Errorf("failed to get sender device ID: %w", err)
	}
	serialized, err := record.Serialize()
	if err != nil {
		return fmt.Errorf("failed to serialize sender key: %w", err)
	}
	_, err = s.db.Exec(ctx, storeSenderKeyQuery, s.AccountID, senderUUID, deviceID, distributionID, serialized)
	return err
}
