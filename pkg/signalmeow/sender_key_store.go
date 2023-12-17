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

package signalmeow

import (
	"context"
	"database/sql"
	"errors"
	"fmt"

	"github.com/google/uuid"

	"go.mau.fi/mautrix-signal/pkg/libsignalgo"
)

var _ libsignalgo.SenderKeyStore = (*SQLStore)(nil)

const (
	loadSenderKeyQuery  = `SELECT key_record FROM signalmeow_sender_keys WHERE our_aci_uuid=$1 AND sender_uuid=$2 AND sender_device_id=$3 AND distribution_id=$4`
	storeSenderKeyQuery = `INSERT INTO signalmeow_sender_keys (our_aci_uuid, sender_uuid, sender_device_id, distribution_id, key_record) VALUES ($1, $2, $3, $4, $5) ON CONFLICT (our_aci_uuid, sender_uuid, sender_device_id, distribution_id) DO UPDATE SET key_record=excluded.key_record`
)

func scanSenderKey(row scannable) (*libsignalgo.SenderKeyRecord, error) {
	var key []byte
	err := row.Scan(&key)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, nil
	} else if err != nil {
		return nil, err
	}
	return libsignalgo.DeserializeSenderKeyRecord(key)
}

func (s *SQLStore) LoadSenderKey(sender libsignalgo.Address, distributionID uuid.UUID, ctx context.Context) (*libsignalgo.SenderKeyRecord, error) {
	distributionIdString := distributionID.String()
	if distributionIdString == "" {
		return nil, errors.New(fmt.Sprintf("distributionID did not parse: %v", distributionID))
	}
	senderUuid, err := sender.Name()
	if err != nil {
		return nil, err
	}
	deviceId, err := sender.DeviceID()
	if err != nil {
		return nil, err
	}
	return scanSenderKey(s.db.QueryRow(loadSenderKeyQuery, s.AciUuid, senderUuid, deviceId, distributionIdString))
}

func (s *SQLStore) StoreSenderKey(sender libsignalgo.Address, distributionID uuid.UUID, record *libsignalgo.SenderKeyRecord, ctx context.Context) error {
	distributionIdString := distributionID.String()
	if distributionIdString == "" {
		return errors.New(fmt.Sprintf("distributionID did not parse: %v", distributionID))
	}
	senderUuid, err := sender.Name()
	if err != nil {
		return err
	}
	deviceId, err := sender.DeviceID()
	if err != nil {
		return err
	}
	serialized, err := record.Serialize()
	if err != nil {
		return err
	}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		tx.Rollback()
		return err
	}
	_, err = tx.Exec(storeSenderKeyQuery, s.AciUuid, senderUuid, deviceId, distributionIdString, serialized)
	if err != nil {
		_ = tx.Rollback()
		return err
	}
	err = tx.Commit()
	return err
}
