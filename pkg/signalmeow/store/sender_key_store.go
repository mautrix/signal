package store

import (
	"context"
	"database/sql"
	"errors"

	"github.com/google/uuid"
	"go.mau.fi/mautrix-signal/pkg/libsignalgo"
)

var _ libsignalgo.SenderKeyStore = (*SQLStore)(nil)

const (
	loadSenderKeyQuery  = `SELECT key FROM signalmeow_sender_keys WHERE our_aci_uuid=$1 AND their_aci_uuid=$2 AND their_device_id=$3`
	storeSenderKeyQuery = `INSERT OR REPLACE INTO signalmeow_sender_keys (our_aci_uuid, sender_uuid, sender_device_id, key) VALUES ($1, $2, $3, $4)` // SQLite specific
)

func scanSenderKey(row scannable) (*libsignalgo.SenderKeyRecord, error) {
	var key []byte
	var deviceId int
	err := row.Scan(&deviceId, &key)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, nil
	} else if err != nil {
		return nil, err
	}
	return libsignalgo.DeserializeSenderKeyRecord(key)
}

func (s *SQLStore) LoadSenderKey(sender libsignalgo.Address, distributionID uuid.UUID, ctx context.Context) (*libsignalgo.SenderKeyRecord, error) {
	senderUuid, err := sender.Name()
	if err != nil {
		return nil, err
	}
	deviceId, err := sender.DeviceID()
	if err != nil {
		return nil, err
	}
	return scanSenderKey(s.db.QueryRow(loadSenderKeyQuery, s.AciUuid, senderUuid, deviceId))
}

func (s *SQLStore) StoreSenderKey(sender libsignalgo.Address, distributionID uuid.UUID, record *libsignalgo.SenderKeyRecord, ctx context.Context) error {
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
	_, err = tx.Exec(storeSenderKeyQuery, s.AciUuid, senderUuid, deviceId, serialized)
	if err != nil {
		_ = tx.Rollback()
		return err
	}
	err = tx.Commit()
	return err
}
