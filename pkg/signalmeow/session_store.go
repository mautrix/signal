package signalmeow

import (
	"context"
	"database/sql"
	"errors"

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
	AllSessionsForUUID(theirUuid string, ctx context.Context) ([]*libsignalgo.Address, []*libsignalgo.SessionRecord, error)
	// RemoveSession removes the session for the given address.
	RemoveSession(address *libsignalgo.Address, ctx context.Context) error
	// RemoveAllSessions removes all sessions for our ACI UUID
	RemoveAllSessions(ctx context.Context) error
}

func scanRecord(row scannable) (int, *libsignalgo.SessionRecord, error) {
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

func (s *SQLStore) RemoveSession(address *libsignalgo.Address, ctx context.Context) error {
	theirUuid, err := address.Name()
	if err != nil {
		return err
	}
	deviceId, err := address.DeviceID()
	if err != nil {
		return err
	}
	_, err = s.db.Exec(removeSessionQuery, s.AciUuid, theirUuid, deviceId)
	return err
}

func (s *SQLStore) AllSessionsForUUID(theirUuid string, ctx context.Context) ([]*libsignalgo.Address, []*libsignalgo.SessionRecord, error) {
	rows, err := s.db.Query(allSessionsQuery, s.AciUuid, theirUuid)
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
		address, err := libsignalgo.NewAddress(theirUuid, uint(deviceId))
		if err != nil {
			return nil, nil, err
		}
		addresses = append(addresses, address)
	}
	return addresses, records, nil
}

func (s *SQLStore) LoadSession(address *libsignalgo.Address, ctx context.Context) (*libsignalgo.SessionRecord, error) {
	theirUuid, err := address.Name()
	if err != nil {
		return nil, err
	}
	deviceId, err := address.DeviceID()
	if err != nil {
		return nil, err
	}
	_, record, err := scanRecord(s.db.QueryRow(loadSessionQuery, s.AciUuid, theirUuid, deviceId))
	return record, err
}

func (s *SQLStore) StoreSession(address *libsignalgo.Address, record *libsignalgo.SessionRecord, ctx context.Context) error {
	theirUuid, err := address.Name()
	if err != nil {
		return err
	}
	deviceId, err := address.DeviceID()
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
	_, err = tx.Exec(storeSessionQuery, s.AciUuid, theirUuid, deviceId, serialized)
	if err != nil {
		_ = tx.Rollback()
		return err
	}
	err = tx.Commit()
	return err
}

func (s *SQLStore) RemoveAllSessions(ctx context.Context) error {
	_, err := s.db.Exec("DELETE FROM signalmeow_sessions WHERE our_aci_uuid=$1", s.AciUuid)
	return err
}
