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

	"go.mau.fi/mautrix-signal/pkg/libsignalgo"
)

var _ libsignalgo.PreKeyStore = (*SQLStore)(nil)
var _ libsignalgo.SignedPreKeyStore = (*SQLStore)(nil)
var _ libsignalgo.KyberPreKeyStore = (*SQLStore)(nil)
var _ PreKeyStoreExtras = (*SQLStore)(nil)

// TODO: figure out how best to handle ACI vs PNI UUIDs

type PreKeyStoreExtras interface {
	PreKey(uuidKind UUIDKind, preKeyId int) (*libsignalgo.PreKeyRecord, error)
	SignedPreKey(uuidKind UUIDKind, preKeyId int) (*libsignalgo.SignedPreKeyRecord, error)
	KyberPreKey(uuidKind UUIDKind, preKeyId int) (*libsignalgo.KyberPreKeyRecord, error)
	SavePreKey(uuidKind UUIDKind, preKey *libsignalgo.PreKeyRecord, markUploaded bool) error
	SaveSignedPreKey(uuidKind UUIDKind, preKey *libsignalgo.SignedPreKeyRecord, markUploaded bool) error
	SaveKyberPreKey(uuidKind UUIDKind, preKey *libsignalgo.KyberPreKeyRecord, lastResort bool) error
	DeletePreKey(uuidKind UUIDKind, preKeyId int) error
	DeleteSignedPreKey(uuidKind UUIDKind, preKeyId int) error
	DeleteKyberPreKey(uuidKind UUIDKind, preKeyId int) error
	GetNextPreKeyID(uuidKind UUIDKind) (uint, error)
	GetSignedNextPreKeyID(uuidKind UUIDKind) (uint, error)
	GetNextKyberPreKeyID(uuidKind UUIDKind) (uint, error)
	MarkPreKeysAsUploaded(uuidKind UUIDKind, upToID uint) error
	MarkSignedPreKeysAsUploaded(uuidKind UUIDKind, upToID uint) error
	IsKyberPreKeyLastResort(uuidKind UUIDKind, preKeyId int) (bool, error)
	DeleteAllPreKeys() error
}

// libsignalgo.PreKeyStore implementation
func (s *SQLStore) LoadPreKey(id uint32, ctx context.Context) (*libsignalgo.PreKeyRecord, error) {
	return s.PreKey(UUIDKindACI, int(id))
}
func (s *SQLStore) StorePreKey(id uint32, preKeyRecord *libsignalgo.PreKeyRecord, ctx context.Context) error {
	return s.SavePreKey(UUIDKindACI, preKeyRecord, false)
}
func (s *SQLStore) RemovePreKey(id uint32, ctx context.Context) error {
	return s.DeletePreKey(UUIDKindACI, int(id))
}

// libsignalgo.SignedPreKeyStore implementation
func (s *SQLStore) LoadSignedPreKey(id uint32, ctx context.Context) (*libsignalgo.SignedPreKeyRecord, error) {
	return s.SignedPreKey(UUIDKindACI, int(id))
}
func (s *SQLStore) StoreSignedPreKey(id uint32, signedPreKeyRecord *libsignalgo.SignedPreKeyRecord, ctx context.Context) error {
	return s.SaveSignedPreKey(UUIDKindACI, signedPreKeyRecord, false)
}
func (s *SQLStore) RemoveSignedPreKey(id uint32, ctx context.Context) error {
	return s.DeleteSignedPreKey(UUIDKindACI, int(id))
}

// libsignalgo.KyberPreKeyStore implementation
func (s *SQLStore) LoadKyberPreKey(id uint32, ctx context.Context) (*libsignalgo.KyberPreKeyRecord, error) {
	return s.KyberPreKey(UUIDKindACI, int(id))
}
func (s *SQLStore) StoreKyberPreKey(id uint32, preKeyRecord *libsignalgo.KyberPreKeyRecord, ctx context.Context) error {
	return s.SaveKyberPreKey(UUIDKindACI, preKeyRecord, false)
}
func (s *SQLStore) MarkKyberPreKeyUsed(id uint32, ctx context.Context) error {
	isLastResort, err := s.IsKyberPreKeyLastResort(UUIDKindACI, int(id))
	if err != nil {
		return err
	}
	if !isLastResort {
		return s.DeleteKyberPreKey(UUIDKindACI, int(id))
	}
	return nil
}

func (s *SQLStore) KyberPreKey(uuidKind UUIDKind, preKeyId int) (*libsignalgo.KyberPreKeyRecord, error) {
	getKyberPreKeyQuery := `SELECT key_pair, is_last_resort FROM signalmeow_kyber_pre_keys WHERE aci_uuid=$1 AND key_id=$2 AND uuid_kind=$3`
	var record []byte
	var isLastResort bool
	err := s.db.QueryRow(getKyberPreKeyQuery, s.ACI, preKeyId, uuidKind).Scan(&record, &isLastResort)
	if errors.Is(err, sql.ErrNoRows) {
		zlog.Info().Msg("scanKyberPreKey: no rows")
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	return libsignalgo.DeserializeKyberPreKeyRecord(record)
}

func (s *SQLStore) SaveKyberPreKey(uuidKind UUIDKind, kyberPreKeyRecord *libsignalgo.KyberPreKeyRecord, lastResort bool) error {
	insertKyberPreKeyQuery := `INSERT INTO signalmeow_kyber_pre_keys (aci_uuid, key_id, uuid_kind, key_pair, is_last_resort) VALUES ($1, $2, $3, $4, $5)`
	id, err := kyberPreKeyRecord.GetID()
	if err != nil {
		return err
	}
	serialized, err := kyberPreKeyRecord.Serialize()
	if err != nil {
		return err
	}
	_, err = s.db.Exec(insertKyberPreKeyQuery, s.ACI, id, uuidKind, serialized, lastResort)
	if err != nil {
		zlog.Err(err).Msg("error inserting kyberPreKeyRecord")
	}
	return err
}

func (s *SQLStore) DeleteKyberPreKey(uuidKind UUIDKind, preKeyId int) error {
	deleteKyberPreKeyQuery := `DELETE FROM signalmeow_kyber_pre_keys WHERE aci_uuid=$1 AND key_id=$2 AND uuid_kind=$3`
	_, err := s.db.Exec(deleteKyberPreKeyQuery, s.ACI, preKeyId, uuidKind)
	return err
}

func (s *SQLStore) GetNextKyberPreKeyID(uuidKind UUIDKind) (uint, error) {
	getLastKyberPreKeyIDQuery := `SELECT MAX(key_id) FROM signalmeow_kyber_pre_keys WHERE aci_uuid=$1 AND uuid_kind=$2`
	var lastKeyID sql.NullInt64
	err := s.db.QueryRow(getLastKyberPreKeyIDQuery, s.ACI, uuidKind).Scan(&lastKeyID)
	if err != nil {
		return 0, fmt.Errorf("failed to query next kyber prekey ID: %w", err)
	}
	return uint(lastKeyID.Int64) + 1, nil
}

func (s *SQLStore) IsKyberPreKeyLastResort(uuidKind UUIDKind, preKeyId int) (bool, error) {
	isLastResortQuery := `SELECT is_last_resort FROM signalmeow_kyber_pre_keys WHERE aci_uuid=$1 AND key_id=$2 AND uuid_kind=$3`
	var isLastResort bool
	err := s.db.QueryRow(isLastResortQuery, s.ACI, preKeyId, uuidKind).Scan(&isLastResort)
	if err != nil {
		return false, err
	}
	return isLastResort, nil
}

const (
	getPreKeyQuery              = `SELECT key_id, key_pair FROM signalmeow_pre_keys WHERE aci_uuid=$1 AND key_id=$2 AND uuid_kind=$3 and is_signed=$4`
	insertPreKeyQuery           = `INSERT INTO signalmeow_pre_keys (aci_uuid, key_id, uuid_kind, is_signed, key_pair, uploaded) VALUES ($1, $2, $3, $4, $5, $6)`
	deletePreKeyQuery           = `DELETE FROM signalmeow_pre_keys WHERE aci_uuid=$1 AND key_id=$2 AND uuid_kind=$3 AND is_signed=$4`
	getLastPreKeyIDQuery        = `SELECT MAX(key_id) FROM signalmeow_pre_keys WHERE aci_uuid=$1 AND uuid_kind=$2 AND is_signed=$3`
	markPreKeysAsUploadedQuery  = `UPDATE signalmeow_pre_keys SET uploaded=true WHERE aci_uuid=$1 AND uuid_kind=$2 AND is_signed=$3 AND key_id<=$4`
	getUnuploadedPreKeysQuery   = `SELECT key_id, key_pair FROM signalmeow_pre_keys WHERE aci_uuid=$1 AND uuid_kind=$2 AND is_signed=$3 AND uploaded=false ORDER BY key_id`
	getUploadedPreKeyCountQuery = `SELECT COUNT(*) FROM signalmeow_pre_keys WHERE aci_uuid=$1 AND uuid_kind=$2 AND is_signed=$3 AND uploaded=true`
)

func scanPreKey(row scannable) (*libsignalgo.PreKeyRecord, error) {
	var id uint
	var record []byte
	err := row.Scan(&id, &record)
	if errors.Is(err, sql.ErrNoRows) {
		zlog.Info().Msg("scanPreKey: no rows")
		return nil, nil
	} else if err != nil {
		return nil, err
	}
	return libsignalgo.DeserializePreKeyRecord(record)
}

func scanSignedPreKey(row scannable) (*libsignalgo.SignedPreKeyRecord, error) {
	var id uint
	var record []byte
	err := row.Scan(&id, &record)
	if errors.Is(err, sql.ErrNoRows) {
		zlog.Info().Msg("scanSignedPreKey: no rows")
		return nil, nil
	} else if err != nil {
		return nil, err
	}
	return libsignalgo.DeserializeSignedPreKeyRecord(record)
}

func (s *SQLStore) PreKey(uuidKind UUIDKind, preKeyId int) (*libsignalgo.PreKeyRecord, error) {
	return scanPreKey(s.db.QueryRow(getPreKeyQuery, s.ACI, preKeyId, uuidKind, false))
}

func (s *SQLStore) SignedPreKey(uuidKind UUIDKind, preKeyId int) (*libsignalgo.SignedPreKeyRecord, error) {
	return scanSignedPreKey(s.db.QueryRow(getPreKeyQuery, s.ACI, preKeyId, uuidKind, true))
}

func (s *SQLStore) SavePreKey(uuidKind UUIDKind, preKey *libsignalgo.PreKeyRecord, markUploaded bool) error {
	id, err := preKey.GetID()
	serialized, err := preKey.Serialize()
	if err != nil {
		zlog.Err(err).Msg("error serializing prekey")
		return err
	}
	_, err = s.db.Exec(insertPreKeyQuery, s.ACI, id, uuidKind, false, serialized, markUploaded)
	if err != nil {
		zlog.Err(err).Msg("error inserting prekey")
	}
	return err
}

func (s *SQLStore) SaveSignedPreKey(uuidKind UUIDKind, preKey *libsignalgo.SignedPreKeyRecord, markUploaded bool) error {
	id, err := preKey.GetID()
	serialized, err := preKey.Serialize()
	if err != nil {
		zlog.Err(err).Msg("error serializing signed prekey")
		return err
	}
	_, err = s.db.Exec(insertPreKeyQuery, s.ACI, id, uuidKind, true, serialized, markUploaded)
	if err != nil {
		zlog.Err(err).Msg("error inserting signed prekey")
	}
	return err
}

func (s *SQLStore) DeletePreKey(uuidKind UUIDKind, preKeyId int) error {
	_, err := s.db.Exec(deletePreKeyQuery, s.ACI, preKeyId, uuidKind, false)
	return err
}

func (s *SQLStore) DeleteSignedPreKey(uuidKind UUIDKind, preKeyId int) error {
	_, err := s.db.Exec(deletePreKeyQuery, s.ACI, preKeyId, uuidKind, true)
	return err
}

func (s *SQLStore) GetNextPreKeyID(uuidKind UUIDKind) (uint, error) {
	var lastKeyID sql.NullInt64
	err := s.db.QueryRow(getLastPreKeyIDQuery, s.ACI, uuidKind, false).Scan(&lastKeyID)
	if err != nil {
		return 0, fmt.Errorf("failed to query next prekey ID: %w", err)
	}
	return uint(lastKeyID.Int64) + 1, nil
}

func (s *SQLStore) GetSignedNextPreKeyID(uuidKind UUIDKind) (uint, error) {
	var lastKeyID sql.NullInt64
	err := s.db.QueryRow(getLastPreKeyIDQuery, s.ACI, uuidKind, true).Scan(&lastKeyID)
	if err != nil {
		return 0, fmt.Errorf("failed to query next signed prekey ID: %w", err)
	}
	return uint(lastKeyID.Int64) + 1, nil
}

func (s *SQLStore) MarkPreKeysAsUploaded(uuidKind UUIDKind, upToID uint) error {
	_, err := s.db.Exec(markPreKeysAsUploadedQuery, s.ACI, uuidKind, false, upToID)
	return err
}

func (s *SQLStore) MarkSignedPreKeysAsUploaded(uuidKind UUIDKind, upToID uint) error {
	_, err := s.db.Exec(markPreKeysAsUploadedQuery, s.ACI, uuidKind, true, upToID)
	return err
}

func (s *SQLStore) DeleteAllPreKeys() error {
	_, err := s.db.Exec("DELETE FROM signalmeow_pre_keys WHERE aci_uuid=$1", s.ACI)
	_, err = s.db.Exec("DELETE FROM signalmeow_kyber_pre_keys WHERE aci_uuid=$1", s.ACI)
	return err
}
