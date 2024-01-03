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

	"go.mau.fi/util/dbutil"

	"go.mau.fi/mautrix-signal/pkg/libsignalgo"
)

var _ libsignalgo.PreKeyStore = (*SQLStore)(nil)
var _ libsignalgo.SignedPreKeyStore = (*SQLStore)(nil)
var _ libsignalgo.KyberPreKeyStore = (*SQLStore)(nil)
var _ PreKeyStoreExtras = (*SQLStore)(nil)

// TODO: figure out how best to handle ACI vs PNI UUIDs

type PreKeyStoreExtras interface {
	PreKey(ctx context.Context, uuidKind UUIDKind, preKeyID int) (*libsignalgo.PreKeyRecord, error)
	SignedPreKey(ctx context.Context, uuidKind UUIDKind, preKeyID int) (*libsignalgo.SignedPreKeyRecord, error)
	KyberPreKey(ctx context.Context, uuidKind UUIDKind, preKeyID int) (*libsignalgo.KyberPreKeyRecord, error)
	SavePreKey(ctx context.Context, uuidKind UUIDKind, preKey *libsignalgo.PreKeyRecord, markUploaded bool) error
	SaveSignedPreKey(ctx context.Context, uuidKind UUIDKind, preKey *libsignalgo.SignedPreKeyRecord, markUploaded bool) error
	SaveKyberPreKey(ctx context.Context, uuidKind UUIDKind, preKey *libsignalgo.KyberPreKeyRecord, lastResort bool) error
	DeletePreKey(ctx context.Context, uuidKind UUIDKind, preKeyID int) error
	DeleteSignedPreKey(ctx context.Context, uuidKind UUIDKind, preKeyID int) error
	DeleteKyberPreKey(ctx context.Context, uuidKind UUIDKind, preKeyID int) error
	GetNextPreKeyID(ctx context.Context, uuidKind UUIDKind) (uint, error)
	GetSignedNextPreKeyID(ctx context.Context, uuidKind UUIDKind) (uint, error)
	GetNextKyberPreKeyID(ctx context.Context, uuidKind UUIDKind) (uint, error)
	MarkPreKeysAsUploaded(ctx context.Context, uuidKind UUIDKind, upToID uint) error
	MarkSignedPreKeysAsUploaded(ctx context.Context, uuidKind UUIDKind, upToID uint) error
	IsKyberPreKeyLastResort(ctx context.Context, uuidKind UUIDKind, preKeyID int) (bool, error)
	DeleteAllPreKeys(ctx context.Context) error
}

// libsignalgo.PreKeyStore implementation

func (s *SQLStore) LoadPreKey(ctx context.Context, id uint32) (*libsignalgo.PreKeyRecord, error) {
	return s.PreKey(ctx, UUIDKindACI, int(id))
}
func (s *SQLStore) StorePreKey(ctx context.Context, id uint32, preKeyRecord *libsignalgo.PreKeyRecord) error {
	return s.SavePreKey(ctx, UUIDKindACI, preKeyRecord, false)
}
func (s *SQLStore) RemovePreKey(ctx context.Context, id uint32) error {
	return s.DeletePreKey(ctx, UUIDKindACI, int(id))
}

// libsignalgo.SignedPreKeyStore implementation

func (s *SQLStore) LoadSignedPreKey(ctx context.Context, id uint32) (*libsignalgo.SignedPreKeyRecord, error) {
	return s.SignedPreKey(ctx, UUIDKindACI, int(id))
}
func (s *SQLStore) StoreSignedPreKey(ctx context.Context, id uint32, signedPreKeyRecord *libsignalgo.SignedPreKeyRecord) error {
	return s.SaveSignedPreKey(ctx, UUIDKindACI, signedPreKeyRecord, false)
}
func (s *SQLStore) RemoveSignedPreKey(ctx context.Context, id uint32) error {
	return s.DeleteSignedPreKey(ctx, UUIDKindACI, int(id))
}

// libsignalgo.KyberPreKeyStore implementation

func (s *SQLStore) LoadKyberPreKey(ctx context.Context, id uint32) (*libsignalgo.KyberPreKeyRecord, error) {
	return s.KyberPreKey(ctx, UUIDKindACI, int(id))
}
func (s *SQLStore) StoreKyberPreKey(ctx context.Context, id uint32, kyberPreKeyRecord *libsignalgo.KyberPreKeyRecord) error {
	return s.SaveKyberPreKey(ctx, UUIDKindACI, kyberPreKeyRecord, false)
}
func (s *SQLStore) MarkKyberPreKeyUsed(ctx context.Context, id uint32) error {
	isLastResort, err := s.IsKyberPreKeyLastResort(ctx, UUIDKindACI, int(id))
	if err != nil {
		return err
	}
	if !isLastResort {
		return s.DeleteKyberPreKey(ctx, UUIDKindACI, int(id))
	}
	return nil
}

const (
	getKyberPreKeyQuery       = `SELECT key_pair, is_last_resort FROM signalmeow_kyber_pre_keys WHERE aci_uuid=$1 AND key_id=$2 AND uuid_kind=$3`
	insertKyberPreKeyQuery    = `INSERT INTO signalmeow_kyber_pre_keys (aci_uuid, key_id, uuid_kind, key_pair, is_last_resort) VALUES ($1, $2, $3, $4, $5)`
	deleteKyberPreKeyQuery    = `DELETE FROM signalmeow_kyber_pre_keys WHERE aci_uuid=$1 AND key_id=$2 AND uuid_kind=$3`
	getLastKyberPreKeyIDQuery = `SELECT MAX(key_id) FROM signalmeow_kyber_pre_keys WHERE aci_uuid=$1 AND uuid_kind=$2`
	isLastResortQuery         = `SELECT is_last_resort FROM signalmeow_kyber_pre_keys WHERE aci_uuid=$1 AND key_id=$2 AND uuid_kind=$3`
)

func (s *SQLStore) KyberPreKey(ctx context.Context, uuidKind UUIDKind, preKeyID int) (*libsignalgo.KyberPreKeyRecord, error) {
	var record []byte
	var isLastResort bool
	err := s.db.Conn(ctx).QueryRowContext(ctx, getKyberPreKeyQuery, s.ACI, preKeyID, uuidKind).Scan(&record, &isLastResort)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	return libsignalgo.DeserializeKyberPreKeyRecord(record)
}

func (s *SQLStore) SaveKyberPreKey(ctx context.Context, uuidKind UUIDKind, kyberPreKeyRecord *libsignalgo.KyberPreKeyRecord, lastResort bool) error {
	id, err := kyberPreKeyRecord.GetID()
	if err != nil {
		return fmt.Errorf("failed to get kyber prekey record ID: %w", err)
	}
	serialized, err := kyberPreKeyRecord.Serialize()
	if err != nil {
		return fmt.Errorf("failed to serialize kyber prekey record: %w", err)
	}
	_, err = s.db.Conn(ctx).ExecContext(ctx, insertKyberPreKeyQuery, s.ACI, id, uuidKind, serialized, lastResort)
	return err
}

func (s *SQLStore) DeleteKyberPreKey(ctx context.Context, uuidKind UUIDKind, preKeyID int) error {
	_, err := s.db.Conn(ctx).ExecContext(ctx, deleteKyberPreKeyQuery, s.ACI, preKeyID, uuidKind)
	return err
}

func (s *SQLStore) GetNextKyberPreKeyID(ctx context.Context, uuidKind UUIDKind) (uint, error) {
	var lastKeyID sql.NullInt64
	err := s.db.Conn(ctx).QueryRowContext(ctx, getLastKyberPreKeyIDQuery, s.ACI, uuidKind).Scan(&lastKeyID)
	if err != nil {
		return 0, fmt.Errorf("failed to query next kyber prekey ID: %w", err)
	}
	return uint(lastKeyID.Int64) + 1, nil
}

func (s *SQLStore) IsKyberPreKeyLastResort(ctx context.Context, uuidKind UUIDKind, preKeyID int) (bool, error) {
	var isLastResort bool
	err := s.db.Conn(ctx).QueryRowContext(ctx, isLastResortQuery, s.ACI, preKeyID, uuidKind).Scan(&isLastResort)
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

func scanPreKey(row dbutil.Scannable) (*libsignalgo.PreKeyRecord, error) {
	var id uint
	var record []byte
	err := row.Scan(&id, &record)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, nil
	} else if err != nil {
		return nil, err
	}
	return libsignalgo.DeserializePreKeyRecord(record)
}

func scanSignedPreKey(row dbutil.Scannable) (*libsignalgo.SignedPreKeyRecord, error) {
	var id uint
	var record []byte
	err := row.Scan(&id, &record)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, nil
	} else if err != nil {
		return nil, err
	}
	return libsignalgo.DeserializeSignedPreKeyRecord(record)
}

func (s *SQLStore) PreKey(ctx context.Context, uuidKind UUIDKind, preKeyID int) (*libsignalgo.PreKeyRecord, error) {
	return scanPreKey(s.db.Conn(ctx).QueryRowContext(ctx, getPreKeyQuery, s.ACI, preKeyID, uuidKind, false))
}

func (s *SQLStore) SignedPreKey(ctx context.Context, uuidKind UUIDKind, preKeyID int) (*libsignalgo.SignedPreKeyRecord, error) {
	return scanSignedPreKey(s.db.Conn(ctx).QueryRowContext(ctx, getPreKeyQuery, s.ACI, preKeyID, uuidKind, true))
}

func (s *SQLStore) SavePreKey(ctx context.Context, uuidKind UUIDKind, preKey *libsignalgo.PreKeyRecord, markUploaded bool) error {
	id, err := preKey.GetID()
	if err != nil {
		return fmt.Errorf("failed to get prekey ID: %w", err)
	}
	serialized, err := preKey.Serialize()
	if err != nil {
		return fmt.Errorf("failed to serialize prekey: %w", err)
	}
	_, err = s.db.Conn(ctx).ExecContext(ctx, insertPreKeyQuery, s.ACI, id, uuidKind, false, serialized, markUploaded)
	return err
}

func (s *SQLStore) SaveSignedPreKey(ctx context.Context, uuidKind UUIDKind, preKey *libsignalgo.SignedPreKeyRecord, markUploaded bool) error {
	id, err := preKey.GetID()
	if err != nil {
		return fmt.Errorf("failed to get signed prekey ID: %w", err)
	}
	serialized, err := preKey.Serialize()
	if err != nil {
		return fmt.Errorf("failed to serialize signed prekey: %w", err)
	}
	_, err = s.db.Conn(ctx).ExecContext(ctx, insertPreKeyQuery, s.ACI, id, uuidKind, true, serialized, markUploaded)
	return err
}

func (s *SQLStore) DeletePreKey(ctx context.Context, uuidKind UUIDKind, preKeyID int) error {
	_, err := s.db.Conn(ctx).ExecContext(ctx, deletePreKeyQuery, s.ACI, preKeyID, uuidKind, false)
	return err
}

func (s *SQLStore) DeleteSignedPreKey(ctx context.Context, uuidKind UUIDKind, preKeyID int) error {
	_, err := s.db.Conn(ctx).ExecContext(ctx, deletePreKeyQuery, s.ACI, preKeyID, uuidKind, true)
	return err
}

func (s *SQLStore) GetNextPreKeyID(ctx context.Context, uuidKind UUIDKind) (uint, error) {
	var lastKeyID sql.NullInt64
	err := s.db.Conn(ctx).QueryRowContext(ctx, getLastPreKeyIDQuery, s.ACI, uuidKind, false).Scan(&lastKeyID)
	if err != nil {
		return 0, fmt.Errorf("failed to query next prekey ID: %w", err)
	}
	return uint(lastKeyID.Int64) + 1, nil
}

func (s *SQLStore) GetSignedNextPreKeyID(ctx context.Context, uuidKind UUIDKind) (uint, error) {
	var lastKeyID sql.NullInt64
	err := s.db.Conn(ctx).QueryRowContext(ctx, getLastPreKeyIDQuery, s.ACI, uuidKind, true).Scan(&lastKeyID)
	if err != nil {
		return 0, fmt.Errorf("failed to query next signed prekey ID: %w", err)
	}
	return uint(lastKeyID.Int64) + 1, nil
}

func (s *SQLStore) MarkPreKeysAsUploaded(ctx context.Context, uuidKind UUIDKind, upToID uint) error {
	_, err := s.db.Conn(ctx).ExecContext(ctx, markPreKeysAsUploadedQuery, s.ACI, uuidKind, false, upToID)
	return err
}

func (s *SQLStore) MarkSignedPreKeysAsUploaded(ctx context.Context, uuidKind UUIDKind, upToID uint) error {
	_, err := s.db.Conn(ctx).ExecContext(ctx, markPreKeysAsUploadedQuery, s.ACI, uuidKind, true, upToID)
	return err
}

func (s *SQLStore) DeleteAllPreKeys(ctx context.Context) error {
	return s.db.DoTxn(ctx, nil, func(ctx context.Context) error {
		_, err := s.db.Conn(ctx).ExecContext(ctx, "DELETE FROM signalmeow_pre_keys WHERE aci_uuid=$1", s.ACI)
		if err != nil {
			return err
		}
		_, err = s.db.Conn(ctx).ExecContext(ctx, "DELETE FROM signalmeow_kyber_pre_keys WHERE aci_uuid=$1", s.ACI)
		return err
	})
}
