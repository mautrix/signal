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
	SavePreKey(uuidKind UUIDKind, preKey *libsignalgo.PreKeyRecord, markUploaded bool) error
	SaveSignedPreKey(uuidKind UUIDKind, preKey *libsignalgo.SignedPreKeyRecord, markUploaded bool) error
	DeletePreKey(uuidKind UUIDKind, preKeyId int) error
	DeleteSignedPreKey(uuidKind UUIDKind, preKeyId int) error
	GetNextPreKeyID(uuidKind UUIDKind) (uint, error)
	GetSignedNextPreKeyID(uuidKind UUIDKind) (uint, error)
	MarkPreKeysAsUploaded(uuidKind UUIDKind, upToID uint) error
	MarkSignedPreKeysAsUploaded(uuidKind UUIDKind, upToID uint) error
	GetUnuploadedPreKeys(uuidKind UUIDKind) ([]*libsignalgo.PreKeyRecord, error)
	GetUnuploadedSignedPreKeys(uuidKind UUIDKind) ([]*libsignalgo.SignedPreKeyRecord, error)
	GetUploadedPreKeyCount(uuidKind UUIDKind) (int, error)
	GetUploadedSignedPreKeyCount(uuidKind UUIDKind) (int, error)
}

// libsignalgo.PreKeyStore implementation
func (s *SQLStore) LoadPreKey(id uint32, ctx context.Context) (*libsignalgo.PreKeyRecord, error) {
	return s.PreKey(UUID_KIND_ACI, int(id))
}
func (s *SQLStore) StorePreKey(id uint32, preKeyRecord *libsignalgo.PreKeyRecord, ctx context.Context) error {
	return s.SavePreKey(UUID_KIND_ACI, preKeyRecord, false)
}
func (s *SQLStore) RemovePreKey(id uint32, ctx context.Context) error {
	return s.DeletePreKey(UUID_KIND_ACI, int(id))
}

// libsignalgo.SignedPreKeyStore implementation
func (s *SQLStore) LoadSignedPreKey(id uint32, ctx context.Context) (*libsignalgo.SignedPreKeyRecord, error) {
	return s.SignedPreKey(UUID_KIND_ACI, int(id))
}
func (s *SQLStore) StoreSignedPreKey(id uint32, signedPreKeyRecord *libsignalgo.SignedPreKeyRecord, ctx context.Context) error {
	return s.SaveSignedPreKey(UUID_KIND_ACI, signedPreKeyRecord, false)
}
func (s *SQLStore) RemoveSignedPreKey(id uint32, ctx context.Context) error {
	return s.DeleteSignedPreKey(UUID_KIND_ACI, int(id))
}

// libsignalgo.KyberPreKeyStore implementation
// TODO: implement this for reals
func (s *SQLStore) LoadKyberPreKey(id uint32, ctx context.Context) (*libsignalgo.KyberPreKeyRecord, error) {
	return nil, nil
}
func (s *SQLStore) StoreKyberPreKey(id uint32, preKeyRecord *libsignalgo.KyberPreKeyRecord, ctx context.Context) error {
	return nil
}
func (s *SQLStore) MarkKyberPreKeyUsed(id uint32, ctx context.Context) error {
	return nil
}

const (
	getPreKeyQuery              = `SELECT key_id, key_pair FROM signalmeow_pre_keys WHERE aci_uuid=$1 AND key_id=$2 AND uuid_kind=$3 and is_signed=$4`
	insertPreKeyQuery           = `INSERT INTO signalmeow_pre_keys (aci_uuid, key_id, uuid_kind, is_signed, key_pair, uploaded) VALUES ($1, $2, $3, $4, $5, $6)`
	deletePreKeyQuery           = `DELETE FROM signalmeow_pre_keys WHERE aci_uuid=$1 AND key_id=$2 AND uuid_kind=$3 AND is_signed=$4`
	getLastPreKeyIDQuery        = `SELECT MAX(key_id) FROM signalmeow_pre_keys WHERE aci_uuid=$1, uuid_kind=$2 AND is_signed=$3`
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
	return scanPreKey(s.db.QueryRow(getPreKeyQuery, s.AciUuid, preKeyId, uuidKind, false))
}

func (s *SQLStore) SignedPreKey(uuidKind UUIDKind, preKeyId int) (*libsignalgo.SignedPreKeyRecord, error) {
	return scanSignedPreKey(s.db.QueryRow(getPreKeyQuery, s.AciUuid, preKeyId, uuidKind, true))
}

func (s *SQLStore) SavePreKey(uuidKind UUIDKind, preKey *libsignalgo.PreKeyRecord, markUploaded bool) error {
	id, err := preKey.GetID()
	serialized, err := preKey.Serialize()
	if err != nil {
		zlog.Err(err).Msg("error serializing prekey")
		return err
	}
	_, err = s.db.Exec(insertPreKeyQuery, s.AciUuid, id, uuidKind, false, serialized, markUploaded)
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
	_, err = s.db.Exec(insertPreKeyQuery, s.AciUuid, id, uuidKind, true, serialized, markUploaded)
	if err != nil {
		zlog.Err(err).Msg("error inserting signed prekey")
	}
	return err
}

func (s *SQLStore) DeletePreKey(uuidKind UUIDKind, preKeyId int) error {
	_, err := s.db.Exec(deletePreKeyQuery, s.AciUuid, preKeyId, uuidKind, false)
	return err
}

func (s *SQLStore) DeleteSignedPreKey(uuidKind UUIDKind, preKeyId int) error {
	_, err := s.db.Exec(deletePreKeyQuery, s.AciUuid, preKeyId, uuidKind, true)
	return err
}

func (s *SQLStore) GetNextPreKeyID(uuidKind UUIDKind) (uint, error) {
	var lastKeyID sql.NullInt64
	err := s.db.QueryRow(getLastPreKeyIDQuery, s.AciUuid, uuidKind, false).Scan(&lastKeyID)
	if err != nil {
		return 0, fmt.Errorf("failed to query next prekey ID: %w", err)
	}
	return uint(lastKeyID.Int64) + 1, nil
}

func (s *SQLStore) GetSignedNextPreKeyID(uuidKind UUIDKind) (uint, error) {
	var lastKeyID sql.NullInt64
	err := s.db.QueryRow(getLastPreKeyIDQuery, s.AciUuid, uuidKind, true).Scan(&lastKeyID)
	if err != nil {
		return 0, fmt.Errorf("failed to query next signed prekey ID: %w", err)
	}
	return uint(lastKeyID.Int64) + 1, nil
}

func (s *SQLStore) MarkPreKeysAsUploaded(uuidKind UUIDKind, upToID uint) error {
	_, err := s.db.Exec(markPreKeysAsUploadedQuery, s.AciUuid, uuidKind, false, upToID)
	return err
}

func (s *SQLStore) MarkSignedPreKeysAsUploaded(uuidKind UUIDKind, upToID uint) error {
	_, err := s.db.Exec(markPreKeysAsUploadedQuery, s.AciUuid, uuidKind, true, upToID)
	return err
}

func (s *SQLStore) GetUnuploadedPreKeys(uuidKind UUIDKind) ([]*libsignalgo.PreKeyRecord, error) {
	res, err := s.db.Query(getUnuploadedPreKeysQuery, s.AciUuid, uuidKind, false)
	if err != nil {
		return nil, fmt.Errorf("failed to query existing prekeys: %w", err)
	}
	defer res.Close()
	newKeys := []*libsignalgo.PreKeyRecord{}
	for res.Next() {
		key, err := scanPreKey(res)
		if err != nil {
			return nil, err
		} else if key != nil {
			newKeys = append(newKeys, key)
		}
	}
	return newKeys, nil
}

func (s *SQLStore) GetUnuploadedSignedPreKeys(uuidKind UUIDKind) ([]*libsignalgo.SignedPreKeyRecord, error) {
	res, err := s.db.Query(getUnuploadedPreKeysQuery, s.AciUuid, uuidKind, true)
	if err != nil {
		return nil, fmt.Errorf("failed to query existing prekeys: %w", err)
	}
	defer res.Close()
	newKeys := []*libsignalgo.SignedPreKeyRecord{}
	for res.Next() {
		key, err := scanSignedPreKey(res)
		if err != nil {
			return nil, err
		} else if key != nil {
			newKeys = append(newKeys, key)
		}
	}
	return newKeys, nil
}

func (s *SQLStore) GetUploadedPreKeyCount(uuidKind UUIDKind) (count int, err error) {
	err = s.db.QueryRow(getUploadedPreKeyCountQuery, s.AciUuid, uuidKind, false).Scan(&count)
	return count, err
}

func (s *SQLStore) GetUploadedSignedPreKeyCount(uuidKind UUIDKind) (count int, err error) {
	err = s.db.QueryRow(getUploadedPreKeyCountQuery, s.AciUuid, uuidKind, true).Scan(&count)
	return count, err
}
