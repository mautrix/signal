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

var _ libsignalgo.IdentityKeyStore = (*sqlStore)(nil)

const (
	getIdentityKeyPairQuery     = `SELECT aci_identity_key_pair FROM signalmeow_device WHERE aci_uuid=$1`
	getRegistrationLocalIDQuery = `SELECT registration_id FROM signalmeow_device WHERE aci_uuid=$1`
	insertIdentityKeyQuery      = `
		INSERT INTO signalmeow_identity_keys (account_id, their_service_id, their_device_id, key, trust_level)
		VALUES ($1, $2, $3, $4, $5)
		ON CONFLICT (account_id, their_service_id, their_device_id) DO UPDATE
			SET key=excluded.key, trust_level=excluded.trust_level
	`
	getIdentityKeyTrustLevelQuery = `
		SELECT trust_level FROM signalmeow_identity_keys
		WHERE account_id=$1 AND their_service_id=$2 AND their_device_id=$3
	`
	getIdentityKeyQuery = `
		SELECT key FROM signalmeow_identity_keys
		WHERE account_id=$1 AND their_service_id=$2 AND their_device_id=$3
	`
)

func scanIdentityKeyPair(row dbutil.Scannable) (*libsignalgo.IdentityKeyPair, error) {
	var keyPair []byte
	err := row.Scan(&keyPair)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, nil
	} else if err != nil {
		return nil, err
	}
	return libsignalgo.DeserializeIdentityKeyPair(keyPair)
}

func scanIdentityKey(row dbutil.Scannable) (*libsignalgo.IdentityKey, error) {
	var key []byte
	err := row.Scan(&key)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, nil
	} else if err != nil {
		return nil, err
	}
	return libsignalgo.DeserializeIdentityKey(key)
}

func (s *sqlStore) GetIdentityKeyPair(ctx context.Context) (*libsignalgo.IdentityKeyPair, error) {
	return scanIdentityKeyPair(s.db.QueryRow(ctx, getIdentityKeyPairQuery, s.AccountID))
}

func (s *sqlStore) GetLocalRegistrationID(ctx context.Context) (uint32, error) {
	var regID sql.NullInt64
	err := s.db.QueryRow(ctx, getRegistrationLocalIDQuery, s.AccountID).Scan(&regID)
	if err != nil {
		return 0, fmt.Errorf("failed to get local registration ID: %w", err)
	}
	return uint32(regID.Int64), nil
}

func (s *sqlStore) SaveIdentityKey(ctx context.Context, address *libsignalgo.Address, identityKey *libsignalgo.IdentityKey) (bool, error) {
	trustLevel := "TRUSTED_UNVERIFIED" // TODO: this should be hard coded here
	serialized, err := identityKey.Serialize()
	if err != nil {
		return false, fmt.Errorf("failed to serialize identity key: %w", err)
	}
	theirServiceID, err := address.Name()
	if err != nil {
		return false, fmt.Errorf("failed to get their service ID: %w", err)
	}
	deviceID, err := address.DeviceID()
	if err != nil {
		return false, fmt.Errorf("failed to get device ID: %w", err)
	}
	oldKey, err := scanIdentityKey(s.db.QueryRow(ctx, getIdentityKeyQuery, s.AccountID, theirServiceID, deviceID))
	if err != nil {
		return false, fmt.Errorf("failed to get old identity key: %w", err)
	}
	var replacing bool
	if oldKey != nil {
		equal, err := oldKey.Equal(identityKey)
		if err != nil {
			return false, fmt.Errorf("failed to compare new and old identity keys: %w", err)
		}
		// We are replacing the old key if the old key exists, and it is not equal to the new key
		replacing = !equal
	}
	_, err = s.db.Exec(ctx, insertIdentityKeyQuery, s.AccountID, theirServiceID, deviceID, serialized, trustLevel)
	if err != nil {
		return replacing, fmt.Errorf("failed to insert new identity key: %w", err)
	}
	return replacing, err
}

func (s *sqlStore) IsTrustedIdentity(ctx context.Context, address *libsignalgo.Address, identityKey *libsignalgo.IdentityKey, direction libsignalgo.SignalDirection) (bool, error) {
	// TODO: this should check direction, and probably some other stuff (though whisperfish is pretty basic)
	theirServiceID, err := address.Name()
	if err != nil {
		return false, fmt.Errorf("failed to get their service ID: %w", err)
	}
	deviceID, err := address.DeviceID()
	if err != nil {
		return false, fmt.Errorf("failed to get device ID: %w", err)
	}
	var trustLevel string
	err = s.db.QueryRow(ctx, getIdentityKeyTrustLevelQuery, s.AccountID, theirServiceID, deviceID).Scan(&trustLevel)
	if errors.Is(err, sql.ErrNoRows) {
		// If no rows, they are a new identity, so trust by default
		return true, nil
	} else if err != nil {
		return false, fmt.Errorf("failed to get trust level from database: %w", err)
	}
	trusted := trustLevel == "TRUSTED_UNVERIFIED" || trustLevel == "TRUSTED_VERIFIED"
	return trusted, nil
}

func (s *sqlStore) GetIdentityKey(ctx context.Context, address *libsignalgo.Address) (*libsignalgo.IdentityKey, error) {
	theirServiceID, err := address.Name()
	if err != nil {
		return nil, fmt.Errorf("failed to get their service ID: %w", err)
	}
	deviceID, err := address.DeviceID()
	if err != nil {
		return nil, fmt.Errorf("failed to get device ID: %w", err)
	}
	key, err := scanIdentityKey(s.db.QueryRow(ctx, getIdentityKeyQuery, s.AccountID, theirServiceID, deviceID))
	if err != nil {
		return nil, fmt.Errorf("failed to get identity key from database: %w", err)
	}
	return key, err
}
