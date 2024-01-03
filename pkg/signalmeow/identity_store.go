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

var _ libsignalgo.IdentityKeyStore = (*SQLStore)(nil)

const (
	getIdentityKeyPairQuery       = `SELECT aci_identity_key_pair FROM signalmeow_device WHERE aci_uuid=$1`
	getRegistrationLocalIDQuery   = `SELECT registration_id FROM signalmeow_device WHERE aci_uuid=$1`
	insertIdentityKeyQuery        = `INSERT INTO signalmeow_identity_keys (our_aci_uuid, their_aci_uuid, their_device_id, key, trust_level) VALUES ($1, $2, $3, $4, $5) ON CONFLICT (our_aci_uuid, their_aci_uuid, their_device_id) DO UPDATE SET key=excluded.key, trust_level=excluded.trust_level`
	getIdentityKeyTrustLevelQuery = `SELECT trust_level FROM signalmeow_identity_keys WHERE our_aci_uuid=$1 AND their_aci_uuid=$2 AND their_device_id=$3`
	getIdentityKeyQuery           = `SELECT key FROM signalmeow_identity_keys WHERE our_aci_uuid=$1 AND their_aci_uuid=$2 AND their_device_id=$3`
)

func scanIdentityKeyPair(row scannable) (*libsignalgo.IdentityKeyPair, error) {
	var keyPair []byte
	err := row.Scan(&keyPair)
	if errors.Is(err, sql.ErrNoRows) {
		zlog.Info().Msg("no identity key pair found")
		return nil, nil
	} else if err != nil {
		return nil, err
	}
	return libsignalgo.DeserializeIdentityKeyPair(keyPair)
}

func scanIdentityKey(row scannable) (*libsignalgo.IdentityKey, error) {
	var key []byte
	err := row.Scan(&key)
	if errors.Is(err, sql.ErrNoRows) {
		zlog.Info().Msg("no identity key found")
		return nil, nil
	} else if err != nil {
		return nil, err
	}
	return libsignalgo.DeserializeIdentityKey(key)
}

func (s *SQLStore) GetIdentityKeyPair(ctx context.Context) (*libsignalgo.IdentityKeyPair, error) {
	keyPair, err := scanIdentityKeyPair(s.db.QueryRow(getIdentityKeyPairQuery, s.ACI))
	if err != nil {
		err = fmt.Errorf("failed to get identity key pair: %w", err)
		zlog.Error().Err(err).Msg("")
		return nil, err
	} else if keyPair == nil {
		return nil, nil
	}
	return keyPair, nil
}

func (s *SQLStore) GetLocalRegistrationID(ctx context.Context) (uint32, error) {
	var regID sql.NullInt64
	err := s.db.QueryRow(getRegistrationLocalIDQuery, s.ACI).Scan(&regID)
	if err != nil {
		err = fmt.Errorf("failed to get local registration ID: %w", err)
		zlog.Error().Err(err).Msg("")
		return 0, err
	}
	return uint32(regID.Int64), nil
}

func (s *SQLStore) SaveIdentityKey(address *libsignalgo.Address, identityKey *libsignalgo.IdentityKey, ctx context.Context) (bool, error) {
	trustLevel := "TRUSTED_UNVERIFIED" // TODO: this should be hard coded here
	serialized, err := identityKey.Serialize()
	if err != nil {
		zlog.Err(err).Msg("error serializing identityKey")
		return false, err
	}
	theirUuid, err := address.Name()
	if err != nil {
		zlog.Err(err).Msg("error getting theirUuid")
		return false, err
	}
	deviceId, err := address.DeviceID()
	if err != nil {
		zlog.Err(err).Msg("error getting deviceId")
		return false, err
	}
	oldKey, err := scanIdentityKey(s.db.QueryRow(getIdentityKeyQuery, s.ACI, theirUuid, deviceId))
	if err != nil {
		zlog.Err(err).Msg("error getting old identity key")
	}
	replacing := false
	if oldKey != nil {
		equal, err := oldKey.Equal(identityKey)
		if err != nil {
			zlog.Err(err).Msg("error comparing old and new identity keys")
		}
		// We are replacing the old key iff the old key exists and it is not equal to the new key
		replacing = !equal
	}
	_, err = s.db.Exec(insertIdentityKeyQuery, s.ACI, theirUuid, deviceId, serialized, trustLevel)
	if err != nil {
		zlog.Err(err).Msg("error inserting identity")
	}
	return replacing, err
}
func (s *SQLStore) IsTrustedIdentity(
	address *libsignalgo.Address,
	identityKey *libsignalgo.IdentityKey,
	direction libsignalgo.SignalDirection,
	ctx context.Context,
) (bool, error) {
	// TODO: this should check direction, and probably some other stuff (though whisperfish is pretty basic)
	theirUuid, err := address.Name()
	if err != nil {
		zlog.Err(err).Msg("error getting theirUuid")
		zlog.Info().Msg("RETURNING NOT TRUSTED")
		return false, err
	}
	deviceId, err := address.DeviceID()
	if err != nil {
		zlog.Err(err).Msg("error getting deviceId")
		zlog.Info().Msg("RETURNING NOT TRUSTED")
		return false, err
	}
	var trustLevel string
	err = s.db.QueryRow(getIdentityKeyTrustLevelQuery, s.ACI, theirUuid, deviceId).Scan(&trustLevel)
	// If no rows, they are a new identity, so trust by default
	if errors.Is(err, sql.ErrNoRows) {
		zlog.Info().Msg("no rows, TRUSTING BY DEFAULT")
		return true, nil
	} else if err != nil {
		zlog.Err(err).Msg("error getting trust level")
		zlog.Info().Msg("RETURNING NOT TRUSTED")
		return false, err
	}
	trusted := trustLevel == "TRUSTED_UNVERIFIED" || trustLevel == "TRUSTED_VERIFIED"
	if !trusted {
		zlog.Info().Msg("RETURNING NOT TRUSTED")
	}
	return trusted, nil
}

func (s *SQLStore) GetIdentityKey(address *libsignalgo.Address, ctx context.Context) (*libsignalgo.IdentityKey, error) {
	theirUuid, err := address.Name()
	if err != nil {
		zlog.Err(err).Msg("error getting theirUuid")
		return nil, err
	}
	deviceId, err := address.DeviceID()
	if err != nil {
		zlog.Err(err).Msg("error getting deviceId")
		return nil, err
	}
	key, err := scanIdentityKey(s.db.QueryRow(getIdentityKeyQuery, s.ACI, theirUuid, deviceId))
	if err != nil {
		zlog.Err(err).Msg("error getting identity key")
		return nil, err
	}
	return key, err
}
