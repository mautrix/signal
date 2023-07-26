package signalmeow

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"log"

	"go.mau.fi/mautrix-signal/pkg/libsignalgo"
)

var _ libsignalgo.IdentityKeyStore = (*SQLStore)(nil)

const (
	getIdentityKeyPairQuery       = `SELECT aci_identity_key_pair FROM signalmeow_device WHERE aci_uuid=$1`
	getRegistrationLocalIDQuery   = `SELECT registration_id FROM signalmeow_device WHERE aci_uuid=$1`
	insertIdentityKeyQuery        = `INSERT OR REPLACE INTO signalmeow_identity_keys (our_aci_uuid, their_aci_uuid, their_device_id, key, trust_level) VALUES ($1, $2, $3, $4, $5)`
	getIdentityKeyTrustLevelQuery = `SELECT trust_level FROM signalmeow_identity_keys WHERE our_aci_uuid=$1 AND their_aci_uuid=$2 AND their_device_id=$3`
	getIdentityKeyQuery           = `SELECT key FROM signalmeow_identity_keys WHERE our_aci_uuid=$1 AND their_aci_uuid=$2 AND their_device_id=$3`
)

func scanIdentityKeyPair(row scannable) (*libsignalgo.IdentityKeyPair, error) {
	var keyPair []byte
	err := row.Scan(&keyPair)
	if errors.Is(err, sql.ErrNoRows) {
		log.Println("no identity key pair found")
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
		log.Println("no identity key found")
		return nil, nil
	} else if err != nil {
		return nil, err
	}
	return libsignalgo.DeserializeIdentityKey(key)
}

func (s *SQLStore) GetIdentityKeyPair(ctx context.Context) (*libsignalgo.IdentityKeyPair, error) {
	keyPair, err := scanIdentityKeyPair(s.db.QueryRow(getIdentityKeyPairQuery, s.AciUuid))
	if err != nil {
		log.Println("error getting identity key pair:", err)
		return nil, fmt.Errorf("failed to get identity key pair: %w", err)
	} else if keyPair == nil {
		log.Println("no identity key pair found")
		return nil, nil
	}
	return keyPair, nil
}

func (s *SQLStore) GetLocalRegistrationID(ctx context.Context) (uint32, error) {
	var regID sql.NullInt64
	err := s.db.QueryRow(getRegistrationLocalIDQuery, s.AciUuid).Scan(&regID)
	if err != nil {
		log.Println("error getting local registration ID:", err)
		return 0, fmt.Errorf("failed to get local registration ID: %w", err)
	}
	return uint32(regID.Int64), nil
}

func (s *SQLStore) SaveIdentityKey(address *libsignalgo.Address, identityKey *libsignalgo.IdentityKey, ctx context.Context) (bool, error) {
	trustLevel := "TRUSTED_UNVERIFIED" // TODO: this should be hard coded here
	serialized, err := identityKey.Serialize()
	if err != nil {
		log.Println("error serializing identityKey:", err)
		return false, err
	}
	theirUuid, err := address.Name()
	if err != nil {
		log.Println("error getting theirUuid:", err)
		return false, err
	}
	deviceId, err := address.DeviceID()
	if err != nil {
		log.Println("error getting deviceId:", err)
		return false, err
	}
	oldKey, err := scanIdentityKey(s.db.QueryRow(getIdentityKeyQuery, s.AciUuid, theirUuid, deviceId))
	if err != nil {
		log.Println("error getting old identity key:", err)
	}
	replacing := false
	if oldKey != nil {
		equal, err := oldKey.Equal(identityKey)
		if err != nil {
			log.Println("error comparing old and new identity keys:", err)
		}
		// We are replacing the old key iff the old key exists and it is not equal to the new key
		replacing = !equal
	}
	_, err = s.db.Exec(insertIdentityKeyQuery, s.AciUuid, theirUuid, deviceId, serialized, trustLevel)
	if err != nil {
		log.Println("error inserting identity:", err)
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
		log.Println("error getting theirUuid:", err)
		log.Println("RETURNING NOT TRUSTED")
		return false, err
	}
	deviceId, err := address.DeviceID()
	if err != nil {
		log.Println("error getting deviceId:", err)
		log.Println("RETURNING NOT TRUSTED")
		return false, err
	}
	var trustLevel string
	err = s.db.QueryRow(getIdentityKeyTrustLevelQuery, s.AciUuid, theirUuid, deviceId).Scan(&trustLevel)
	// If no rows, they are a new identity, so trust by default
	if errors.Is(err, sql.ErrNoRows) {
		log.Println("no rows, TRUSTING BY DEFAULT")
		return true, nil
	} else if err != nil {
		log.Println("error getting trust level:", err)
		log.Println("RETURNING NOT TRUSTED")
		return false, err
	}
	trusted := trustLevel == "TRUSTED_UNVERIFIED" || trustLevel == "TRUSTED_VERIFIED"
	if !trusted {
		log.Println("RETURNING NOT TRUSTED")
	}
	return trusted, nil
}

func (s *SQLStore) GetIdentityKey(address *libsignalgo.Address, ctx context.Context) (*libsignalgo.IdentityKey, error) {
	theirUuid, err := address.Name()
	if err != nil {
		log.Println("error getting theirUuid:", err)
		return nil, err
	}
	deviceId, err := address.DeviceID()
	if err != nil {
		log.Println("error getting deviceId:", err)
		return nil, err
	}
	key, err := scanIdentityKey(s.db.QueryRow(getIdentityKeyQuery, s.AciUuid, theirUuid, deviceId))
	if err != nil {
		log.Println("error getting identity key:", err)
		return nil, err
	}
	return key, err
}
