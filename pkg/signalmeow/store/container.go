package store

import (
	"context"
	"database/sql"
	"errors"
	"fmt"

	"github.com/google/uuid"
	"github.com/rs/zerolog"
	"go.mau.fi/util/dbutil"

	"go.mau.fi/mautrix-signal/pkg/libsignalgo"
	"go.mau.fi/mautrix-signal/pkg/signalmeow/store/upgrades"
)

var _ DeviceStore = (*StoreContainer)(nil)

type DeviceStore interface {
	PutDevice(ctx context.Context, dd *DeviceData) error
	DeviceByACI(ctx context.Context, aci uuid.UUID) (*Device, error)
}

// StoreContainer is a wrapper for a SQL database that can contain multiple signalmeow sessions.
type StoreContainer struct {
	db *dbutil.Database
}

func NewStore(db *dbutil.Database, log dbutil.DatabaseLogger) *StoreContainer {
	return &StoreContainer{db: db.Child("signalmeow_version", upgrades.Table, log)}
}

const getAllDevicesQuery = `
SELECT
	aci_uuid, aci_identity_key_pair, registration_id,
	pni_uuid, pni_identity_key_pair, pni_registration_id,
	device_id, number, password
FROM signalmeow_device
`

const getDeviceQuery = getAllDevicesQuery + " WHERE aci_uuid=$1"

func (c *StoreContainer) Upgrade(ctx context.Context) error {
	return c.db.Upgrade(ctx)
}

func (c *StoreContainer) scanDevice(row dbutil.Scannable) (*Device, error) {
	var device Device
	var aciIdentityKeyPair, pniIdentityKeyPair []byte

	err := row.Scan(
		&device.ACI, &aciIdentityKeyPair, &device.RegistrationID,
		&device.PNI, &pniIdentityKeyPair, &device.PNIRegistrationID,
		&device.DeviceID, &device.Number, &device.Password,
	)
	if err != nil {
		return nil, fmt.Errorf("failed to scan session: %w", err)
	}
	device.ACIIdentityKeyPair, err = libsignalgo.DeserializeIdentityKeyPair(aciIdentityKeyPair)
	if err != nil {
		return nil, fmt.Errorf("failed to deserialize ACI identity key pair: %w", err)
	}
	device.PNIIdentityKeyPair, err = libsignalgo.DeserializeIdentityKeyPair(pniIdentityKeyPair)
	if err != nil {
		return nil, fmt.Errorf("failed to deserialize PNI identity key pair: %w", err)
	}

	innerStore := newSQLStore(c, device.ACI)
	// Assign innerStore to all the interfaces
	device.PreKeyStore = innerStore
	device.PreKeyStoreExtras = innerStore
	device.SignedPreKeyStore = innerStore
	device.KyberPreKeyStore = innerStore
	device.IdentityStore = innerStore
	device.SessionStore = innerStore
	device.SessionStoreExtras = innerStore
	device.ProfileKeyStore = innerStore
	device.SenderKeyStore = innerStore
	device.GroupStore = innerStore
	device.ContactStore = innerStore
	device.DeviceStore = innerStore

	return &device, nil
}

// GetAllDevices finds all the devices in the database.
func (c *StoreContainer) GetAllDevices(ctx context.Context) ([]*Device, error) {
	rows, err := c.db.Query(ctx, getAllDevicesQuery)
	if err != nil {
		return nil, fmt.Errorf("failed to query sessions: %w", err)
	}
	defer rows.Close()
	sessions := make([]*Device, 0)
	for rows.Next() {
		sess, scanErr := c.scanDevice(rows)
		if scanErr != nil {
			return sessions, scanErr
		}
		sessions = append(sessions, sess)
	}
	return sessions, nil
}

// GetDevice finds the device with the specified ACI UUID in the database.
// If the device is not found, nil is returned instead.
func (c *StoreContainer) DeviceByACI(ctx context.Context, aci uuid.UUID) (*Device, error) {
	sess, err := c.scanDevice(c.db.QueryRow(ctx, getDeviceQuery, aci))
	if errors.Is(err, sql.ErrNoRows) {
		return nil, nil
	}
	return sess, err
}

const (
	insertDeviceQuery = `
		INSERT INTO signalmeow_device (
			aci_uuid, aci_identity_key_pair, registration_id,
			pni_uuid, pni_identity_key_pair, pni_registration_id,
			device_id, number, password
		)
		VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9)
		ON CONFLICT (aci_uuid) DO UPDATE SET
			aci_identity_key_pair=excluded.aci_identity_key_pair,
			registration_id=excluded.registration_id,
			pni_uuid=excluded.pni_uuid,
			pni_identity_key_pair=excluded.pni_identity_key_pair,
			pni_registration_id=excluded.pni_registration_id,
			device_id=excluded.device_id,
			number=excluded.number,
			password=excluded.password
	`
	deleteDeviceQuery = `DELETE FROM signalmeow_device WHERE aci_uuid=$1`
)

// ErrDeviceIDMustBeSet is the error returned by PutDevice if you try to save a device before knowing its ACI UUID.
var ErrDeviceIDMustBeSet = errors.New("device aci_uuid must be known before accessing database")

// PutDevice stores the given device in this database.
func (c *StoreContainer) PutDevice(ctx context.Context, device *DeviceData) error {
	if device.ACI == uuid.Nil {
		return ErrDeviceIDMustBeSet
	}
	aciIdentityKeyPair, err := device.ACIIdentityKeyPair.Serialize()
	if err != nil {
		zerolog.Ctx(ctx).Err(err).Msg("failed to serialize aci identity key pair")
		return err
	}
	pniIdentityKeyPair, err := device.PNIIdentityKeyPair.Serialize()
	if err != nil {
		zerolog.Ctx(ctx).Err(err).Msg("failed to serialize pni identity key pair")
		return err
	}
	_, err = c.db.Exec(ctx, insertDeviceQuery,
		device.ACI, aciIdentityKeyPair, device.RegistrationID,
		device.PNI, pniIdentityKeyPair, device.PNIRegistrationID,
		device.DeviceID, device.Number, device.Password,
	)
	if err != nil {
		zerolog.Ctx(ctx).Err(err).Msg("failed to insert device")
	}
	return err
}

// DeleteDevice deletes the given device from this database
func (c *StoreContainer) DeleteDevice(ctx context.Context, device *DeviceData) error {
	if device.ACI == uuid.Nil {
		return ErrDeviceIDMustBeSet
	}
	_, err := c.db.Exec(ctx, deleteDeviceQuery, device.ACI)
	return err
}
