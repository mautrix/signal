package signalmeow

import (
	"database/sql"
	"errors"
	"fmt"

	"go.mau.fi/mautrix-signal/pkg/libsignalgo"
)

var _ DeviceStore = (*StoreContainer)(nil)

type DeviceStore interface {
	PutDevice(dd *DeviceData) error
	DeviceByAci(aciUuid string) (*Device, error)
}

// StoreContainer is a wrapper for a SQL database that can contain multiple signalmeow sessions.
type StoreContainer struct {
	db      *sql.DB
	dialect string

	DatabaseErrorHandler func(device *DeviceData, action string, attemptIndex int, err error) (retry bool)
}

// Device is a wrapper for a signalmeow session, including device data,
// and interfaces for operating on the DB within the session.
type Device struct {
	Data       DeviceData
	Connection DeviceConnection

	// NOTE: when adding a new store interface, make sure to assing it below
	// (search for "innerStore" further down in this file)

	// libsignalgo store interfaces
	PreKeyStore       libsignalgo.PreKeyStore
	SignedPreKeyStore libsignalgo.SignedPreKeyStore
	KyberPreKeyStore  libsignalgo.KyberPreKeyStore
	IdentityStore     libsignalgo.IdentityKeyStore
	SessionStore      libsignalgo.SessionStore
	SenderKeyStore    libsignalgo.SenderKeyStore

	// internal store interfaces
	PreKeyStoreExtras  PreKeyStoreExtras
	SessionStoreExtras SessionStoreExtras
	ProfileKeyStore    ProfileKeyStore
}

// New connects to the given SQL database and wraps it in a StoreContainer.
// Only SQLite and Postgres are currently fully supported.
// The logger can be nil and will default to a no-op logger.
// When using SQLite, it's strongly recommended to enable foreign keys by adding `?_foreign_keys=true`:
//
//	container, err := sqlstore.New("sqlite3", "file:yoursqlitefile.db?_foreign_keys=on", nil)
func NewStore(dialect, address string) (*StoreContainer, error) {
	db, err := sql.Open(dialect, address)
	if err != nil {
		return nil, fmt.Errorf("failed to open database: %w", err)
	}
	container := NewStoreWithDB(db, dialect)
	err = container.Upgrade()
	if err != nil {
		return nil, fmt.Errorf("failed to upgrade database: %w", err)
	}
	return container, nil
}

// NewWithDB wraps an existing SQL connection in a StoreContainer.
// Only SQLite and Postgres are currently fully supported.
// The logger can be nil and will default to a no-op logger.
// When using SQLite, it's strongly recommended to enable foreign keys by adding `?_foreign_keys=true`:
//
//	db, err := sql.Open("sqlite3", "file:yoursqlitefile.db?_foreign_keys=on")
//	if err != nil {
//	    panic(err)
//	}
//	container := sqlstore.NewWithDB(db, "sqlite3", nil)
//
// This method does not call Upgrade automatically like New does, so you must call it yourself:
//
//	container := sqlstore.NewWithDB(...)
//	err := container.Upgrade()
func NewStoreWithDB(db *sql.DB, dialect string) *StoreContainer {
	return &StoreContainer{
		db:      db,
		dialect: dialect,
	}
}

const getAllDevicesQuery = `
SELECT
	aci_uuid, aci_identity_key_pair, registration_id,
	pni_uuid, pni_identity_key_pair, pni_registration_id,
	device_id, number, password
FROM signalmeow_device
`

const getDeviceQuery = getAllDevicesQuery + " WHERE aci_uuid=$1"

type scannable interface {
	Scan(dest ...interface{}) error
}

func (c *StoreContainer) scanDevice(row scannable) (*Device, error) {
	var device Device
	deviceData := &device.Data
	var aciIdentityKeyPair, pniIdentityKeyPair []byte

	err := row.Scan(
		&deviceData.AciUuid, &aciIdentityKeyPair, &deviceData.RegistrationId,
		&deviceData.PniUuid, &pniIdentityKeyPair, &deviceData.PniRegistrationId,
		&deviceData.DeviceId, &deviceData.Number, &deviceData.Password,
	)
	deviceData.AciIdentityKeyPair, err = libsignalgo.DeserializeIdentityKeyPair(aciIdentityKeyPair)
	deviceData.PniIdentityKeyPair, err = libsignalgo.DeserializeIdentityKeyPair(pniIdentityKeyPair)
	if err != nil {
		return nil, fmt.Errorf("failed to scan session: %w", err)
	}

	innerStore := newSQLStore(c, deviceData.AciUuid)
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

	return &device, nil
}

// GetAllDevices finds all the devices in the database.
func (c *StoreContainer) GetAllDevices() ([]*Device, error) {
	rows, err := c.db.Query(getAllDevicesQuery)
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
func (c *StoreContainer) DeviceByAci(aciUuid string) (*Device, error) {
	sess, err := c.scanDevice(c.db.QueryRow(getDeviceQuery, aciUuid))
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
	`
	deleteDeviceQuery = `DELETE FROM signalmeow_device WHERE aci_uuid=$1`
)

// ErrDeviceIDMustBeSet is the error returned by PutDevice if you try to save a device before knowing its ACI UUID.
var ErrDeviceIDMustBeSet = errors.New("device aci_uuid must be known before accessing database")

// PutDevice stores the given device in this database.
func (c *StoreContainer) PutDevice(device *DeviceData) error {
	// TODO: if storing with same ACI UUID and device id, update instead of insert
	if device.AciUuid == "" {
		return ErrDeviceIDMustBeSet
	}
	aciIdentityKeyPair, err := device.AciIdentityKeyPair.Serialize()
	pniIdentityKeyPair, err := device.PniIdentityKeyPair.Serialize()
	if err != nil {
		zlog.Err(err).Msg("failed to serialize identity key pair")
		return err
	}
	_, err = c.db.Exec(insertDeviceQuery,
		device.AciUuid, aciIdentityKeyPair, device.RegistrationId,
		device.PniUuid, pniIdentityKeyPair, device.PniRegistrationId,
		device.DeviceId, device.Number, device.Password,
	)
	if err != nil {
		zlog.Err(err).Msg("failed to insert device")
	}
	return err
}

// DeleteDevice deletes the given device from this database
func (c *StoreContainer) DeleteDevice(device *DeviceData) error {
	if device.AciUuid == "" {
		return ErrDeviceIDMustBeSet
	}
	_, err := c.db.Exec(deleteDeviceQuery, device.AciUuid)
	return err
}

//
// Implementing "Store" interfaces
//

// SQLStore is basically a StoreContainer with an ACI UUID attached to it,
// reperesenting a store for a single user
type SQLStore struct {
	*StoreContainer
	AciUuid string
}

func newSQLStore(container *StoreContainer, aciUuid string) *SQLStore {
	return &SQLStore{
		StoreContainer: container,
		AciUuid:        aciUuid,
	}
}
