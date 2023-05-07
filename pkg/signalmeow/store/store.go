package store

import (
	"database/sql"
	"errors"
	"fmt"
	"log"

	"go.mau.fi/mautrix-signal/pkg/libsignalgo"
	"go.mau.fi/mautrix-signal/pkg/signalmeow/types"
)

type DeviceStore interface {
	SaveDeviceData(dd *types.DeviceData) error
	DeviceDataByAci(aciUuid string) (*types.DeviceData, error)
}

type PreKeyStore interface {
	PreKey(aciUuid string, uuidKind string, preKeyId int) (*libsignalgo.PreKeyRecord, error)
	SavePreKey(aciUuid string, uuidKind string, preKey *libsignalgo.PreKeyRecord) error
	RemovePreKey(aciUuid string, uuidKind string, preKeyId int) error
	SignedPreKey(aciUuid string, uuidKind string, preKeyId int) (*libsignalgo.PreKeyRecord, error)
	SaveSignedPreKey(aciUuid string, uuidKind string, preKey *libsignalgo.PreKeyRecord) error
	RemoveSignedPreKey(aciUuid string, uuidKind string, preKeyId int) error
}

// SQLStoreContainer is a wrapper for a SQL database that can contain multiple signalmeow sessions.
type SQLStoreContainer struct {
	db      *sql.DB
	dialect string
	log     log.Logger

	DatabaseErrorHandler func(device *types.DeviceData, action string, attemptIndex int, err error) (retry bool)
}

// New connects to the given SQL database and wraps it in a SQLStoreContainer.
// Only SQLite and Postgres are currently fully supported.
// The logger can be nil and will default to a no-op logger.
// When using SQLite, it's strongly recommended to enable foreign keys by adding `?_foreign_keys=true`:
//
//	container, err := sqlstore.New("sqlite3", "file:yoursqlitefile.db?_foreign_keys=on", nil)
func New(dialect, address string) (*SQLStoreContainer, error) {
	db, err := sql.Open(dialect, address)
	if err != nil {
		return nil, fmt.Errorf("failed to open database: %w", err)
	}
	container := NewWithDB(db, dialect)
	err = container.Upgrade()
	if err != nil {
		panic(err)
		return nil, fmt.Errorf("failed to upgrade database: %w", err)
	}
	return container, nil
}

// NewWithDB wraps an existing SQL connection in a SQLStoreContainer.
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
func NewWithDB(db *sql.DB, dialect string) *SQLStoreContainer {
	return &SQLStoreContainer{
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

func (c *SQLStoreContainer) scanDevice(row scannable) (*types.DeviceData, error) {
	var device types.DeviceData
	var aciIdentityKeyPair, pniIdentityKeyPair []byte

	err := row.Scan(
		&device.AciUuid, &aciIdentityKeyPair, &device.RegistrationId,
		&device.PniUuid, &pniIdentityKeyPair, &device.PniRegistrationId,
		&device.DeviceId, &device.Number, &device.Password,
	)
	device.AciIdentityKeyPair, err = libsignalgo.DeserializeIdentityKeyPair(aciIdentityKeyPair)
	device.PniIdentityKeyPair, err = libsignalgo.DeserializeIdentityKeyPair(pniIdentityKeyPair)
	if err != nil {
		return nil, fmt.Errorf("failed to scan session: %w", err)
	}

	return &device, nil
}

// GetAllDevices finds all the devices in the database.
func (c *SQLStoreContainer) GetAllDevices() ([]*types.DeviceData, error) {
	res, err := c.db.Query(getAllDevicesQuery)
	if err != nil {
		return nil, fmt.Errorf("failed to query sessions: %w", err)
	}
	sessions := make([]*types.DeviceData, 0)
	for res.Next() {
		sess, scanErr := c.scanDevice(res)
		if scanErr != nil {
			return sessions, scanErr
		}
		sessions = append(sessions, sess)
	}
	return sessions, nil
}

// GetDevice finds the device with the specified JID in the database.
// If the device is not found, nil is returned instead.
// Note that the parameter usually must be an AD-JID.
func (c *SQLStoreContainer) DeviceDataByAci(aciUuid string) (*types.DeviceData, error) {
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

// ErrDeviceIDMustBeSet is the error returned by PutDevice if you try to save a device before knowing its JID.
var ErrDeviceIDMustBeSet = errors.New("device aci_uuid must be known before accessing database")

// PutDevice stores the given device in this database. This should be called through Device.Save()
// (which usually doesn't need to be called manually, as the library does that automatically when relevant).
func (c *SQLStoreContainer) SaveDeviceData(device *types.DeviceData) error {
	if device.AciUuid == "" {
		return ErrDeviceIDMustBeSet
	}
	aciIdentityKeyPair, err := device.AciIdentityKeyPair.Serialize()
	pniIdentityKeyPair, err := device.PniIdentityKeyPair.Serialize()
	if err != nil {
		log.Printf("failed to serialize identity key pair: %v", err)
		return err
	}
	_, err = c.db.Exec(insertDeviceQuery,
		device.AciUuid, aciIdentityKeyPair, device.RegistrationId,
		device.PniUuid, pniIdentityKeyPair, device.PniRegistrationId,
		device.DeviceId, device.Number, device.Password,
	)
	return err
}

// DeleteDevice deletes the given device from this database. This should be called through Device.Delete()
func (c *SQLStoreContainer) DeleteDevice(device *types.DeviceData) error {
	if device.AciUuid == "" {
		return ErrDeviceIDMustBeSet
	}
	_, err := c.db.Exec(deleteDeviceQuery, device.AciUuid)
	return err
}

//
// Implementing "Store" interfaces
//

var _ DeviceStore = (*SQLStoreContainer)(nil) // Implemented above
var _ PreKeyStore = (*SQLStoreContainer)(nil)

// PreKeyStore interface
func (c *SQLStoreContainer) PreKey(aciUuid string, uuidKind string, preKeyId int) (*libsignalgo.PreKeyRecord, error) {
	panic("implement me")
	return nil, nil
}

func (c *SQLStoreContainer) SavePreKey(aciUuid string, uuidKind string, preKey *libsignalgo.PreKeyRecord) error {
	panic("implement me")
	return nil
}

func (c *SQLStoreContainer) RemovePreKey(aciUuid string, uuidKind string, preKeyId int) error {
	panic("implement me")
	return nil
}

func (c *SQLStoreContainer) SignedPreKey(aciUuid string, uuidKind string, preKeyId int) (*libsignalgo.PreKeyRecord, error) {
	panic("implement me")
	return nil, nil
}

func (c *SQLStoreContainer) SaveSignedPreKey(aciUuid string, uuidKind string, preKey *libsignalgo.PreKeyRecord) error {
	panic("implement me")
	return nil
}

func (c *SQLStoreContainer) RemoveSignedPreKey(aciUuid string, uuidKind string, preKeyId int) error {
	panic("implement me")
	return nil
}
