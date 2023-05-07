package store

import (
	"database/sql"
	"errors"
	"fmt"
	"log"

	"go.mau.fi/mautrix-signal/pkg/libsignalgo"
	"go.mau.fi/mautrix-signal/pkg/signalmeow/types"
)

var _ DeviceStore = (*StoreContainer)(nil)

type DeviceStore interface {
	PutDevice(dd *types.DeviceData) error
	DeviceByAci(aciUuid string) (*Device, error)
}

// StoreContainer is a wrapper for a SQL database that can contain multiple signalmeow sessions.
type StoreContainer struct {
	db      *sql.DB
	dialect string
	log     log.Logger

	DatabaseErrorHandler func(device *types.DeviceData, action string, attemptIndex int, err error) (retry bool)
}

type Device struct {
	Data        types.DeviceData
	PreKeyStore PreKeyStore
}

// New connects to the given SQL database and wraps it in a StoreContainer.
// Only SQLite and Postgres are currently fully supported.
// The logger can be nil and will default to a no-op logger.
// When using SQLite, it's strongly recommended to enable foreign keys by adding `?_foreign_keys=true`:
//
//	container, err := sqlstore.New("sqlite3", "file:yoursqlitefile.db?_foreign_keys=on", nil)
func New(dialect, address string) (*StoreContainer, error) {
	db, err := sql.Open(dialect, address)
	if err != nil {
		return nil, fmt.Errorf("failed to open database: %w", err)
	}
	container := NewWithDB(db, dialect)
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
func NewWithDB(db *sql.DB, dialect string) *StoreContainer {
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
	device.PreKeyStore = innerStore

	return &device, nil
}

// GetAllDevices finds all the devices in the database.
func (c *StoreContainer) GetAllDevices() ([]*Device, error) {
	res, err := c.db.Query(getAllDevicesQuery)
	if err != nil {
		return nil, fmt.Errorf("failed to query sessions: %w", err)
	}
	sessions := make([]*Device, 0)
	for res.Next() {
		sess, scanErr := c.scanDevice(res)
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
func (c *StoreContainer) PutDevice(device *types.DeviceData) error {
	// TODO: if storing with same ACI UUID and device id, update instead of insert
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
func (c *StoreContainer) DeleteDevice(device *types.DeviceData) error {
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

var _ PreKeyStore = (*SQLStore)(nil)

type PreKeyStore interface {
	PreKey(uuidKind types.UUIDKind, preKeyId int) (*libsignalgo.PreKeyRecord, error)
	SavePreKey(uuidKind types.UUIDKind, preKey *libsignalgo.PreKeyRecord, markUploaded bool) error
	RemovePreKey(uuidKind types.UUIDKind, preKeyId int) error
	SignedPreKey(uuidKind types.UUIDKind, preKeyId int) (*libsignalgo.SignedPreKeyRecord, error)
	SaveSignedPreKey(uuidKind types.UUIDKind, preKey *libsignalgo.SignedPreKeyRecord, markUploaded bool) error
	RemoveSignedPreKey(uuidKind types.UUIDKind, preKeyId int) error
}

// PreKeyStore interface
const (
	getLastPreKeyIDQuery        = `SELECT MAX(key_id) FROM signalmeow_pre_keys WHERE aci_uuid=$1`
	insertPreKeyQuery           = `INSERT INTO signalmeow_pre_keys (aci_uuid, key_id, key, uploaded) VALUES ($1, $2, $3, $4)`
	getUnuploadedPreKeysQuery   = `SELECT key_id, key FROM signalmeow_pre_keys WHERE aci_uuid=$1 AND uploaded=false ORDER BY key_id LIMIT $2`
	getPreKeyQuery              = `SELECT key_id, key FROM signalmeow_pre_keys WHERE aci_uuid=$1 AND key_id=$2`
	deletePreKeyQuery           = `DELETE FROM signalmeow_pre_keys WHERE aci_uuid=$1 AND key_id=$2`
	markPreKeysAsUploadedQuery  = `UPDATE signalmeow_pre_keys SET uploaded=true WHERE aci_uuid=$1 AND key_id<=$2`
	getUploadedPreKeyCountQuery = `SELECT COUNT(*) FROM signalmeow_pre_keys WHERE aci_uuid=$1 AND uploaded=true`
)

func (c *SQLStore) PreKey(uuidKind types.UUIDKind, preKeyId int) (*libsignalgo.PreKeyRecord, error) {
	return nil, nil
}

func (s *SQLStore) getNextPreKeyID() (uint32, error) {
	var lastKeyID sql.NullInt32
	err := s.db.QueryRow(getLastPreKeyIDQuery, s.AciUuid).Scan(&lastKeyID)
	if err != nil {
		return 0, fmt.Errorf("failed to query next prekey ID: %w", err)
	}
	return uint32(lastKeyID.Int32) + 1, nil
}

func (c *SQLStore) SavePreKey(
	uuidKind types.UUIDKind,
	preKey *libsignalgo.PreKeyRecord,
	markUploaded bool) error {
	//	id, err := preKey.GetID()
	//	serialized, err := preKey.Serialize()
	//	if err != nil {
	//		return err
	//	}
	//	_, err = c.db.Exec(`
	//`)
	//
	return nil
}

func (c *SQLStore) RemovePreKey(uuidKind types.UUIDKind, preKeyId int) error {
	return nil
}

func (c *SQLStore) SignedPreKey(uuidKind types.UUIDKind, preKeyId int) (*libsignalgo.SignedPreKeyRecord, error) {
	return nil, nil
}

func (c *SQLStore) SaveSignedPreKey(uuidKind types.UUIDKind, preKey *libsignalgo.SignedPreKeyRecord, markUploaded bool) error {
	return nil
}

func (c *SQLStore) RemoveSignedPreKey(uuidKind types.UUIDKind, preKeyId int) error {
	return nil
}
