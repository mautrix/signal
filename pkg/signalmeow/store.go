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

	"github.com/google/uuid"
	"go.mau.fi/util/dbutil"

	"go.mau.fi/mautrix-signal/pkg/libsignalgo"
	"go.mau.fi/mautrix-signal/pkg/signalmeow/upgrades"
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
	GroupStore         GroupStore
	ContactStore       ContactStore
	DeviceStore        DeviceStore
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

func (c *StoreContainer) Upgrade() error {
	return c.db.Upgrade()
}

func (c *StoreContainer) scanDevice(row dbutil.Scannable) (*Device, error) {
	var device Device
	deviceData := &device.Data
	var aciIdentityKeyPair, pniIdentityKeyPair []byte

	err := row.Scan(
		&deviceData.ACI, &aciIdentityKeyPair, &deviceData.RegistrationID,
		&deviceData.PNI, &pniIdentityKeyPair, &deviceData.PNIRegistrationID,
		&deviceData.DeviceID, &deviceData.Number, &deviceData.Password,
	)
	deviceData.ACIIdentityKeyPair, err = libsignalgo.DeserializeIdentityKeyPair(aciIdentityKeyPair)
	deviceData.PNIIdentityKeyPair, err = libsignalgo.DeserializeIdentityKeyPair(pniIdentityKeyPair)
	if err != nil {
		return nil, fmt.Errorf("failed to scan session: %w", err)
	}

	innerStore := newSQLStore(c, deviceData.ACI)
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
	rows, err := c.db.Conn(ctx).QueryContext(ctx, getAllDevicesQuery)
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
	sess, err := c.scanDevice(c.db.Conn(ctx).QueryRowContext(ctx, getDeviceQuery, aci))
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
	pniIdentityKeyPair, err := device.PNIIdentityKeyPair.Serialize()
	if err != nil {
		zlog.Err(err).Msg("failed to serialize identity key pair")
		return err
	}
	_, err = c.db.Conn(ctx).ExecContext(ctx, insertDeviceQuery,
		device.ACI, aciIdentityKeyPair, device.RegistrationID,
		device.PNI, pniIdentityKeyPair, device.PNIRegistrationID,
		device.DeviceID, device.Number, device.Password,
	)
	if err != nil {
		zlog.Err(err).Msg("failed to insert device")
	}
	return err
}

// DeleteDevice deletes the given device from this database
func (c *StoreContainer) DeleteDevice(ctx context.Context, device *DeviceData) error {
	if device.ACI == uuid.Nil {
		return ErrDeviceIDMustBeSet
	}
	_, err := c.db.Conn(ctx).ExecContext(ctx, deleteDeviceQuery, device.ACI)
	return err
}

func (d *Device) ClearDeviceKeys(ctx context.Context) error {
	// We need to clear out keys associated with the Signal device that no longer has valid credentials
	if d == nil {
		zlog.Warn().Msg("ClearDeviceKeys called with nil device")
		return nil
	}
	err := d.PreKeyStoreExtras.DeleteAllPreKeys(ctx)
	err = d.SessionStoreExtras.RemoveAllSessions(ctx)
	return err
}

func (d *Device) IsDeviceLoggedIn() bool {
	return d != nil &&
		d.Data.ACI != uuid.Nil &&
		d.Data.DeviceID != 0 &&
		d.Data.Password != ""
}

func (d *Device) ClearKeysAndDisconnect(ctx context.Context) error {
	// Essentially logout, clearing sessions and keys, and disconnecting websockets
	// but don't clear ACI UUID or profile keys or contacts, or anything else that
	// we can reuse if we reassociate with the same Signal account.
	// To fully "logout" delete the device from the database.
	clearErr := d.ClearDeviceKeys(ctx)
	d.Data.Password = ""
	saveDeviceErr := d.DeviceStore.PutDevice(ctx, &d.Data)
	stopLoopErr := StopReceiveLoops(d)

	if clearErr != nil {
		return clearErr
	}
	if saveDeviceErr != nil {
		return saveDeviceErr
	}
	return stopLoopErr
}

//
// Implementing "Store" interfaces
//

// SQLStore is basically a StoreContainer with an ACI UUID attached to it,
// reperesenting a store for a single user
type SQLStore struct {
	*StoreContainer
	ACI uuid.UUID
}

func newSQLStore(container *StoreContainer, aci uuid.UUID) *SQLStore {
	return &SQLStore{
		StoreContainer: container,
		ACI:            aci,
	}
}
