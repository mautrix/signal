package store

import (
	"context"
	"fmt"

	"github.com/google/uuid"
	"github.com/rs/zerolog"

	"go.mau.fi/mautrix-signal/pkg/libsignalgo"
)

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

type DeviceData struct {
	ACIIdentityKeyPair *libsignalgo.IdentityKeyPair
	PNIIdentityKeyPair *libsignalgo.IdentityKeyPair
	RegistrationID     int
	PNIRegistrationID  int
	ACI                uuid.UUID
	PNI                uuid.UUID
	DeviceID           int
	Number             string
	Password           string
}

func (d *DeviceData) BasicAuthCreds() (string, string) {
	username := fmt.Sprintf("%s.%d", d.ACI, d.DeviceID)
	password := d.Password
	return username, password
}

// Device is a wrapper for a signalmeow session, including device data,
// and interfaces for operating on the DB within the session.
type Device struct {
	DeviceData

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

func (d *Device) ClearDeviceKeys(ctx context.Context) error {
	// We need to clear out keys associated with the Signal device that no longer has valid credentials
	if d == nil {
		zerolog.Ctx(ctx).Warn().Msg("ClearDeviceKeys called with nil device")
		return nil
	}
	err := d.PreKeyStoreExtras.DeleteAllPreKeys(ctx)
	if err != nil {
		return err
	}
	err = d.SessionStoreExtras.RemoveAllSessions(ctx)
	return err
}

func (d *Device) IsDeviceLoggedIn() bool {
	return d != nil &&
		d.ACI != uuid.Nil &&
		d.DeviceID != 0 &&
		d.Password != ""
}

func (d *Device) ClearPassword(ctx context.Context) error {
	d.Password = ""
	return d.DeviceStore.PutDevice(ctx, &d.DeviceData)
}

func (d *Device) DeleteDevice(ctx context.Context) error {
	if err := d.DeviceStore.DeleteDevice(ctx, &d.DeviceData); err != nil {
		return err
	}
	d.ACI = uuid.Nil
	d.DeviceID = 0
	d.Password = ""
	return nil
}
