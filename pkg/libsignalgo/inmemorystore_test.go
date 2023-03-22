package libsignalgo_test

import (
	"context"
	"crypto/rand"
	"errors"
	"math/big"

	"github.com/google/uuid"
	"github.com/rs/zerolog/log"

	"go.mau.fi/mautrix-signal/pkg/libsignalgo"
)

type SenderKeyName struct {
	SenderName     string
	SenderDeviceID uint
	DistributionID uuid.UUID
}

type AddressKey struct {
	Name     string
	DeviceID uint
}

type InMemorySignalProtocolStore struct {
	privateKeys    *libsignalgo.IdentityKeyPair
	registrationID uint32

	identityKeyMap  map[AddressKey]*libsignalgo.IdentityKey
	preKeyMap       map[uint32]*libsignalgo.PreKeyRecord
	senderKeyMap    map[SenderKeyName]*libsignalgo.SenderKeyRecord
	sessionMap      map[AddressKey]*libsignalgo.SessionRecord
	signedPreKeyMap map[uint32]*libsignalgo.SignedPreKeyRecord
}

func NewInMemorySignalProtocolStore() *InMemorySignalProtocolStore {
	identityKeyPair, err := libsignalgo.GenerateIdentityKeyPair()
	if err != nil {
		panic(err)
	}

	registrationID, err := rand.Int(rand.Reader, big.NewInt(0x4000))
	if err != nil {
		panic(err)
	}

	return &InMemorySignalProtocolStore{
		privateKeys:    identityKeyPair,
		registrationID: uint32(registrationID.Uint64()),

		identityKeyMap:  make(map[AddressKey]*libsignalgo.IdentityKey),
		preKeyMap:       make(map[uint32]*libsignalgo.PreKeyRecord),
		senderKeyMap:    make(map[SenderKeyName]*libsignalgo.SenderKeyRecord),
		sessionMap:      make(map[AddressKey]*libsignalgo.SessionRecord),
		signedPreKeyMap: make(map[uint32]*libsignalgo.SignedPreKeyRecord),
	}
}

// Implementation of the SessionStore interface

func (ps *InMemorySignalProtocolStore) LoadSession(address *libsignalgo.Address, ctx context.Context) (*libsignalgo.SessionRecord, error) {
	log.Debug().Msg("LoadSession called")
	name, err := address.Name()
	if err != nil {
		return nil, err
	}
	deviceID, err := address.DeviceID()
	if err != nil {
		return nil, err
	}
	log.Debug().Interface("returning", ps.sessionMap[AddressKey{name, deviceID}]).Msg("LoadSession")
	return ps.sessionMap[AddressKey{name, deviceID}], nil
}

func (ps *InMemorySignalProtocolStore) StoreSession(address *libsignalgo.Address, record *libsignalgo.SessionRecord, ctx context.Context) error {
	log.Debug().Msg("StoreSession called")
	name, err := address.Name()
	if err != nil {
		return err
	}
	deviceID, err := address.DeviceID()
	if err != nil {
		return err
	}
	ps.sessionMap[AddressKey{name, deviceID}] = record
	return nil
}

// Implementation of the SenderKeyStore interface

func (ps *InMemorySignalProtocolStore) LoadSenderKey(sender libsignalgo.Address, distributionID uuid.UUID, ctx context.Context) (*libsignalgo.SenderKeyRecord, error) {
	log.Debug().Msg("LoadSenderKey called")
	name, err := sender.Name()
	if err != nil {
		return nil, err
	}
	deviceID, err := sender.DeviceID()
	if err != nil {
		return nil, err
	}
	return ps.senderKeyMap[SenderKeyName{name, deviceID, distributionID}], nil
}

func (ps *InMemorySignalProtocolStore) StoreSenderKey(sender libsignalgo.Address, distributionID uuid.UUID, record *libsignalgo.SenderKeyRecord, ctx context.Context) error {
	log.Debug().Msg("StoreSenderKey called")
	name, err := sender.Name()
	if err != nil {
		return err
	}
	deviceID, err := sender.DeviceID()
	if err != nil {
		return err
	}
	ps.senderKeyMap[SenderKeyName{name, deviceID, distributionID}] = record
	return nil
}

// Implementation of the IdentityKeyStore interface

func (ps *InMemorySignalProtocolStore) GetIdentityKeyPair(ctx context.Context) (*libsignalgo.IdentityKeyPair, error) {
	log.Debug().Msg("GetIdentityKeyPair called")
	return ps.privateKeys, nil
}

func (ps *InMemorySignalProtocolStore) GetLocalRegistrationID(ctx context.Context) (uint32, error) {
	log.Debug().Msg("GetLocalRegistrationID called")
	return ps.registrationID, nil
}

func (ps *InMemorySignalProtocolStore) SaveIdentityKey(address *libsignalgo.Address, identityKey *libsignalgo.IdentityKey, ctx context.Context) error {
	log.Debug().Msg("SaveIdentityKey called")
	name, err := address.Name()
	if err != nil {
		return err
	}
	deviceID, err := address.DeviceID()
	if err != nil {
		return err
	}
	ps.identityKeyMap[AddressKey{name, deviceID}] = identityKey
	return err
}
func (ps *InMemorySignalProtocolStore) GetIdentityKey(address *libsignalgo.Address, ctx context.Context) (*libsignalgo.IdentityKey, error) {
	log.Debug().Msg("GetIdentityKey called")
	name, err := address.Name()
	if err != nil {
		return nil, err
	}
	deviceID, err := address.DeviceID()
	if err != nil {
		return nil, err
	}
	return ps.identityKeyMap[AddressKey{name, deviceID}], nil
}

func (ps *InMemorySignalProtocolStore) IsTrustedIdentity(address *libsignalgo.Address, identityKey *libsignalgo.IdentityKey, direction libsignalgo.SignalDirection, ctx context.Context) (bool, error) {
	log.Debug().Msg("IsTrustedIdentity called")
	name, err := address.Name()
	if err != nil {
		return false, err
	}
	deviceID, err := address.DeviceID()
	if err != nil {
		return false, err
	}
	if ik, ok := ps.identityKeyMap[AddressKey{name, deviceID}]; ok {
		return ik.Equal(identityKey)
	} else {
		log.Trace().Msg("Trusting on first use")
		return true, nil // Trust on first use
	}
}

// Implementation of the PreKeyStore interface

func (ps *InMemorySignalProtocolStore) LoadPreKey(id uint32, ctx context.Context) (*libsignalgo.PreKeyRecord, error) {
	return ps.preKeyMap[id], nil
}

func (ps *InMemorySignalProtocolStore) StorePreKey(id uint32, preKeyRecord *libsignalgo.PreKeyRecord, ctx context.Context) error {
	ps.preKeyMap[id] = preKeyRecord
	return nil
}

func (ps *InMemorySignalProtocolStore) RemovePreKey(id uint32, ctx context.Context) error {
	delete(ps.preKeyMap, id)
	return nil
}

// Implementation of the SignedPreKeyStore interface

func (ps *InMemorySignalProtocolStore) LoadSignedPreKey(id uint32, ctx context.Context) (*libsignalgo.SignedPreKeyRecord, error) {
	return ps.signedPreKeyMap[id], nil
}

func (ps *InMemorySignalProtocolStore) StoreSignedPreKey(id uint32, signedPreKeyRecord *libsignalgo.SignedPreKeyRecord, ctx context.Context) error {
	ps.signedPreKeyMap[id] = signedPreKeyRecord
	return nil
}

type BadInMemorySignalProtocolStore struct {
	*InMemorySignalProtocolStore
}

func (ps *BadInMemorySignalProtocolStore) LoadPreKey(id uint32, ctx context.Context) (*libsignalgo.PreKeyRecord, error) {
	return nil, errors.New("Test error")
}
