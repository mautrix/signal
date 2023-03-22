package libsignalgo_test

import (
	"testing"
	"time"

	"github.com/stretchr/testify/assert"

	"go.mau.fi/mautrix-signal/pkg/libsignalgo"
)

type Serializable interface {
	Serialize() ([]byte, error)
}

func testRoundTrip[T Serializable](t *testing.T, name string, obj T, deserializer func([]byte) (T, error)) {
	t.Run(name, func(t *testing.T) {
		serialized, err := obj.Serialize()
		assert.NoError(t, err)

		deserialized, err := deserializer(serialized)
		assert.NoError(t, err)

		deserializedSerialized, err := deserialized.Serialize()
		assert.NoError(t, err)

		assert.Equal(t, serialized, deserializedSerialized)
	})
}

// From PublicAPITests.swift:testSerializationRoundTrip
func TestSenderCertificateSerializationRoundTrip(t *testing.T) {
	keyPair, err := libsignalgo.GenerateIdentityKeyPair()
	assert.NoError(t, err)

	testRoundTrip(t, "key pair", keyPair, libsignalgo.DeserializeIdentityKeyPair)
	testRoundTrip(t, "public key", keyPair.GetPublicKey(), libsignalgo.DeserializePublicKey)
	testRoundTrip(t, "private key", keyPair.GetPrivateKey(), libsignalgo.DeserializePrivateKey)
	testRoundTrip(t, "identity key", keyPair.GetIdentityKey(), libsignalgo.NewIdentityKeyFromBytes)

	preKeyRecord, err := libsignalgo.NewPreKeyRecord(7, keyPair.GetPublicKey(), keyPair.GetPrivateKey())
	assert.NoError(t, err)
	testRoundTrip(t, "pre key record", preKeyRecord, libsignalgo.DeserializePreKeyRecord)

	publicKeySerialized, err := keyPair.GetPublicKey().Serialize()
	assert.NoError(t, err)
	signature, err := keyPair.GetPrivateKey().Sign(publicKeySerialized)
	assert.NoError(t, err)

	signedPreKeyRecord, err := libsignalgo.NewSignedPreKeyRecordFromPrivateKey(
		77,
		time.UnixMilli(42000),
		keyPair.GetPrivateKey(),
		signature,
	)
	assert.NoError(t, err)
	testRoundTrip(t, "signed pre key record", signedPreKeyRecord, libsignalgo.DeserializeSignedPreKeyRecord)
}
