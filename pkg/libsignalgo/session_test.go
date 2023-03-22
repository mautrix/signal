package libsignalgo_test

import (
	"context"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"go.mau.fi/mautrix-signal/pkg/libsignalgo"
)

func initializeSessions(t *testing.T, aliceStore, bobStore *InMemorySignalProtocolStore, bobAddress *libsignalgo.Address) {
	ctx := context.TODO()

	bobPreKey, err := libsignalgo.GeneratePrivateKey()
	assert.NoError(t, err)
	bobPreKeyPublicKey, err := bobPreKey.GetPublicKey()
	assert.NoError(t, err)

	bobSignedPreKey, err := libsignalgo.GeneratePrivateKey()
	assert.NoError(t, err)

	bobSignedPreKeyPublic, err := bobSignedPreKey.GetPublicKey()
	assert.NoError(t, err)
	bobSignedPreKeyPublicSerialized, err := bobSignedPreKeyPublic.Serialize()
	assert.NoError(t, err)

	bobIdentityKey, err := bobStore.GetIdentityKeyPair(ctx)
	assert.NoError(t, err)
	bobSignedPreKeySignature, err := bobIdentityKey.GetPrivateKey().Sign(bobSignedPreKeyPublicSerialized)
	assert.NoError(t, err)

	var prekeyID uint32 = 4570
	var signedPreKeyID uint32 = 3006

	bobRegistrationID, err := bobStore.GetLocalRegistrationID(ctx)
	assert.NoError(t, err)
	bobBundle, err := libsignalgo.NewPreKeyBundle(
		bobRegistrationID,
		9,
		prekeyID,
		bobPreKeyPublicKey,
		signedPreKeyID,
		bobSignedPreKeyPublic,
		bobSignedPreKeySignature,
		bobIdentityKey.GetPublicKey(),
	)
	assert.NoError(t, err)

	// Alice processes the bundle
	err = libsignalgo.ProcessPreKeyBundle(bobBundle, bobAddress, aliceStore, aliceStore, libsignalgo.NewCallbackContext(ctx))
	assert.NoError(t, err)

	record, err := aliceStore.LoadSession(bobAddress, ctx)
	assert.NoError(t, err)
	assert.NotNil(t, record)

	hasCurrentState, err := record.HasCurrentState()
	assert.NoError(t, err)
	assert.True(t, hasCurrentState)

	remoteRegistrationID, err := record.GetRemoteRegistrationID()
	assert.NoError(t, err)
	assert.Equal(t, bobRegistrationID, remoteRegistrationID)

	// Bob processes the bundle
	preKeyRecord, err := libsignalgo.NewPreKeyRecordFromPrivateKey(prekeyID, bobPreKey)
	assert.NoError(t, err)
	err = bobStore.StorePreKey(prekeyID, preKeyRecord, ctx)
	assert.NoError(t, err)

	signedPreKeyRecord, err := libsignalgo.NewSignedPreKeyRecordFromPrivateKey(signedPreKeyID, time.UnixMilli(42000), bobSignedPreKey, bobSignedPreKeySignature)
	err = bobStore.StoreSignedPreKey(signedPreKeyID, signedPreKeyRecord, ctx)
	assert.NoError(t, err)
}

// From SessionTests.swift:testSessionCipher
func TestSessionCipher(t *testing.T) {
	ctx := libsignalgo.NewEmptyCallbackContext()
	aliceAddress, err := libsignalgo.NewAddress("+14151111111", 1)
	assert.NoError(t, err)
	bobAddress, err := libsignalgo.NewAddress("+14151111112", 1)
	assert.NoError(t, err)

	aliceStore := NewInMemorySignalProtocolStore()
	bobStore := NewInMemorySignalProtocolStore()

	initializeSessions(t, aliceStore, bobStore, bobAddress)

	alicePlaintext := []byte{8, 6, 7, 5, 3, 0, 9}

	aliceCiphertext, err := libsignalgo.Encrypt(alicePlaintext, bobAddress, aliceStore, aliceStore, ctx)
	assert.NoError(t, err)
	aliceCiphertextMessageType, err := aliceCiphertext.MessageType()
	assert.NoError(t, err)
	assert.Equal(t, libsignalgo.CiphertextMessageTypePreKey, aliceCiphertextMessageType)

	aliceCiphertextSerialized, err := aliceCiphertext.Serialize()
	assert.NoError(t, err)
	bobCiphertext, err := libsignalgo.DeserializePreKeyMessage(aliceCiphertextSerialized)
	assert.NoError(t, err)
	bobPlaintext, err := libsignalgo.DecryptPreKey(bobCiphertext, aliceAddress, bobStore, bobStore, bobStore, bobStore, ctx)
	assert.NoError(t, err)
	assert.Equal(t, alicePlaintext, bobPlaintext)

	bobPlaintext2 := []byte{23}

	bobCiphertext2, err := libsignalgo.Encrypt(bobPlaintext2, aliceAddress, bobStore, bobStore, ctx)
	assert.NoError(t, err)
	bobCiphertext2MessageType, err := bobCiphertext2.MessageType()
	assert.NoError(t, err)
	assert.Equal(t, libsignalgo.CiphertextMessageTypeWhisper, bobCiphertext2MessageType)

	bobCiphertext2Serialized, err := bobCiphertext2.Serialize()
	assert.NoError(t, err)
	aliceCiphertext2, err := libsignalgo.DeserializeMessage(bobCiphertext2Serialized)
	assert.NoError(t, err)
	alicePlaintext2, err := libsignalgo.Decrypt(aliceCiphertext2, bobAddress, aliceStore, aliceStore, ctx)
	assert.NoError(t, err)
	assert.Equal(t, bobPlaintext2, alicePlaintext2)
}

// From SessionTests.swift:testSessionCipherWithBadStore
func TestSessionCipherWithBadStore(t *testing.T) {
	ctx := libsignalgo.NewEmptyCallbackContext()
	aliceAddress, err := libsignalgo.NewAddress("+14151111111", 1)
	assert.NoError(t, err)
	bobAddress, err := libsignalgo.NewAddress("+14151111112", 1)
	assert.NoError(t, err)

	aliceStore := NewInMemorySignalProtocolStore()
	bobStore := &BadInMemorySignalProtocolStore{NewInMemorySignalProtocolStore()}

	initializeSessions(t, aliceStore, bobStore.InMemorySignalProtocolStore, bobAddress)

	alicePlaintext := []byte{8, 6, 7, 5, 3, 0, 9}

	aliceCiphertext, err := libsignalgo.Encrypt(alicePlaintext, bobAddress, aliceStore, aliceStore, ctx)
	assert.NoError(t, err)
	aliceCiphertextMessageType, err := aliceCiphertext.MessageType()
	assert.NoError(t, err)
	assert.Equal(t, libsignalgo.CiphertextMessageTypePreKey, aliceCiphertextMessageType)

	aliceCiphertextSerialized, err := aliceCiphertext.Serialize()
	assert.NoError(t, err)
	bobCiphertext, err := libsignalgo.DeserializePreKeyMessage(aliceCiphertextSerialized)
	assert.NoError(t, err)
	_, err = libsignalgo.DecryptPreKey(bobCiphertext, aliceAddress, bobStore, bobStore, bobStore, bobStore, ctx)
	require.Error(t, err)
	assert.Equal(t, "Test error", err.Error())
}
