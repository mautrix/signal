package libsignalgo_test

import (
	"context"
	"testing"
	"time"

	"github.com/google/uuid"
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

	bobSignedPreKeyPublicKey, err := bobSignedPreKey.GetPublicKey()
	assert.NoError(t, err)
	bobSignedPreKeyPublicSerialized, err := bobSignedPreKeyPublicKey.Serialize()
	assert.NoError(t, err)

	bobIdentityKeyPair, err := bobStore.GetIdentityKeyPair(ctx)
	assert.NoError(t, err)
	bobSignedPreKeySignature, err := bobIdentityKeyPair.GetPrivateKey().Sign(bobSignedPreKeyPublicSerialized)
	assert.NoError(t, err)

	bobPublicIdentityKey := bobIdentityKeyPair.GetPublicKey()
	bobIdentityKey, err := libsignalgo.NewIdentityKeyFromPublicKey(bobPublicIdentityKey)
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
		bobSignedPreKeyPublicKey,
		bobSignedPreKeySignature,
		bobIdentityKey,
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
	assert.NoError(t, err)
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

// From SessionTests.swift:testSealedSenderSession
func TestSealedSenderSession(t *testing.T) {
	setupLogging()

	ctx := libsignalgo.NewEmptyCallbackContext()
	aliceAddress, err := libsignalgo.NewAddress("9d0652a3-dcc3-4d11-975f-74d61598733f", 1)
	assert.NoError(t, err)
	bobAddress, err := libsignalgo.NewAddress("6838237D-02F6-4098-B110-698253D15961", 1)
	assert.NoError(t, err)

	aliceStore := NewInMemorySignalProtocolStore()
	bobStore := NewInMemorySignalProtocolStore()

	initializeSessions(t, aliceStore, bobStore, bobAddress)

	trustRoot, err := libsignalgo.GenerateIdentityKeyPair()
	assert.NoError(t, err)
	serverKeys, err := libsignalgo.GenerateIdentityKeyPair()
	assert.NoError(t, err)
	serverCert, err := libsignalgo.NewServerCertificate(1, serverKeys.GetPublicKey(), trustRoot.GetPrivateKey())
	assert.NoError(t, err)
	aliceName, err := aliceAddress.Name()
	assert.NoError(t, err)
	senderAddress := libsignalgo.NewSealedSenderAddress("+14151111111", uuid.MustParse(aliceName), 1)

	aliceIdentityKeyPair, err := aliceStore.GetIdentityKeyPair(ctx.Ctx)
	require.NoError(t, err)
	senderCert, err := libsignalgo.NewSenderCertificate(senderAddress, aliceIdentityKeyPair.GetPublicKey(), time.UnixMilli(31337), serverCert, serverKeys.GetPrivateKey())
	assert.NoError(t, err)

	message := []byte("2020 vision")
	ciphertext, err := libsignalgo.SealedSenderEncryptPlaintext(message, bobAddress, senderCert, aliceStore, aliceStore, ctx)
	require.NoError(t, err)
	assert.NotNil(t, ciphertext)

	bobName, err := bobAddress.Name()
	require.NoError(t, err)
	recipientAddress := libsignalgo.NewSealedSenderAddress("", uuid.MustParse(bobName), 1)
	plaintext, err := libsignalgo.SealedSenderDecrypt(
		ciphertext,
		recipientAddress,
		trustRoot.GetPublicKey(),
		time.UnixMilli(31335),
		bobStore,
		bobStore,
		bobStore,
		bobStore,
		ctx,
	)
	require.NoError(t, err)
	assert.Equal(t, message, plaintext.Message)
	assert.Equal(t, senderAddress.DeviceID, plaintext.Sender.DeviceID)
	assert.Equal(t, senderAddress.E164, plaintext.Sender.E164)
	assert.Equal(t, senderAddress.UUID, plaintext.Sender.UUID)

	innerMessage, err := libsignalgo.Encrypt([]byte{}, bobAddress, aliceStore, aliceStore, ctx)
	require.NoError(t, err)

	hints := []libsignalgo.UnidentifiedSenderMessageContentHint{
		200,
		libsignalgo.UnidentifiedSenderMessageContentHintDefault,
		libsignalgo.UnidentifiedSenderMessageContentHintResendable,
		libsignalgo.UnidentifiedSenderMessageContentHintImplicit,
	}

	for _, hint := range hints {
		content, err := libsignalgo.NewUnidentifiedSenderMessageContent(
			innerMessage,
			senderCert,
			hint,
			[]byte{},
		)
		require.NoError(t, err)

		_, err = libsignalgo.SealedSenderEncrypt(content, bobAddress, aliceStore, ctx)
		require.NoError(t, err)

		// decryptedContent, err := libsignalgo.NewUnidentifiedSenderMessageContent(ciphertext)

		// let decryptedContent = try UnidentifiedSenderMessageContent(message: ciphertext,
		//                                                             identityStore: bob_store,
		//                                                             context: NullContext())
		// XCTAssertEqual(decryptedContent.contentHint, hint)
	}
}

// From SessionTests.swift:testArchiveSession
func TestArchiveSession(t *testing.T) {
	setupLogging()
	ctx := libsignalgo.NewEmptyCallbackContext()

	bobAddress, err := libsignalgo.NewAddress("+14151111112", 1)
	assert.NoError(t, err)

	aliceStore := NewInMemorySignalProtocolStore()
	bobStore := NewInMemorySignalProtocolStore()

	initializeSessions(t, aliceStore, bobStore, bobAddress)

	session, err := aliceStore.LoadSession(bobAddress, ctx.Ctx)
	assert.NoError(t, err)
	assert.NotNil(t, session)

	hasCurrentState, err := session.HasCurrentState()
	assert.NoError(t, err)
	assert.True(t, hasCurrentState)

	newIdentityKeyPair, err := libsignalgo.GenerateIdentityKeyPair()
	assert.NoError(t, err)
	matches, err := session.CurrentRatchetKeyMatches(newIdentityKeyPair.GetPublicKey())
	assert.NoError(t, err)
	assert.False(t, matches)

	err = session.ArchiveCurrentState()
	assert.NoError(t, err)

	hasCurrentState, err = session.HasCurrentState()
	assert.NoError(t, err)
	assert.False(t, hasCurrentState)
	newIdentityKeyPair, err = libsignalgo.GenerateIdentityKeyPair()
	assert.NoError(t, err)
	matches, err = session.CurrentRatchetKeyMatches(newIdentityKeyPair.GetPublicKey())
	assert.NoError(t, err)
	assert.False(t, matches)

	// A redundant archive shouldn't break anything.
	err = session.ArchiveCurrentState()
	assert.NoError(t, err)

	hasCurrentState, err = session.HasCurrentState()
	assert.NoError(t, err)
	assert.False(t, hasCurrentState)
}

// From SessionTests.swift:testSealedSenderGroupCipher
func TestSealedSenderGroupCipher(t *testing.T) {
	setupLogging()
	ctx := libsignalgo.NewEmptyCallbackContext()

	aliceAddress, err := libsignalgo.NewAddress("9d0652a3-dcc3-4d11-975f-74d61598733f", 1)
	assert.NoError(t, err)
	bobAddress, err := libsignalgo.NewAddress("6838237D-02F6-4098-B110-698253D15961", 1)
	assert.NoError(t, err)

	aliceStore := NewInMemorySignalProtocolStore()
	aliceIdentityKeyPair, err := aliceStore.GetIdentityKeyPair(ctx.Ctx)
	assert.NoError(t, err)

	bobStore := NewInMemorySignalProtocolStore()

	initializeSessions(t, aliceStore, bobStore, bobAddress)

	trustRoot, err := libsignalgo.GenerateIdentityKeyPair()
	assert.NoError(t, err)
	serverKeys, err := libsignalgo.GenerateIdentityKeyPair()
	assert.NoError(t, err)
	serverCert, err := libsignalgo.NewServerCertificate(1, serverKeys.GetPublicKey(), trustRoot.GetPrivateKey())
	assert.NoError(t, err)
	aliceName, err := aliceAddress.Name()
	assert.NoError(t, err)
	senderAddress := libsignalgo.NewSealedSenderAddress("+14151111111", uuid.MustParse(aliceName), 1)
	senderCert, err := libsignalgo.NewSenderCertificate(
		senderAddress,
		aliceIdentityKeyPair.GetPublicKey(),
		time.UnixMilli(31337),
		serverCert,
		serverKeys.GetPrivateKey(),
	)
	assert.NoError(t, err)

	distributionID := uuid.MustParse("d1d1d1d1-7000-11eb-b32a-33b8a8a487a6")

	skdm, err := libsignalgo.NewSenderKeyDistributionMessage(aliceAddress, distributionID, aliceStore, ctx)
	assert.NoError(t, err)
	skdmBytes, err := skdm.Serialize()
	assert.NoError(t, err)

	skdmR, err := libsignalgo.DeserializeSenderKeyDistributionMessage(skdmBytes)
	assert.NoError(t, err)

	err = libsignalgo.ProcessSenderKeyDistributionMessage(skdmR, aliceAddress, bobStore, ctx)
	assert.NoError(t, err)

	aMessage, err := libsignalgo.GroupEncrypt([]byte{1, 2, 3}, aliceAddress, distributionID, aliceStore, ctx)
	assert.NoError(t, err)

	aUSMC, err := libsignalgo.NewUnidentifiedSenderMessageContent(aMessage, senderCert, libsignalgo.UnidentifiedSenderMessageContentHintDefault, []byte{42})
	assert.NoError(t, err)

	aCtext, err := libsignalgo.SealedSenderMultiRecipientEncrypt(aUSMC, []*libsignalgo.Address{bobAddress}, aliceStore, aliceStore, ctx)
	assert.NoError(t, err)

	// TODO: finish
	assert.NotNil(t, aCtext)
}
