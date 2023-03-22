package libsignalgo_test

import (
	"testing"

	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"

	"github.com/beeper/libsignalgo"
)

// From PublicAPITests.swift:testGroupCipher
func TestGroupCipher(t *testing.T) {
	ctx := libsignalgo.NewEmptyCallbackContext()
	sender, err := libsignalgo.NewAddress("+14159999111", 4)
	assert.NoError(t, err)

	distributionID, err := uuid.Parse("d1d1d1d1-7000-11eb-b32a-33b8a8a487a6")
	assert.NoError(t, err)

	aliceStore := NewInMemorySignalProtocolStore()

	skdm, err := libsignalgo.NewSenderKeyDistributionMessage(sender, distributionID, aliceStore, ctx)
	assert.NoError(t, err)

	serialized, err := skdm.Serialize()
	assert.NoError(t, err)

	skdmReloaded, err := libsignalgo.DeserializeSenderKeyDistributionMessage(serialized)
	assert.NoError(t, err)

	aliceCiphertextMessage, err := libsignalgo.GroupEncrypt([]byte{1, 2, 3}, sender, distributionID, aliceStore, ctx)
	assert.NoError(t, err)

	aliceCiphertext, err := aliceCiphertextMessage.Serialize()
	assert.NoError(t, err)

	bobStore := NewInMemorySignalProtocolStore()
	err = skdmReloaded.Process(sender, bobStore, ctx)
	assert.NoError(t, err)

	bobPtext, err := libsignalgo.GroupDecrypt(aliceCiphertext, sender, bobStore, ctx)
	assert.NoError(t, err)
	assert.Equal(t, []byte{1, 2, 3}, bobPtext)
}
