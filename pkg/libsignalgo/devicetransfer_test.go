package libsignalgo_test

import (
	"testing"

	"github.com/stretchr/testify/assert"

	"go.mau.fi/mautrix-signal/pkg/libsignalgo"
)

// From PublicAPITests.swift:testDeviceTransferKey
func TestDeviceTransferKey(t *testing.T) {
	deviceKey, err := libsignalgo.GenerateDeviceTransferKey()
	assert.NoError(t, err)

	/*
		Anything encoded in an ASN.1 SEQUENCE starts with 0x30 when encoded
		as DER. (This test could be better.)
	*/
	key := deviceKey.PrivateKeyMaterial()
	assert.Greater(t, len(key), 0)
	assert.EqualValues(t, 0x30, key[0])

	cert, err := deviceKey.GenerateCertificate("name", 30)
	assert.NoError(t, err)
	assert.Greater(t, len(cert), 0)
	assert.EqualValues(t, 0x30, cert[0])
}
