package libsignalgo_test

import (
	"testing"

	"github.com/stretchr/testify/assert"

	"github.com/beeper/libsignalgo"
)

// From PublicAPITests.swift:testAddress
func TestAddress(t *testing.T) {
	setupLogging()

	addr, err := libsignalgo.NewAddress("addr1", 5)
	assert.NoError(t, err)

	name, err := addr.Name()
	assert.NoError(t, err)
	assert.Equal(t, "addr1", name)

	deviceID, err := addr.DeviceID()
	assert.NoError(t, err)
	assert.Equal(t, uint(5), deviceID)
}
