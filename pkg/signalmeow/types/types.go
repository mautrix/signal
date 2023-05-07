package types

import "go.mau.fi/mautrix-signal/pkg/libsignalgo"

type DeviceData struct {
	AciIdentityKeyPair *libsignalgo.IdentityKeyPair
	PniIdentityKeyPair *libsignalgo.IdentityKeyPair
	RegistrationId     int
	PniRegistrationId  int
	AciUuid            string
	PniUuid            string
	DeviceId           int
	Number             string
	Password           string
}

const (
	UUID_KIND_ACI = "aci"
	UUID_KIND_PNI = "pni"
)

type UUIDKind string
