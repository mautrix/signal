package signalmeow

const (
	UUID_KIND_ACI = "aci"
	UUID_KIND_PNI = "pni"
)

type UUIDKind string

type GroupCredentials struct {
	Credentials []GroupCredential `json:"credentials"`
	Pni         string            `json:"pni"`
}
type GroupCredential struct {
	Credential     []byte
	RedemptionTime int64
}
type GroupExternalCredential struct {
	Token []byte `json:"token"`
}
