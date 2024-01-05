package types

const (
	// UUIDKindACI is the UUID kind for account identifiers.
	UUIDKindACI UUIDKind = "aci"
	// UUIDKindPNI is the UUID kind for phone number identifiers.
	UUIDKindPNI UUIDKind = "pni"
)

type UUIDKind string
