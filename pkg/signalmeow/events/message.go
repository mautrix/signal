package events

import (
	"github.com/google/uuid"

	signalpb "go.mau.fi/mautrix-signal/pkg/signalmeow/protobuf"
)

type MessageInfo struct {
	Sender uuid.UUID
	Chat   string
}

type Receipt struct {
	*signalpb.ReceiptMessage
}
