package signalmeow

// Below is a lot of boilerplate to have a nice ADTish type for incoming messages

type IncomingSignalMessageBase struct {
	// When uniquely identifiying a chat, use GroupID if it is not nil, otherwise use SenderUUID.
	SenderUUID    string   // Always the UUID of the sender of the message
	RecipientUUID string   // Usually our UUID, unless this is a message we sent on another device
	GroupID       *GroupID // Unique identifier for the group chat, or nil for 1:1 chats
}

type IncomingSignalMessageType int

const (
	IncomingSignalMessageTypeUnhandled IncomingSignalMessageType = iota
	IncomingSignalMessageTypeText
	IncomingSignalMessageTypeImage
	IncomingSignalMessageTypeTyping
	IncomingSignalMessageTypeReceipt
)

type IncomingSignalMessage interface {
	MessageType() IncomingSignalMessageType
	Base() IncomingSignalMessageBase
}

// Ensure all of these types implement IncomingSignalMessage
var _ IncomingSignalMessage = IncomingSignalMessageUnhandled{}
var _ IncomingSignalMessage = IncomingSignalMessageText{}
var _ IncomingSignalMessage = IncomingSignalMessageImage{}
var _ IncomingSignalMessage = IncomingSignalMessageTyping{}
var _ IncomingSignalMessage = IncomingSignalMessageReceipt{}

// ** IncomingSignalMessageUnhandled **
type IncomingSignalMessageUnhandled struct {
	IncomingSignalMessageBase
	Timestamp uint64
	Type      string
	Notice    string
}

func (IncomingSignalMessageUnhandled) MessageType() IncomingSignalMessageType {
	return IncomingSignalMessageTypeUnhandled
}
func (i IncomingSignalMessageUnhandled) Base() IncomingSignalMessageBase {
	return i.IncomingSignalMessageBase
}

// ** IncomingSignalMessageText **
type IncomingSignalMessageText struct {
	IncomingSignalMessageBase
	Timestamp uint64
	Content   string
}

func (IncomingSignalMessageText) MessageType() IncomingSignalMessageType {
	return IncomingSignalMessageTypeText
}
func (i IncomingSignalMessageText) Base() IncomingSignalMessageBase {
	return i.IncomingSignalMessageBase
}

// ** IncomingSignalMessageImage **
type IncomingSignalMessageImage struct {
	IncomingSignalMessageBase
	Timestamp   uint64
	Caption     string
	Image       []byte
	Filename    string
	ContentType string
	Size        uint64
	Width       uint32
	Height      uint32
	BlurHash    string
}

func (IncomingSignalMessageImage) MessageType() IncomingSignalMessageType {
	return IncomingSignalMessageTypeImage
}
func (i IncomingSignalMessageImage) Base() IncomingSignalMessageBase {
	return i.IncomingSignalMessageBase
}

// ** IncomingSignalMessageTyping **
type IncomingSignalMessageTyping struct {
	IncomingSignalMessageBase
	Timestamp uint64
	IsTyping  bool
}

func (IncomingSignalMessageTyping) MessageType() IncomingSignalMessageType {
	return IncomingSignalMessageTypeTyping
}
func (i IncomingSignalMessageTyping) Base() IncomingSignalMessageBase {
	return i.IncomingSignalMessageBase
}

// ** IncomingSignalMessageReceipt **
type IncomingSignalMessageReceiptType int

const (
	IncomingSignalMessageReceiptTypeDelivery IncomingSignalMessageReceiptType = iota
	IncomingSignalMessageReceiptTypeRead
	IncomingSignalMessageReceiptTypeViewed
)

type IncomingSignalMessageReceipt struct {
	IncomingSignalMessageBase
	Timestamps  []uint64
	ReceiptType IncomingSignalMessageReceiptType
}

func (IncomingSignalMessageReceipt) MessageType() IncomingSignalMessageType {
	return IncomingSignalMessageTypeReceipt
}
func (i IncomingSignalMessageReceipt) Base() IncomingSignalMessageBase {
	return i.IncomingSignalMessageBase
}
