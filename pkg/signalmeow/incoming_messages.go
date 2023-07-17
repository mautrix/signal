package signalmeow

// Below is a lot of boilerplate to have a nice ADTish type for incoming messages

type IncomingSignalMessageType int

const (
	IncomingSignalMessageTypeText IncomingSignalMessageType = iota
	IncomingSignalMessageTypeTyping
	IncomingSignalMessageTypeReceipt
)

type IncomingSignalMessage interface {
	MessageType() IncomingSignalMessageType
}
type IncomingSignalMessageText struct {
	IncomingSignalMessageBase
	Timestamp uint64
	Content   string
}

func (IncomingSignalMessageText) MessageType() IncomingSignalMessageType {
	return IncomingSignalMessageTypeText
}

type IncomingSignalMessageTyping struct {
	IncomingSignalMessageBase
	Timestamp uint64
	IsTyping  bool
}

func (IncomingSignalMessageTyping) MessageType() IncomingSignalMessageType {
	return IncomingSignalMessageTypeTyping
}

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

type IncomingSignalMessageBase struct {
	// When uniquely identifiying a chat, use GroupID if it is not nil, otherwise use SenderUUID.
	SenderUUID string   // Always the UUID of the sender of the message
	GroupID    *GroupID // Unique identifier for the group chat, or nil for 1:1 chats
}
