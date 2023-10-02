package signalmeow

// Below is a lot of boilerplate to have a nice ADTish type for incoming Signal messages

type IncomingSignalMessageBase struct {
	// When uniquely identifiying a chat, use GroupID if it is not nil, otherwise use SenderUUID.
	SenderUUID    string                             // Always the UUID of the sender of the message
	RecipientUUID string                             // Usually our UUID, unless this is a message we sent on another device
	GroupID       *GroupIdentifier                   // Unique identifier for the group chat, or nil for 1:1 chats
	Timestamp     uint64                             // With SenderUUID, treated as a unique identifier for a specific Signal message
	Quote         *IncomingSignalMessageQuoteData    // If this message is a quote (reply), this will be non-nil
	Mentions      []IncomingSignalMessageMentionData // If this message mentions other users, this will be len > 0
}

type IncomingSignalMessageQuoteData struct {
	QuotedTimestamp uint64
	QuotedSender    string
}

type IncomingSignalMessageMentionData struct {
	Start         uint32
	Length        uint32
	MentionedUUID string
	MentionedName string
}

type IncomingSignalMessageType int

const (
	IncomingSignalMessageTypeUnhandled IncomingSignalMessageType = iota
	IncomingSignalMessageTypeText
	IncomingSignalMessageTypeImage
	IncomingSignalMessageTypeReaction
	IncomingSignalMessageTypeDelete
	IncomingSignalMessageTypeTyping
	IncomingSignalMessageTypeReceipt
	IncomingSignalMessageTypeSticker
	IncomingSignalMessageTypeCall
)

type IncomingSignalMessage interface {
	MessageType() IncomingSignalMessageType
	Base() IncomingSignalMessageBase
}

// Ensure all of these types implement IncomingSignalMessage
var _ IncomingSignalMessage = IncomingSignalMessageUnhandled{}
var _ IncomingSignalMessage = IncomingSignalMessageText{}
var _ IncomingSignalMessage = IncomingSignalMessageImage{}
var _ IncomingSignalMessage = IncomingSignalMessageReaction{}
var _ IncomingSignalMessage = IncomingSignalMessageDelete{}
var _ IncomingSignalMessage = IncomingSignalMessageTyping{}
var _ IncomingSignalMessage = IncomingSignalMessageReceipt{}
var _ IncomingSignalMessage = IncomingSignalMessageSticker{}
var _ IncomingSignalMessage = IncomingSignalMessageCall{}

// ** IncomingSignalMessageUnhandled **
type IncomingSignalMessageUnhandled struct {
	IncomingSignalMessageBase
	Type   string
	Notice string
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
	Content string
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

// ** IncomingSignalMessageSticker
type IncomingSignalMessageSticker struct {
	IncomingSignalMessageBase
	ContentType string
	Width       uint32
	Height      uint32
	Sticker     []byte
	Filename    string
	Emoji       string
}

func (i IncomingSignalMessageSticker) MessageType() IncomingSignalMessageType {
	return IncomingSignalMessageTypeSticker
}

func (i IncomingSignalMessageSticker) Base() IncomingSignalMessageBase {
	return i.IncomingSignalMessageBase
}

// ** IncomingSignalMessageReaction **
type IncomingSignalMessageReaction struct {
	IncomingSignalMessageBase
	Emoji                  string
	Remove                 bool
	TargetAuthorUUID       string
	TargetMessageTimestamp uint64
}

func (IncomingSignalMessageReaction) MessageType() IncomingSignalMessageType {
	return IncomingSignalMessageTypeReaction
}
func (i IncomingSignalMessageReaction) Base() IncomingSignalMessageBase {
	return i.IncomingSignalMessageBase
}

// ** IncomingSignalMessageDelete **
type IncomingSignalMessageDelete struct {
	IncomingSignalMessageBase
	TargetMessageTimestamp uint64
}

func (IncomingSignalMessageDelete) MessageType() IncomingSignalMessageType {
	return IncomingSignalMessageTypeDelete
}
func (i IncomingSignalMessageDelete) Base() IncomingSignalMessageBase {
	return i.IncomingSignalMessageBase
}

// ** IncomingSignalMessageTyping **
type IncomingSignalMessageTyping struct {
	IncomingSignalMessageBase
	IsTyping bool
}

func (IncomingSignalMessageTyping) MessageType() IncomingSignalMessageType {
	return IncomingSignalMessageTypeTyping
}
func (i IncomingSignalMessageTyping) Base() IncomingSignalMessageBase {
	return i.IncomingSignalMessageBase
}

// ** IncomingSignalMessageCall **
type IncomingSignalMessageCall struct {
	IncomingSignalMessageBase
	IsRinging bool
}

func (IncomingSignalMessageCall) MessageType() IncomingSignalMessageType {
	return IncomingSignalMessageTypeCall
}
func (i IncomingSignalMessageCall) Base() IncomingSignalMessageBase {
	return i.IncomingSignalMessageBase
}

// ** IncomingSignalMessageReceipt **
type IncomingSignalMessageReceiptType int

const (
	IncomingSignalMessageReceiptTypeDelivery IncomingSignalMessageReceiptType = iota
	IncomingSignalMessageReceiptTypeRead
)

type IncomingSignalMessageReceipt struct {
	IncomingSignalMessageBase
	OriginalTimestamp uint64
	OriginalSender    string
	ReceiptType       IncomingSignalMessageReceiptType
}

func (IncomingSignalMessageReceipt) MessageType() IncomingSignalMessageType {
	return IncomingSignalMessageTypeReceipt
}
func (i IncomingSignalMessageReceipt) Base() IncomingSignalMessageBase {
	return i.IncomingSignalMessageBase
}
