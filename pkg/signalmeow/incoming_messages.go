// mautrix-signal - A Matrix-signal puppeting bridge.
// Copyright (C) 2023 Scott Weber
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU Affero General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.
//
// This program is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
// GNU Affero General Public License for more details.
//
// You should have received a copy of the GNU Affero General Public License
// along with this program.  If not, see <https://www.gnu.org/licenses/>.

package signalmeow

import (
	signalpb "go.mau.fi/mautrix-signal/pkg/signalmeow/protobuf"
)

// Below is a lot of boilerplate to have a nice ADTish type for incoming Signal messages

type IncomingSignalMessageBase struct {
	// When uniquely identifiying a chat, use GroupID if it is not nil, otherwise use SenderUUID.
	SenderUUID    string                          // Always the UUID of the sender of the message
	RecipientUUID string                          // Usually our UUID, unless this is a message we sent on another device
	GroupID       *GroupIdentifier                // Unique identifier for the group chat, or nil for 1:1 chats
	Timestamp     uint64                          // With SenderUUID, treated as a unique identifier for a specific Signal message
	PartIndex     int                             //
	Quote         *IncomingSignalMessageQuoteData // If this message is a quote (reply), this will be non-nil
	ExpiresIn     int64                           // If this message is ephemeral, this will be non-zero (in seconds)
}

type IncomingSignalMessageQuoteData struct {
	QuotedTimestamp uint64
	QuotedSender    string
}

type IncomingSignalMessageType int

const (
	IncomingSignalMessageTypeUnhandled IncomingSignalMessageType = iota
	IncomingSignalMessageTypeText
	IncomingSignalMessageTypeAttachment
	IncomingSignalMessageTypeReaction
	IncomingSignalMessageTypeDelete
	IncomingSignalMessageTypeTyping
	IncomingSignalMessageTypeReceipt
	IncomingSignalMessageTypeSticker
	IncomingSignalMessageTypeCall
	IncomingSignalMessageTypeExpireTimerChange
	IncomingSignalMessageTypeGroupChange
	IncomingSignalMessageTypeContactChange
	IncomingSignalMessageTypeContactCard
)

type IncomingSignalMessage interface {
	MessageType() IncomingSignalMessageType
	Base() IncomingSignalMessageBase
}

// Ensure all of these types implement IncomingSignalMessage
var _ IncomingSignalMessage = IncomingSignalMessageUnhandled{}
var _ IncomingSignalMessage = IncomingSignalMessageText{}
var _ IncomingSignalMessage = IncomingSignalMessageAttachment{}
var _ IncomingSignalMessage = IncomingSignalMessageReaction{}
var _ IncomingSignalMessage = IncomingSignalMessageDelete{}
var _ IncomingSignalMessage = IncomingSignalMessageTyping{}
var _ IncomingSignalMessage = IncomingSignalMessageReceipt{}
var _ IncomingSignalMessage = IncomingSignalMessageSticker{}
var _ IncomingSignalMessage = IncomingSignalMessageCall{}
var _ IncomingSignalMessage = IncomingSignalMessageExpireTimerChange{}
var _ IncomingSignalMessage = IncomingSignalMessageGroupChange{}
var _ IncomingSignalMessage = IncomingSignalMessageContactChange{}
var _ IncomingSignalMessage = IncomingSignalMessageContactCard{}

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
	Content       string
	ContentRanges []*signalpb.BodyRange
}

func (IncomingSignalMessageText) MessageType() IncomingSignalMessageType {
	return IncomingSignalMessageTypeText
}
func (i IncomingSignalMessageText) Base() IncomingSignalMessageBase {
	return i.IncomingSignalMessageBase
}

// ** IncomingSignalMessageAttachment **
type IncomingSignalMessageAttachment struct {
	IncomingSignalMessageBase
	Caption     string
	Attachment  []byte
	Filename    string
	ContentType string
	Size        uint64
	Width       uint32
	Height      uint32
	BlurHash    string

	CaptionRanges []*signalpb.BodyRange
}

func (IncomingSignalMessageAttachment) MessageType() IncomingSignalMessageType {
	return IncomingSignalMessageTypeAttachment
}
func (i IncomingSignalMessageAttachment) Base() IncomingSignalMessageBase {
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

// ** IncomingSignalMessageExpireTimerChange **
type IncomingSignalMessageExpireTimerChange struct {
	IncomingSignalMessageBase
	NewExpireTimer uint32
}

func (IncomingSignalMessageExpireTimerChange) MessageType() IncomingSignalMessageType {
	return IncomingSignalMessageTypeExpireTimerChange
}
func (i IncomingSignalMessageExpireTimerChange) Base() IncomingSignalMessageBase {
	return i.IncomingSignalMessageBase
}

// ** IncomingSignalMessageGroupChange **
type IncomingSignalMessageGroupChange struct {
	IncomingSignalMessageBase
}

func (IncomingSignalMessageGroupChange) MessageType() IncomingSignalMessageType {
	return IncomingSignalMessageTypeGroupChange
}
func (i IncomingSignalMessageGroupChange) Base() IncomingSignalMessageBase {
	return i.IncomingSignalMessageBase
}

// ** IncomingSignalMessageContactChange **
type IncomingSignalMessageContactChange struct {
	IncomingSignalMessageBase
	Contact Contact
	Avatar  *ContactAvatar
}

func (IncomingSignalMessageContactChange) MessageType() IncomingSignalMessageType {
	return IncomingSignalMessageTypeContactChange
}
func (i IncomingSignalMessageContactChange) Base() IncomingSignalMessageBase {
	return i.IncomingSignalMessageBase
}

// ** IncomingSignalMessageContactCard **
// Note: a "contact card" has nothing to do with a Signal "contact"
// a "contact" (as in the ContactChange above) actually includes the user's UUID and such
// a "contact card" is just information about a person shared from another person, no UUIDs or anything
type IncomingSignalMessageContactCard struct {
	IncomingSignalMessageBase
	DisplayName  string
	PhoneNumbers []string
	Emails       []string
	Addresses    []string
	Organization string
}

func (IncomingSignalMessageContactCard) MessageType() IncomingSignalMessageType {
	return IncomingSignalMessageTypeContactCard
}
func (i IncomingSignalMessageContactCard) Base() IncomingSignalMessageBase {
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
