// mautrix-signal - A Matrix-signal puppeting bridge.
// Copyright (C) 2024 Tulir Asokan
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

package events

import (
	"github.com/google/uuid"

	signalpb "go.mau.fi/mautrix-signal/pkg/signalmeow/protobuf"
	"go.mau.fi/mautrix-signal/pkg/signalmeow/types"
)

type SignalEvent interface {
	isSignalEvent()
}

func (*ChatEvent) isSignalEvent()   {}
func (*Receipt) isSignalEvent()     {}
func (*ReadSelf) isSignalEvent()    {}
func (*Call) isSignalEvent()        {}
func (*ContactList) isSignalEvent() {}

type MessageInfo struct {
	Sender uuid.UUID
	ChatID string

	GroupRevision uint32
}

type ChatEvent struct {
	Info  MessageInfo
	Event signalpb.ChatEventContent
}

type Receipt struct {
	Sender  uuid.UUID
	Content *signalpb.ReceiptMessage
}

type ReadSelf struct {
	Messages []*signalpb.SyncMessage_Read
}

type Call struct {
	Info      MessageInfo
	Timestamp uint64
	IsRinging bool
}

type ContactList struct {
	Contacts []*types.Contact
}
