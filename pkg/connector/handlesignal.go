// mautrix-signal - A Matrix-Signal puppeting bridge.
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

package connector

import (
	"context"
	"fmt"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/rs/zerolog"
	"go.mau.fi/util/exzerolog"
	"maunium.net/go/mautrix/bridgev2"
	"maunium.net/go/mautrix/bridgev2/database"
	"maunium.net/go/mautrix/bridgev2/networkid"
	"maunium.net/go/mautrix/bridgev2/simplevent"
	"maunium.net/go/mautrix/event"

	"go.mau.fi/mautrix-signal/pkg/signalid"
	"go.mau.fi/mautrix-signal/pkg/signalmeow/events"
	signalpb "go.mau.fi/mautrix-signal/pkg/signalmeow/protobuf"
)

func (s *SignalClient) handleSignalEvent(rawEvt events.SignalEvent) {
	switch evt := rawEvt.(type) {
	case *events.ChatEvent:
		s.Main.Bridge.QueueRemoteEvent(s.UserLogin, &Bv2ChatEvent{ChatEvent: evt, s: s})
	case *events.DecryptionError:
		s.Main.Bridge.QueueRemoteEvent(s.UserLogin, s.wrapDecryptionError(evt))
	case *events.Receipt:
		s.handleSignalReceipt(evt)
	case *events.ReadSelf:
		s.handleSignalReadSelf(evt)
	case *events.Call:
		s.Main.Bridge.QueueRemoteEvent(s.UserLogin, s.wrapCallEvent(evt))
	case *events.ContactList:
		s.handleSignalContactList(evt)
	case *events.ACIFound:
		s.handleSignalACIFound(evt)
	}
}

func (s *SignalClient) wrapCallEvent(evt *events.Call) bridgev2.RemoteMessage {
	return &simplevent.Message[*events.Call]{
		EventMeta: simplevent.EventMeta{
			Type: bridgev2.RemoteEventMessage,
			LogContext: func(c zerolog.Context) zerolog.Context {
				c = c.Stringer("sender_id", evt.Info.Sender)
				c = c.Uint64("message_ts", evt.Timestamp)
				return c
			},
			PortalKey:    s.makePortalKey(evt.Info.ChatID),
			CreatePortal: true,
			Sender:       s.makeEventSender(evt.Info.Sender),
			Timestamp:    time.UnixMilli(int64(evt.Timestamp)),
		},
		Data: evt,
		ID:   signalid.MakeMessageID(evt.Info.Sender, evt.Timestamp),

		ConvertMessageFunc: convertCallEvent,
	}
}

func convertCallEvent(ctx context.Context, portal *bridgev2.Portal, intent bridgev2.MatrixAPI, data *events.Call) (*bridgev2.ConvertedMessage, error) {
	content := &event.MessageEventContent{
		MsgType: event.MsgNotice,
	}
	if data.IsRinging {
		content.Body = "Incoming call"
		if userID, _, _ := signalid.ParsePortalID(portal.ID); !userID.IsEmpty() {
			content.MsgType = event.MsgText
		}
	} else {
		content.Body = "Call ended"
	}
	return &bridgev2.ConvertedMessage{
		Parts: []*bridgev2.ConvertedMessagePart{{
			Type:    event.EventMessage,
			Content: content,
		}},
	}, nil
}

func (s *SignalClient) wrapDecryptionError(evt *events.DecryptionError) bridgev2.RemoteMessage {
	return &simplevent.Message[*events.DecryptionError]{
		EventMeta: simplevent.EventMeta{
			Type: bridgev2.RemoteEventMessage,
			LogContext: func(c zerolog.Context) zerolog.Context {
				c = c.Stringer("sender_id", evt.Sender)
				return c
			},
			PortalKey:    s.makePortalKey(evt.Sender.String()),
			CreatePortal: true,
			Sender:       s.makeEventSender(evt.Sender),
			Timestamp:    time.UnixMilli(int64(evt.Timestamp)),
		},
		Data: evt,
		// TODO use main message id and edit it if it later becomes decryptable?
		ID: "decrypterr|" + signalid.MakeMessageID(evt.Sender, evt.Timestamp),

		ConvertMessageFunc: convertDecryptionError,
	}
}

func convertDecryptionError(_ context.Context, _ *bridgev2.Portal, _ bridgev2.MatrixAPI, _ *events.DecryptionError) (*bridgev2.ConvertedMessage, error) {
	return &bridgev2.ConvertedMessage{
		Parts: []*bridgev2.ConvertedMessagePart{{
			Type: event.EventMessage,
			Content: &event.MessageEventContent{
				MsgType: event.MsgNotice,
				Body:    "Message couldn't be decrypted. It may have been in this chat or a group chat. Please check your Signal app.",
			},
		}},
	}, nil
}

type Bv2ChatEvent struct {
	*events.ChatEvent
	s *SignalClient
}

var (
	_ bridgev2.RemoteMessage              = (*Bv2ChatEvent)(nil)
	_ bridgev2.RemoteEdit                 = (*Bv2ChatEvent)(nil)
	_ bridgev2.RemoteEventWithTimestamp   = (*Bv2ChatEvent)(nil)
	_ bridgev2.RemoteReaction             = (*Bv2ChatEvent)(nil)
	_ bridgev2.RemoteReactionRemove       = (*Bv2ChatEvent)(nil)
	_ bridgev2.RemoteMessageRemove        = (*Bv2ChatEvent)(nil)
	_ bridgev2.RemoteTyping               = (*Bv2ChatEvent)(nil)
	_ bridgev2.RemotePreHandler           = (*Bv2ChatEvent)(nil)
	_ bridgev2.RemoteChatInfoChange       = (*Bv2ChatEvent)(nil)
	_ bridgev2.RemoteEventWithStreamOrder = (*Bv2ChatEvent)(nil)
)

func (evt *Bv2ChatEvent) GetType() bridgev2.RemoteEventType {
	switch innerEvt := evt.Event.(type) {
	case *signalpb.DataMessage:
		switch {
		case innerEvt.Body != nil, innerEvt.Attachments != nil, innerEvt.Contact != nil, innerEvt.Sticker != nil,
			innerEvt.Payment != nil, innerEvt.GiftBadge != nil,
			innerEvt.GetRequiredProtocolVersion() > uint32(signalpb.DataMessage_CURRENT),
			innerEvt.GetFlags()&uint32(signalpb.DataMessage_EXPIRATION_TIMER_UPDATE) != 0:
			return bridgev2.RemoteEventMessage
		case innerEvt.Reaction != nil:
			if innerEvt.Reaction.GetRemove() {
				return bridgev2.RemoteEventReactionRemove
			}
			return bridgev2.RemoteEventReaction
		case innerEvt.Delete != nil:
			return bridgev2.RemoteEventMessageRemove
		case innerEvt.GetGroupV2().GetGroupChange() != nil:
			return bridgev2.RemoteEventChatInfoChange
		}
	case *signalpb.EditMessage:
		return bridgev2.RemoteEventEdit
	case *signalpb.TypingMessage:
		return bridgev2.RemoteEventTyping
	}
	return bridgev2.RemoteEventUnknown
}

func (evt *Bv2ChatEvent) GetChatInfoChange(ctx context.Context) (*bridgev2.ChatInfoChange, error) {
	dm, _ := evt.Event.(*signalpb.DataMessage)
	gv2 := dm.GetGroupV2()
	if gv2 == nil || gv2.GroupChange == nil {
		return nil, fmt.Errorf("GetChatInfoChange() called for non-GroupChange event")
	}
	groupChange, err := evt.s.Client.DecryptGroupChange(ctx, gv2)
	if err != nil {
		return nil, fmt.Errorf("failed to decrypt group change: %w", err)
	}
	return evt.s.groupChangeToChatInfoChange(ctx, gv2.GetRevision(), groupChange), nil
}

func (evt *Bv2ChatEvent) PreHandle(ctx context.Context, portal *bridgev2.Portal) {
	dataMsg, ok := evt.Event.(*signalpb.DataMessage)
	if !ok || dataMsg.GroupV2 == nil {
		return
	}
	portalRev := portal.Metadata.(*signalid.PortalMetadata).Revision
	if evt.Info.GroupRevision > portalRev {
		toRevision := evt.Info.GroupRevision
		if dataMsg.GetGroupV2().GetGroupChange() != nil {
			toRevision--
		}
		evt.s.catchUpGroup(ctx, portal, portalRev, toRevision, dataMsg.GetTimestamp())
	}
}

func (evt *Bv2ChatEvent) GetTimeout() time.Duration {
	if evt.Event.(*signalpb.TypingMessage).GetAction() == signalpb.TypingMessage_STARTED {
		return 15 * time.Second
	} else {
		return 0
	}
}

func (evt *Bv2ChatEvent) GetPortalKey() networkid.PortalKey {
	return evt.s.makePortalKey(evt.Info.ChatID)
}

func (evt *Bv2ChatEvent) ShouldCreatePortal() bool {
	return evt.GetType() == bridgev2.RemoteEventMessage || evt.GetType() == bridgev2.RemoteEventChatInfoChange
}

func (evt *Bv2ChatEvent) AddLogContext(c zerolog.Context) zerolog.Context {
	c = c.Stringer("sender_id", evt.Info.Sender)
	switch innerEvt := evt.Event.(type) {
	case *signalpb.DataMessage:
		c = c.Uint64("message_ts", innerEvt.GetTimestamp())
		switch {
		case innerEvt.Reaction != nil:
			c = c.Uint64("reaction_target_ts", innerEvt.Reaction.GetTargetSentTimestamp())
		case innerEvt.Delete != nil:
			c = c.Uint64("delete_target_ts", innerEvt.Delete.GetTargetSentTimestamp())
		}
	case *signalpb.EditMessage:
		c = c.
			Uint64("edit_target_ts", innerEvt.GetTargetSentTimestamp()).
			Uint64("edit_ts", innerEvt.GetDataMessage().GetTimestamp())
	}
	return c
}

func (evt *Bv2ChatEvent) GetSender() bridgev2.EventSender {
	return evt.s.makeEventSender(evt.Info.Sender)
}

func (evt *Bv2ChatEvent) GetID() networkid.MessageID {
	ts := evt.getDataMsgTimestamp()
	if ts == 0 {
		panic(fmt.Errorf("GetID() called for non-DataMessage event"))
	}
	return signalid.MakeMessageID(evt.Info.Sender, ts)
}

func (evt *Bv2ChatEvent) getDataMsgTimestamp() uint64 {
	switch innerEvt := evt.Event.(type) {
	case *signalpb.DataMessage:
		return innerEvt.GetTimestamp()
	case *signalpb.EditMessage:
		return innerEvt.GetDataMessage().GetTimestamp()
	default:
		return 0
	}
}

func (evt *Bv2ChatEvent) GetTimestamp() time.Time {
	ts := evt.getDataMsgTimestamp()
	if ts == 0 {
		return time.Now()
	}
	return time.UnixMilli(int64(ts))
}

func (evt *Bv2ChatEvent) GetTargetMessage() networkid.MessageID {
	var targetAuthorACI string
	var targetSentTS uint64
	switch innerEvt := evt.Event.(type) {
	case *signalpb.DataMessage:
		switch {
		case innerEvt.Reaction != nil:
			targetAuthorACI = innerEvt.Reaction.GetTargetAuthorAci()
			targetSentTS = innerEvt.Reaction.GetTargetSentTimestamp()
		case innerEvt.Delete != nil:
			targetSentTS = innerEvt.Delete.GetTargetSentTimestamp()
		default:
			panic(fmt.Errorf("GetTargetMessage() called for message type without target"))
		}
	case *signalpb.EditMessage:
		targetSentTS = innerEvt.GetTargetSentTimestamp()
	default:
		panic(fmt.Errorf("GetTargetMessage() called for message type without target"))
	}
	targetAuthorUUID := evt.Info.Sender
	if targetAuthorACI != "" {
		targetAuthorUUID, _ = uuid.Parse(targetAuthorACI)
	}
	return signalid.MakeMessageID(targetAuthorUUID, targetSentTS)
}

func (evt *Bv2ChatEvent) GetReactionEmoji() (string, networkid.EmojiID) {
	dataMsg, ok := evt.Event.(*signalpb.DataMessage)
	if !ok || dataMsg.Reaction == nil {
		panic(fmt.Errorf("GetReactionEmoji() called for non-reaction event"))
	}
	return dataMsg.GetReaction().GetEmoji(), ""
}

func (evt *Bv2ChatEvent) GetRemovedEmojiID() networkid.EmojiID {
	return ""
}

func (evt *Bv2ChatEvent) ConvertMessage(ctx context.Context, portal *bridgev2.Portal, intent bridgev2.MatrixAPI) (*bridgev2.ConvertedMessage, error) {
	dataMsg, ok := evt.Event.(*signalpb.DataMessage)
	if !ok {
		return nil, fmt.Errorf("ConvertMessage() called for non-DataMessage event")
	}
	converted := evt.s.Main.MsgConv.ToMatrix(ctx, evt.s.Client, portal, intent, dataMsg)
	if converted.Disappear.Type != "" {
		evtTS := evt.GetTimestamp()
		portal.UpdateDisappearingSetting(ctx, converted.Disappear, nil, evtTS, true, true)
		if evt.Info.Sender == evt.s.Client.Store.ACI {
			converted.Disappear.DisappearAt = evtTS.Add(converted.Disappear.Timer)
		}
	}
	return converted, nil
}

func (evt *Bv2ChatEvent) ConvertEdit(ctx context.Context, portal *bridgev2.Portal, intent bridgev2.MatrixAPI, existing []*database.Message) (*bridgev2.ConvertedEdit, error) {
	editMsg, ok := evt.Event.(*signalpb.EditMessage)
	if !ok {
		return nil, fmt.Errorf("ConvertEdit() called for non-EditMessage event")
	}
	// TODO tell converter about existing parts to avoid reupload?
	converted := evt.s.Main.MsgConv.ToMatrix(ctx, evt.s.Client, portal, intent, editMsg.GetDataMessage())
	// TODO can anything other than the text be edited?
	editPart := converted.Parts[len(converted.Parts)-1].ToEditPart(existing[len(existing)-1])
	editPart.Part.EditCount++
	editPart.Part.ID = signalid.MakeMessageID(evt.Info.Sender, editMsg.GetDataMessage().GetTimestamp())
	return &bridgev2.ConvertedEdit{
		ModifiedParts: []*bridgev2.ConvertedEditPart{editPart},
	}, nil
}

func (evt *Bv2ChatEvent) GetStreamOrder() int64 {
	return int64(evt.Info.ServerTimestamp)
}

type Bv2Receipt struct {
	Type   signalpb.ReceiptMessage_Type
	Chat   networkid.PortalKey
	Sender bridgev2.EventSender

	LastTS time.Time
	LastID networkid.MessageID
	IDs    []networkid.MessageID
}

func (b *Bv2Receipt) GetType() bridgev2.RemoteEventType {
	switch b.Type {
	case signalpb.ReceiptMessage_READ:
		return bridgev2.RemoteEventReadReceipt
	case signalpb.ReceiptMessage_DELIVERY:
		return bridgev2.RemoteEventDeliveryReceipt
	default:
		return bridgev2.RemoteEventUnknown
	}
}

func (b *Bv2Receipt) GetPortalKey() networkid.PortalKey {
	return b.Chat
}

func (b *Bv2Receipt) AddLogContext(c zerolog.Context) zerolog.Context {
	return c.
		Str("sender_id", string(b.Sender.Sender)).
		Stringer("receipt_type", b.Type).
		Array("message_ids", exzerolog.ArrayOfStrs(b.IDs))
}

func (b *Bv2Receipt) GetSender() bridgev2.EventSender {
	return b.Sender
}

func (b *Bv2Receipt) GetLastReceiptTarget() networkid.MessageID {
	return b.LastID
}

func (b *Bv2Receipt) GetReceiptTargets() []networkid.MessageID {
	return b.IDs
}

func (b *Bv2Receipt) GetReadUpTo() time.Time {
	return time.Time{}
}

var _ bridgev2.RemoteReceipt = (*Bv2Receipt)(nil)

func convertReceipts[T any](ctx context.Context, input []T, getMessageFunc func(ctx context.Context, msgID T) (*database.Message, error)) map[networkid.PortalKey]*Bv2Receipt {
	log := zerolog.Ctx(ctx)
	receipts := make(map[networkid.PortalKey]*Bv2Receipt)
	for _, msgID := range input {
		msg, err := getMessageFunc(ctx, msgID)
		if err != nil {
			log.Err(err).Any("message_id", msgID).Msg("Failed to get target message for receipt")
		} else if msg == nil {
			log.Debug().Any("message_id", msgID).Msg("Got receipt for unknown message")
		} else {
			receiptEvt, ok := receipts[msg.Room]
			if !ok {
				receiptEvt = &Bv2Receipt{Chat: msg.Room}
				receipts[msg.Room] = receiptEvt
			}
			receiptEvt.IDs = append(receiptEvt.IDs, msg.ID)
			if receiptEvt.LastTS.Before(msg.Timestamp) {
				receiptEvt.LastTS = msg.Timestamp
				receiptEvt.LastID = msg.ID
			}
		}
	}
	return receipts
}

func (s *SignalClient) dispatchReceipts(sender uuid.UUID, receiptType signalpb.ReceiptMessage_Type, receipts map[networkid.PortalKey]*Bv2Receipt) {
	evtSender := s.makeEventSender(sender)
	for chat, receiptEvt := range receipts {
		receiptEvt.Chat = chat
		receiptEvt.Sender = evtSender
		receiptEvt.Type = receiptType
		s.Main.Bridge.QueueRemoteEvent(s.UserLogin, receiptEvt)
	}
}

func (s *SignalClient) handleSignalReceipt(evt *events.Receipt) {
	log := s.UserLogin.Log.With().
		Str("action", "handle signal receipt").
		Stringer("sender_id", evt.Sender).
		Stringer("receipt_type", evt.Content.GetType()).
		Logger()
	ctx := log.WithContext(context.TODO())
	receipts := convertReceipts(ctx, evt.Content.Timestamp, func(ctx context.Context, msgTS uint64) (*database.Message, error) {
		return s.Main.Bridge.DB.Message.GetFirstPartByID(ctx, s.UserLogin.ID, signalid.MakeMessageID(s.Client.Store.ACI, msgTS))
	})
	s.dispatchReceipts(evt.Sender, evt.Content.GetType(), receipts)
}

func (s *SignalClient) handleSignalReadSelf(evt *events.ReadSelf) {
	log := s.UserLogin.Log.With().
		Str("action", "handle signal read self").
		Logger()
	ctx := log.WithContext(context.TODO())
	receipts := convertReceipts(ctx, evt.Messages, func(ctx context.Context, msgInfo *signalpb.SyncMessage_Read) (*database.Message, error) {
		aciUUID, err := uuid.Parse(msgInfo.GetSenderAci())
		if err != nil {
			return nil, err
		}
		return s.Main.Bridge.DB.Message.GetFirstPartByID(ctx, s.UserLogin.ID, signalid.MakeMessageID(aciUUID, msgInfo.GetTimestamp()))
	})
	s.dispatchReceipts(s.Client.Store.ACI, signalpb.ReceiptMessage_READ, receipts)
}

func (s *SignalClient) handleSignalACIFound(evt *events.ACIFound) {
	log := s.UserLogin.Log.With().
		Str("action", "handle aci found").
		Stringer("aci", evt.ACI).
		Stringer("pni", evt.PNI).
		Logger()
	ctx := log.WithContext(context.TODO())
	pniPortalKey := s.makeDMPortalKey(evt.PNI)
	aciPortalKey := s.makeDMPortalKey(evt.ACI)
	result, portal, err := s.Main.Bridge.ReIDPortal(ctx, pniPortalKey, aciPortalKey)
	if err != nil {
		log.Err(err).Msg("Failed to re-ID portal")
	} else if result == bridgev2.ReIDResultSourceReIDd || result == bridgev2.ReIDResultTargetDeletedAndSourceReIDd {
		// If the source portal is re-ID'd, we need to sync metadata and participants.
		// If the source is deleted, then it doesn't matter, any existing target will already be correct
		info, err := s.GetChatInfo(ctx, portal)
		if err != nil {
			log.Err(err).Msg("Failed to get chat info to update portal after re-ID")
		} else {
			portal.UpdateInfo(ctx, info, s.UserLogin, nil, time.Time{})
		}
	}
}

func (s *SignalClient) handleSignalContactList(evt *events.ContactList) {
	log := s.UserLogin.Log.With().Str("action", "handle contact list").Logger()
	ctx := log.WithContext(context.TODO())
	for _, contact := range evt.Contacts {
		if contact.ACI == uuid.Nil {
			continue
		}
		fullContact, err := s.Client.ContactByACI(ctx, contact.ACI)
		if err != nil {
			log.Err(err).Msg("Failed to get full contact info from store")
			continue
		}
		fullContact.ContactAvatar = contact.ContactAvatar
		ghost, err := s.Main.Bridge.GetGhostByID(ctx, signalid.MakeUserID(contact.ACI))
		if err != nil {
			log.Err(err).Msg("Failed to get ghost to update contact info")
			continue
		}
		ghost.UpdateInfo(ctx, s.contactToUserInfo(contact))
		if contact.ACI == s.Client.Store.ACI {
			s.updateRemoteProfile(ctx, true)
		}
	}
}

func (s *SignalClient) updateRemoteProfile(ctx context.Context, resendState bool) {
	var err error
	if s.Ghost == nil {
		s.Ghost, err = s.Main.Bridge.GetGhostByID(ctx, signalid.MakeUserID(s.Client.Store.ACI))
		if err != nil {
			zerolog.Ctx(ctx).Err(err).Msg("Failed to get ghost for remote profile update")
			return
		}
	}
	changed := false
	if s.UserLogin.RemoteProfile.Name != s.Ghost.Name {
		s.UserLogin.RemoteProfile.Name = s.Ghost.Name
		changed = true
	}
	if s.UserLogin.RemoteProfile.Avatar != s.Ghost.AvatarMXC {
		s.UserLogin.RemoteProfile.Avatar = s.Ghost.AvatarMXC
		changed = true
	}
	if len(s.Ghost.Identifiers) > 0 && strings.HasPrefix(s.Ghost.Identifiers[0], "tel:") {
		phone := strings.TrimPrefix(s.Ghost.Identifiers[0], "tel:")
		if s.UserLogin.RemoteProfile.Phone != phone {
			s.UserLogin.RemoteProfile.Phone = phone
			changed = true
		}
	}
	if changed {
		err = s.UserLogin.Save(ctx)
		if err != nil {
			zerolog.Ctx(ctx).Err(err).Msg("Failed to save updated remote profile")
		}
		if resendState {
			// TODO this has potential race conditions
			s.UserLogin.BridgeState.Send(s.UserLogin.BridgeState.GetPrevUnsent())
		}
	}
}
