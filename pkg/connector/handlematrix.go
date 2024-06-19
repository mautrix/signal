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
	"time"

	"github.com/google/uuid"
	"github.com/rs/zerolog"
	"go.mau.fi/util/variationselector"
	"google.golang.org/protobuf/proto"
	"maunium.net/go/mautrix/bridgev2"
	"maunium.net/go/mautrix/bridgev2/database"
	"maunium.net/go/mautrix/bridgev2/networkid"

	"go.mau.fi/mautrix-signal/pkg/libsignalgo"
	"go.mau.fi/mautrix-signal/pkg/signalmeow"
	signalpb "go.mau.fi/mautrix-signal/pkg/signalmeow/protobuf"
)

func (s *SignalClient) sendMessage(ctx context.Context, portalID networkid.PortalID, content *signalpb.Content) (signalmeow.SendResult, error) {
	userID, groupID, err := s.parsePortalID(portalID)
	if err != nil {
		return nil, err
	}
	if groupID != "" {
		res, err := s.Client.SendGroupMessage(ctx, groupID, content)
		if err != nil {
			return nil, err
		}
		return res, nil
	} else {
		res := s.Client.SendMessage(ctx, userID, content)
		return &res, nil
	}
}

func (s *SignalClient) HandleMatrixMessage(ctx context.Context, msg *bridgev2.MatrixMessage) (message *bridgev2.MatrixMessageResponse, err error) {
	mcCtx := &msgconvContext{
		Connector: s.Main,
		Intent:    nil,
		Client:    s,
		Portal:    msg.Portal,
		ReplyTo:   msg.ReplyTo,
	}
	ctx = context.WithValue(ctx, msgconvContextKey, mcCtx)
	converted, err := s.Main.MsgConv.ToSignal(ctx, msg.Event, msg.Content, msg.OrigSender != nil)
	if err != nil {
		return nil, err
	}
	res, err := s.sendMessage(ctx, msg.Portal.ID, &signalpb.Content{DataMessage: converted})
	if err != nil {
		return nil, err
	}
	// TODO check result
	fmt.Println(res)
	dbMsg := &database.Message{
		ID:        makeMessageID(s.Client.Store.ACI, converted.GetTimestamp()),
		SenderID:  makeUserID(s.Client.Store.ACI),
		Timestamp: time.UnixMilli(int64(converted.GetTimestamp())),
	}
	dbMsg.Metadata.Extra = map[string]any{
		"contains_attachments": len(converted.Attachments) > 0,
	}
	if msg.ReplyTo != nil {
		dbMsg.RelatesToRowID = msg.ReplyTo.RowID
	}
	return &bridgev2.MatrixMessageResponse{
		DB: dbMsg,
	}, nil
}

func (s *SignalClient) HandleMatrixEdit(ctx context.Context, msg *bridgev2.MatrixEdit) error {
	_, targetSentTimestamp, err := parseMessageID(msg.EditTarget.ID)
	if err != nil {
		return fmt.Errorf("failed to parse target message ID: %w", err)
	} else if msg.EditTarget.SenderID != makeUserID(s.Client.Store.ACI) {
		return fmt.Errorf("cannot edit other people's messages")
	}
	mcCtx := &msgconvContext{
		Connector: s.Main,
		Intent:    nil,
		Client:    s,
		Portal:    msg.Portal,
	}
	if msg.EditTarget.RelatesToRowID != 0 {
		var err error
		mcCtx.ReplyTo, err = s.Main.Bridge.DB.Message.GetByRowID(ctx, msg.EditTarget.RelatesToRowID)
		if err != nil {
			return fmt.Errorf("failed to get message reply target: %w", err)
		}
	}
	ctx = context.WithValue(ctx, msgconvContextKey, mcCtx)
	converted, err := s.Main.MsgConv.ToSignal(ctx, msg.Event, msg.Content, msg.OrigSender != nil)
	if err != nil {
		return err
	}
	res, err := s.sendMessage(ctx, msg.Portal.ID, &signalpb.Content{EditMessage: &signalpb.EditMessage{
		TargetSentTimestamp: proto.Uint64(targetSentTimestamp),
		DataMessage:         converted,
	}})
	if err != nil {
		return err
	}
	// TODO check result
	fmt.Println(res)
	msg.EditTarget.ID = makeMessageID(s.Client.Store.ACI, converted.GetTimestamp())
	msg.EditTarget.Metadata.Extra["contains_attachments"] = len(converted.Attachments) > 0
	return nil
}

func (s *SignalClient) PreHandleMatrixReaction(ctx context.Context, msg *bridgev2.MatrixReaction) (bridgev2.MatrixReactionPreResponse, error) {
	return bridgev2.MatrixReactionPreResponse{
		SenderID: makeUserID(s.Client.Store.ACI),
		EmojiID:  "",
		Emoji:    variationselector.FullyQualify(msg.Content.RelatesTo.Key),
	}, nil
}

func (s *SignalClient) HandleMatrixReaction(ctx context.Context, msg *bridgev2.MatrixReaction) (reaction *database.Reaction, err error) {
	targetAuthorACI, targetSentTimestamp, err := parseMessageID(msg.TargetMessage.ID)
	if err != nil {
		return nil, fmt.Errorf("failed to parse target message ID: %w", err)
	}
	wrappedContent := &signalpb.Content{
		DataMessage: &signalpb.DataMessage{
			Timestamp:               proto.Uint64(uint64(msg.Event.Timestamp)),
			RequiredProtocolVersion: proto.Uint32(uint32(signalpb.DataMessage_REACTIONS)),
			Reaction: &signalpb.DataMessage_Reaction{
				Emoji:               proto.String(msg.PreHandleResp.Emoji),
				Remove:              proto.Bool(false),
				TargetAuthorAci:     proto.String(targetAuthorACI.String()),
				TargetSentTimestamp: proto.Uint64(targetSentTimestamp),
			},
		},
	}
	res, err := s.sendMessage(ctx, msg.Portal.ID, wrappedContent)
	if err != nil {
		return nil, err
	}
	// TODO check result
	fmt.Println(res)
	return &database.Reaction{}, nil
}

func (s *SignalClient) HandleMatrixReactionRemove(ctx context.Context, msg *bridgev2.MatrixReactionRemove) error {
	targetAuthorACI, targetSentTimestamp, err := parseMessageID(msg.TargetReaction.MessageID)
	if err != nil {
		return fmt.Errorf("failed to parse target message ID: %w", err)
	}
	wrappedContent := &signalpb.Content{
		DataMessage: &signalpb.DataMessage{
			Timestamp:               proto.Uint64(uint64(msg.Event.Timestamp)),
			RequiredProtocolVersion: proto.Uint32(uint32(signalpb.DataMessage_REACTIONS)),
			Reaction: &signalpb.DataMessage_Reaction{
				Emoji:               proto.String(msg.TargetReaction.Metadata.Emoji),
				Remove:              proto.Bool(true),
				TargetAuthorAci:     proto.String(targetAuthorACI.String()),
				TargetSentTimestamp: proto.Uint64(targetSentTimestamp),
			},
		},
	}
	res, err := s.sendMessage(ctx, msg.Portal.ID, wrappedContent)
	if err != nil {
		return err
	}
	// TODO check result
	fmt.Println(res)
	return nil
}

func (s *SignalClient) HandleMatrixMessageRemove(ctx context.Context, msg *bridgev2.MatrixMessageRemove) error {
	_, targetSentTimestamp, err := parseMessageID(msg.TargetMessage.ID)
	if err != nil {
		return fmt.Errorf("failed to parse target message ID: %w", err)
	} else if msg.TargetMessage.SenderID != makeUserID(s.Client.Store.ACI) {
		return fmt.Errorf("cannot delete other people's messages")
	}
	wrappedContent := &signalpb.Content{
		DataMessage: &signalpb.DataMessage{
			Timestamp: proto.Uint64(uint64(msg.Event.Timestamp)),
			Delete: &signalpb.DataMessage_Delete{
				TargetSentTimestamp: proto.Uint64(targetSentTimestamp),
			},
		},
	}
	res, err := s.sendMessage(ctx, msg.Portal.ID, wrappedContent)
	if err != nil {
		return err
	}
	// TODO check result
	fmt.Println(res)
	return nil
}

func (s *SignalClient) HandleMatrixReadReceipt(ctx context.Context, receipt *bridgev2.MatrixReadReceipt) error {
	if !receipt.ReadUpTo.After(receipt.LastRead) {
		return nil
	}
	if receipt.LastRead.IsZero() {
		receipt.LastRead = receipt.ReadUpTo.Add(-5 * time.Second)
	}
	dbMessages, err := s.Main.Bridge.DB.Message.GetMessagesBetweenTimeQuery(ctx, receipt.Portal.PortalKey, receipt.LastRead, receipt.ReadUpTo)
	if err != nil {
		return fmt.Errorf("failed to get messages to mark as read: %w", err)
	} else if len(dbMessages) == 0 {
		return nil
	}
	messagesToRead := map[uuid.UUID][]uint64{}
	for _, msg := range dbMessages {
		userID, timestamp, err := parseMessageID(msg.ID)
		if err != nil {
			return fmt.Errorf("failed to parse message ID %q: %w", msg.ID, err)
		}
		messagesToRead[userID] = append(messagesToRead[userID], timestamp)
	}
	zerolog.Ctx(ctx).Debug().
		Any("targets", messagesToRead).
		Msg("Collected read receipt target messages")

	// TODO send sync message manually containing all read receipts instead of a separate message for each recipient

	for destination, messages := range messagesToRead {
		// Don't send read receipts for own messages
		if destination == s.Client.Store.ACI {
			continue
		}
		// Don't use portal.sendSignalMessage because we're sending this straight to
		// who sent the original message, not the portal's ChatID
		ctx, cancel := context.WithTimeout(ctx, 10*time.Second)
		result := s.Client.SendMessage(ctx, libsignalgo.NewACIServiceID(destination), signalmeow.ReadReceptMessageForTimestamps(messages))
		cancel()
		if !result.WasSuccessful {
			zerolog.Ctx(ctx).Err(result.FailedSendResult.Error).
				Stringer("destination", destination).
				Uints64("message_ids", messages).
				Msg("Failed to send read receipt to Signal")
		} else {
			zerolog.Ctx(ctx).Debug().
				Stringer("destination", destination).
				Uints64("message_ids", messages).
				Msg("Sent read receipt to Signal")
		}
	}
	return nil
}

func (s *SignalClient) HandleMatrixTyping(ctx context.Context, typing *bridgev2.MatrixTyping) error {
	userID, _, err := s.parsePortalID(typing.Portal.ID)
	if err != nil {
		return err
	}
	// Only send typing notifications in DMs for now
	// Sending efficiently to groups requires implementing the proper SenderKey stuff first
	if !userID.IsEmpty() && userID.Type == libsignalgo.ServiceIDTypeACI {
		typingMessage := signalmeow.TypingMessage(typing.IsTyping)
		result := s.Client.SendMessage(ctx, userID, typingMessage)
		fmt.Println(result)
		// TODO check result
	}
	return nil
}
