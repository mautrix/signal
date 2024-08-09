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
	"crypto/sha256"
	"errors"
	"fmt"
	"time"

	"github.com/google/uuid"
	"github.com/rs/zerolog"
	"go.mau.fi/util/variationselector"
	"google.golang.org/protobuf/proto"
	"maunium.net/go/mautrix/bridgev2"
	"maunium.net/go/mautrix/bridgev2/database"
	"maunium.net/go/mautrix/bridgev2/networkid"
	"maunium.net/go/mautrix/event"

	"go.mau.fi/mautrix-signal/pkg/libsignalgo"
	"go.mau.fi/mautrix-signal/pkg/signalid"
	"go.mau.fi/mautrix-signal/pkg/signalmeow"
	signalpb "go.mau.fi/mautrix-signal/pkg/signalmeow/protobuf"
)

func (s *SignalClient) sendMessage(ctx context.Context, portalID networkid.PortalID, content *signalpb.Content) error {
	userID, groupID, err := signalid.ParsePortalID(portalID)
	if err != nil {
		return err
	}
	if groupID != "" {
		result, err := s.Client.SendGroupMessage(ctx, groupID, content)
		if err != nil {
			return err
		}
		totalRecipients := len(result.FailedToSendTo) + len(result.SuccessfullySentTo)
		log := zerolog.Ctx(ctx).With().
			Int("total_recipients", totalRecipients).
			Int("failed_to_send_to_count", len(result.FailedToSendTo)).
			Int("successfully_sent_to_count", len(result.SuccessfullySentTo)).
			Logger()
		if len(result.FailedToSendTo) > 0 {
			log.Error().Msg("Failed to send event to some members of Signal group")
		}
		if len(result.SuccessfullySentTo) == 0 && len(result.FailedToSendTo) == 0 {
			log.Debug().Msg("No successes or failures - Probably sent to myself")
		} else if len(result.SuccessfullySentTo) == 0 {
			log.Error().Msg("Failed to send event to all members of Signal group")
			return errors.New("failed to send to any members of Signal group")

		} else if len(result.SuccessfullySentTo) < totalRecipients {
			log.Warn().Msg("Only sent event to some members of Signal group")
		} else {
			log.Debug().Msg("Sent event to all members of Signal group")
		}
		return nil
	} else {
		res := s.Client.SendMessage(ctx, userID, content)
		if !res.WasSuccessful {
			return res.Error
		}
		return nil
	}
}

func (s *SignalClient) HandleMatrixMessage(ctx context.Context, msg *bridgev2.MatrixMessage) (message *bridgev2.MatrixMessageResponse, err error) {
	converted, err := s.Main.MsgConv.ToSignal(ctx, s.Client, msg.Portal, msg.Event, msg.Content, msg.OrigSender != nil, msg.ReplyTo)
	if err != nil {
		return nil, err
	}
	err = s.sendMessage(ctx, msg.Portal.ID, &signalpb.Content{DataMessage: converted})
	if err != nil {
		return nil, err
	}
	dbMsg := &database.Message{
		ID:        signalid.MakeMessageID(s.Client.Store.ACI, converted.GetTimestamp()),
		SenderID:  signalid.MakeUserID(s.Client.Store.ACI),
		Timestamp: time.UnixMilli(int64(converted.GetTimestamp())),
		Metadata: &signalid.MessageMetadata{
			ContainsAttachments: len(converted.Attachments) > 0,
		},
	}
	return &bridgev2.MatrixMessageResponse{
		DB: dbMsg,
	}, nil
}

func (s *SignalClient) HandleMatrixEdit(ctx context.Context, msg *bridgev2.MatrixEdit) error {
	_, targetSentTimestamp, err := signalid.ParseMessageID(msg.EditTarget.ID)
	if err != nil {
		return fmt.Errorf("failed to parse target message ID: %w", err)
	} else if msg.EditTarget.SenderID != signalid.MakeUserID(s.Client.Store.ACI) {
		return fmt.Errorf("cannot edit other people's messages")
	}
	var replyTo *database.Message
	if msg.EditTarget.ReplyTo.MessageID != "" {
		replyTo, err = s.Main.Bridge.DB.Message.GetFirstOrSpecificPartByID(ctx, msg.Portal.Receiver, msg.EditTarget.ReplyTo)
		if err != nil {
			return fmt.Errorf("failed to get message reply target: %w", err)
		}
	}
	converted, err := s.Main.MsgConv.ToSignal(ctx, s.Client, msg.Portal, msg.Event, msg.Content, msg.OrigSender != nil, replyTo)
	if err != nil {
		return err
	}
	err = s.sendMessage(ctx, msg.Portal.ID, &signalpb.Content{EditMessage: &signalpb.EditMessage{
		TargetSentTimestamp: proto.Uint64(targetSentTimestamp),
		DataMessage:         converted,
	}})
	if err != nil {
		return err
	}
	msg.EditTarget.ID = signalid.MakeMessageID(s.Client.Store.ACI, converted.GetTimestamp())
	msg.EditTarget.Metadata = &signalid.MessageMetadata{ContainsAttachments: len(converted.Attachments) > 0}
	msg.EditTarget.EditCount++
	return nil
}

func (s *SignalClient) PreHandleMatrixReaction(ctx context.Context, msg *bridgev2.MatrixReaction) (bridgev2.MatrixReactionPreResponse, error) {
	return bridgev2.MatrixReactionPreResponse{
		SenderID: signalid.MakeUserID(s.Client.Store.ACI),
		EmojiID:  "",
		Emoji:    variationselector.FullyQualify(msg.Content.RelatesTo.Key),
	}, nil
}

func (s *SignalClient) HandleMatrixReaction(ctx context.Context, msg *bridgev2.MatrixReaction) (reaction *database.Reaction, err error) {
	targetAuthorACI, targetSentTimestamp, err := signalid.ParseMessageID(msg.TargetMessage.ID)
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
	err = s.sendMessage(ctx, msg.Portal.ID, wrappedContent)
	if err != nil {
		return nil, err
	}
	return &database.Reaction{}, nil
}

func (s *SignalClient) HandleMatrixReactionRemove(ctx context.Context, msg *bridgev2.MatrixReactionRemove) error {
	targetAuthorACI, targetSentTimestamp, err := signalid.ParseMessageID(msg.TargetReaction.MessageID)
	if err != nil {
		return fmt.Errorf("failed to parse target message ID: %w", err)
	}
	wrappedContent := &signalpb.Content{
		DataMessage: &signalpb.DataMessage{
			Timestamp:               proto.Uint64(uint64(msg.Event.Timestamp)),
			RequiredProtocolVersion: proto.Uint32(uint32(signalpb.DataMessage_REACTIONS)),
			Reaction: &signalpb.DataMessage_Reaction{
				Emoji:               proto.String(msg.TargetReaction.Emoji),
				Remove:              proto.Bool(true),
				TargetAuthorAci:     proto.String(targetAuthorACI.String()),
				TargetSentTimestamp: proto.Uint64(targetSentTimestamp),
			},
		},
	}
	err = s.sendMessage(ctx, msg.Portal.ID, wrappedContent)
	if err != nil {
		return err
	}
	return nil
}

func (s *SignalClient) HandleMatrixMessageRemove(ctx context.Context, msg *bridgev2.MatrixMessageRemove) error {
	_, targetSentTimestamp, err := signalid.ParseMessageID(msg.TargetMessage.ID)
	if err != nil {
		return fmt.Errorf("failed to parse target message ID: %w", err)
	} else if msg.TargetMessage.SenderID != signalid.MakeUserID(s.Client.Store.ACI) {
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
	err = s.sendMessage(ctx, msg.Portal.ID, wrappedContent)
	if err != nil {
		return err
	}
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
		userID, timestamp, err := signalid.ParseMessageID(msg.ID)
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
	userID, _, err := signalid.ParsePortalID(typing.Portal.ID)
	if err != nil {
		return err
	}
	// Only send typing notifications in DMs for now
	// Sending efficiently to groups requires implementing the proper SenderKey stuff first
	if !userID.IsEmpty() && userID.Type == libsignalgo.ServiceIDTypeACI {
		typingMessage := signalmeow.TypingMessage(typing.IsTyping)
		result := s.Client.SendMessage(ctx, userID, typingMessage)
		if !result.WasSuccessful {
			return result.Error
		}
	}
	return nil
}

func (s *SignalClient) handleMatrixRoomMeta(ctx context.Context, portal *bridgev2.Portal, gc *signalmeow.GroupChange, postUpdatePortal func()) (bool, error) {
	_, groupID, err := signalid.ParsePortalID(portal.ID)
	if err != nil || groupID == "" {
		return false, err
	}
	gc.Revision = portal.Metadata.(*signalid.PortalMetadata).Revision + 1
	revision, err := s.Client.UpdateGroup(ctx, gc, groupID)
	if err != nil {
		return false, err
	}
	if gc.ModifyTitle != nil {
		portal.Name = *gc.ModifyTitle
		portal.NameSet = true
	}
	if gc.ModifyDescription != nil {
		portal.Topic = *gc.ModifyDescription
		portal.TopicSet = true
	}
	if gc.ModifyAvatar != nil {
		portal.AvatarID = makeAvatarPathID(*gc.ModifyAvatar)
		portal.AvatarSet = true
	}
	if postUpdatePortal != nil {
		postUpdatePortal()
	}
	portal.Metadata.(*signalid.PortalMetadata).Revision = revision
	return true, nil
}

func (s *SignalClient) HandleMatrixRoomName(ctx context.Context, msg *bridgev2.MatrixRoomName) (bool, error) {
	return s.handleMatrixRoomMeta(ctx, msg.Portal, &signalmeow.GroupChange{
		ModifyTitle: &msg.Content.Name,
	}, nil)
}

func (s *SignalClient) HandleMatrixRoomAvatar(ctx context.Context, msg *bridgev2.MatrixRoomAvatar) (bool, error) {
	_, groupID, err := signalid.ParsePortalID(msg.Portal.ID)
	if err != nil || groupID == "" {
		return false, err
	}
	var avatarPath string
	var avatarHash [32]byte
	if msg.Content.URL != "" {
		data, err := s.Main.Bridge.Bot.DownloadMedia(ctx, msg.Content.URL, nil)
		if err != nil {
			return false, fmt.Errorf("failed to download avatar: %w", err)
		}
		avatarHash = sha256.Sum256(data)
		avatarPathPtr, err := s.Client.UploadGroupAvatar(ctx, data, groupID)
		if err != nil {
			return false, fmt.Errorf("failed to reupload avatar: %w", err)
		}
		avatarPath = *avatarPathPtr
	}
	return s.handleMatrixRoomMeta(ctx, msg.Portal, &signalmeow.GroupChange{
		ModifyAvatar: &avatarPath,
	}, func() {
		msg.Portal.AvatarMXC = msg.Content.URL
		msg.Portal.AvatarHash = avatarHash
	})
}

func (s *SignalClient) HandleMatrixRoomTopic(ctx context.Context, msg *bridgev2.MatrixRoomTopic) (bool, error) {
	return s.handleMatrixRoomMeta(ctx, msg.Portal, &signalmeow.GroupChange{
		ModifyDescription: &msg.Content.Topic,
	}, nil)
}

func (s *SignalClient) HandleMatrixMembership(ctx context.Context, msg *bridgev2.MatrixMembershipChange) (bool, error) {
	var targetIntent bridgev2.MatrixAPI
	var targetSignalID uuid.UUID
	var err error
	if msg.Portal.RoomType == database.RoomTypeDM {
		//TODO: this probably needs to revert some changes and clean up the portal on leaves
		switch msg.Type {
		case bridgev2.Invite:
			return false, fmt.Errorf("cannot invite additional user to dm")
		default:
			return false, nil
		}
	}
	if msg.TargetGhost != nil {
		targetIntent = msg.TargetGhost.Intent
		targetSignalID, err = signalid.ParseUserID(msg.TargetGhost.ID)
		if err != nil {
			return false, fmt.Errorf("failed to parse target ghost signal id: %w", err)
		}
	} else if msg.TargetUserLogin != nil {
		targetSignalID, err = signalid.ParseUserLoginID(msg.TargetUserLogin.ID)
		if err != nil {
			return false, fmt.Errorf("failed to parse target user signal id: %w", err)
		}
		targetIntent = msg.TargetUserLogin.User.DoublePuppet(ctx)
		if targetIntent == nil {
			ghost, err := s.Main.Bridge.GetGhostByID(ctx, networkid.UserID(msg.TargetUserLogin.ID))
			if err != nil {
				return false, fmt.Errorf("failed to get ghost for user: %w", err)
			}
			targetIntent = ghost.Intent
		}
	}
	log := zerolog.Ctx(ctx).With().
		Str("From Membership", string(msg.Type.From)).
		Str("To Membership", string(msg.Type.To)).
		Logger()
	gc := &signalmeow.GroupChange{}
	role := signalmeow.GroupMember_DEFAULT
	if msg.Type.To == event.MembershipInvite || msg.Type == bridgev2.AcceptKnock {
		levels, err := msg.Portal.Bridge.Matrix.GetPowerLevels(ctx, msg.Portal.MXID)
		if err != nil {
			log.Err(err).Msg("Couldn't get power levels")
			if levels.GetUserLevel(targetIntent.GetMXID()) >= 50 {
				role = signalmeow.GroupMember_ADMINISTRATOR
			}
		}
	}
	switch msg.Type {
	case bridgev2.AcceptInvite:
		gc.PromotePendingMembers = []*signalmeow.PromotePendingMember{{
			ACI: targetSignalID,
		}}
	case bridgev2.RevokeInvite, bridgev2.RejectInvite:
		deletePendingMember := libsignalgo.NewACIServiceID(targetSignalID)
		gc.DeletePendingMembers = []*libsignalgo.ServiceID{&deletePendingMember}
	case bridgev2.Leave, bridgev2.Kick:
		gc.DeleteMembers = []*uuid.UUID{&targetSignalID}
	case bridgev2.Invite:
		gc.AddMembers = []*signalmeow.AddMember{{
			GroupMember: signalmeow.GroupMember{
				ACI:  targetSignalID,
				Role: role,
			},
		}}
	// TODO: joining and knocking requires a way to obtain the invite link
	// because the joining/knocking member doesn't have the GroupMasterKey yet
	// case bridgev2.Join:
	// 	gc.AddMembers = []*signalmeow.AddMember{{
	// 		GroupMember: signalmeow.GroupMember{
	// 			ACI:  targetSignalID,
	// 			Role: role,
	// 		},
	// 		JoinFromInviteLink: true,
	// 	}}
	// case bridgev2.Knock:
	// 	gc.AddRequestingMembers = []*signalmeow.RequestingMember{{
	// 		ACI:       targetSignalID,
	// 		Timestamp: uint64(time.Now().UnixMilli()),
	// 	}}
	case bridgev2.AcceptKnock:
		gc.PromoteRequestingMembers = []*signalmeow.RoleMember{{
			ACI:  targetSignalID,
			Role: role,
		}}
	case bridgev2.RetractKnock, bridgev2.RejectKnock:
		gc.DeleteRequestingMembers = []*uuid.UUID{&targetSignalID}
	case bridgev2.BanKnocked, bridgev2.BanInvited, bridgev2.BanJoined, bridgev2.BanLeft:
		gc.AddBannedMembers = []*signalmeow.BannedMember{{
			ServiceID: libsignalgo.NewACIServiceID(targetSignalID),
			Timestamp: uint64(time.Now().UnixMilli()),
		}}
		switch msg.Type {
		case bridgev2.BanJoined:
			gc.DeleteMembers = []*uuid.UUID{&targetSignalID}
		case bridgev2.BanInvited:
			deletePendingMember := libsignalgo.NewACIServiceID(targetSignalID)
			gc.DeletePendingMembers = []*libsignalgo.ServiceID{&deletePendingMember}
		case bridgev2.BanKnocked:
			gc.DeleteRequestingMembers = []*uuid.UUID{&targetSignalID}
		}
	case bridgev2.Unban:
		unbanUser := libsignalgo.NewACIServiceID(targetSignalID)
		gc.DeleteBannedMembers = []*libsignalgo.ServiceID{&unbanUser}
	default:
		log.Debug().Msg("unsupported membership change")
		return false, nil
	}
	_, groupID, err := signalid.ParsePortalID(msg.Portal.ID)
	if err != nil || groupID == "" {
		return false, err
	}
	gc.Revision = msg.Portal.Metadata.(*signalid.PortalMetadata).Revision + 1
	revision, err := s.Client.UpdateGroup(ctx, gc, groupID)
	if err != nil {
		return false, err
	}
	if msg.Type == bridgev2.Invite {
		err = targetIntent.EnsureJoined(ctx, msg.Portal.MXID)
		if err != nil {
			return false, err
		}
	}
	msg.Portal.Metadata.(*signalid.PortalMetadata).Revision = revision
	return true, nil
}
