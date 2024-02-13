// mautrix-signal - A Matrix-signal puppeting bridge.
// Copyright (C) 2023 Scott Weber, Tulir Asokan
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

package main

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"net/http"
	"reflect"
	"strings"
	"sync"
	"time"

	"github.com/google/uuid"
	"github.com/rs/zerolog"
	"go.mau.fi/util/jsontime"
	"go.mau.fi/util/variationselector"
	"google.golang.org/protobuf/proto"
	"maunium.net/go/mautrix"
	"maunium.net/go/mautrix/appservice"
	"maunium.net/go/mautrix/bridge"
	"maunium.net/go/mautrix/bridge/bridgeconfig"
	"maunium.net/go/mautrix/bridge/status"
	"maunium.net/go/mautrix/event"
	"maunium.net/go/mautrix/id"

	"go.mau.fi/mautrix-signal/database"
	"go.mau.fi/mautrix-signal/msgconv"
	"go.mau.fi/mautrix-signal/msgconv/matrixfmt"
	"go.mau.fi/mautrix-signal/msgconv/signalfmt"
	"go.mau.fi/mautrix-signal/pkg/signalmeow"
	"go.mau.fi/mautrix-signal/pkg/signalmeow/events"
	signalpb "go.mau.fi/mautrix-signal/pkg/signalmeow/protobuf"
	"go.mau.fi/mautrix-signal/pkg/signalmeow/types"
)

func (br *SignalBridge) GetPortalByMXID(mxid id.RoomID) *Portal {
	br.portalsLock.Lock()
	defer br.portalsLock.Unlock()

	portal, ok := br.portalsByMXID[mxid]
	if !ok {
		dbPortal, err := br.DB.Portal.GetByMXID(context.TODO(), mxid)
		if err != nil {
			br.ZLog.Err(err).Msg("Failed to get portal from database")
			return nil
		}
		return br.loadPortal(context.TODO(), dbPortal, nil)
	}

	return portal
}

func (br *SignalBridge) GetPortalByChatID(key database.PortalKey) *Portal {
	br.portalsLock.Lock()
	defer br.portalsLock.Unlock()
	// If this PortalKey is for a group, Receiver should be empty
	if key.UserID() == uuid.Nil {
		key.Receiver = uuid.Nil
	}
	portal, ok := br.portalsByID[key]
	if !ok {
		dbPortal, err := br.DB.Portal.GetByChatID(context.TODO(), key)
		if err != nil {
			br.ZLog.Err(err).Msg("Failed to get portal from database")
			return nil
		}
		return br.loadPortal(context.TODO(), dbPortal, &key)
	}
	return portal
}

func (br *SignalBridge) GetAllPortalsWithMXID() []*Portal {
	portals, err := br.dbPortalsToPortals(br.DB.Portal.GetAllWithMXID(context.TODO()))
	if err != nil {
		br.ZLog.Err(err).Msg("Failed to get all portals with mxid")
		return nil
	}
	return portals
}

func (br *SignalBridge) FindPrivateChatPortalsWith(userID uuid.UUID) []*Portal {
	portals, err := br.dbPortalsToPortals(br.DB.Portal.FindPrivateChatsWith(context.TODO(), userID))
	if err != nil {
		br.ZLog.Err(err).Msg("Failed to get all DM portals with user")
		return nil
	}
	return portals
}

func (br *SignalBridge) GetAllIPortals() (iportals []bridge.Portal) {
	portals, err := br.dbPortalsToPortals(br.DB.Portal.GetAllWithMXID(context.TODO()))
	if err != nil {
		br.ZLog.Err(err).Msg("Failed to get all portals with mxid")
		return nil
	}
	iportals = make([]bridge.Portal, len(portals))
	for i, portal := range portals {
		iportals[i] = portal
	}
	return iportals
}

func (br *SignalBridge) loadPortal(ctx context.Context, dbPortal *database.Portal, key *database.PortalKey) *Portal {
	if dbPortal == nil {
		if key == nil {
			return nil
		}

		dbPortal = br.DB.Portal.New()
		dbPortal.PortalKey = *key
		err := dbPortal.Insert(ctx)
		if err != nil {
			br.ZLog.Err(err).Msg("Failed to insert new portal")
			return nil
		}
	}

	portal := br.NewPortal(dbPortal)

	br.portalsByID[portal.PortalKey] = portal
	if portal.MXID != "" {
		br.portalsByMXID[portal.MXID] = portal
	}

	return portal
}

func (br *SignalBridge) dbPortalsToPortals(dbPortals []*database.Portal, err error) ([]*Portal, error) {
	if err != nil {
		return nil, err
	}
	br.portalsLock.Lock()
	defer br.portalsLock.Unlock()

	output := make([]*Portal, len(dbPortals))
	for index, dbPortal := range dbPortals {
		if dbPortal == nil {
			continue
		}

		portal, ok := br.portalsByID[dbPortal.PortalKey]
		if !ok {
			portal = br.loadPortal(context.TODO(), dbPortal, nil)
		}

		output[index] = portal
	}

	return output, nil
}

type portalSignalMessage struct {
	evt  *events.ChatEvent
	user *User
}

type portalMatrixMessage struct {
	evt  *event.Event
	user *User
}

type Portal struct {
	*database.Portal

	MsgConv *msgconv.MessageConverter

	bridge *SignalBridge
	log    zerolog.Logger

	roomCreateLock sync.Mutex
	encryptLock    sync.Mutex

	signalMessages chan portalSignalMessage
	matrixMessages chan portalMatrixMessage

	currentlyTyping     []id.UserID
	currentlyTypingLock sync.Mutex

	relayUser *User
}

var signalFormatParams *signalfmt.FormatParams
var matrixFormatParams *matrixfmt.HTMLParser

func (br *SignalBridge) NewPortal(dbPortal *database.Portal) *Portal {
	log := br.ZLog.With().Str("chat_id", dbPortal.ChatID).Logger()
	if dbPortal.MXID != "" {
		log = log.With().Stringer("room_id", dbPortal.MXID).Logger()
	}

	portal := &Portal{
		Portal: dbPortal,
		bridge: br,
		log:    log,

		signalMessages: make(chan portalSignalMessage, br.Config.Bridge.PortalMessageBuffer),
		matrixMessages: make(chan portalMatrixMessage, br.Config.Bridge.PortalMessageBuffer),
	}
	portal.MsgConv = &msgconv.MessageConverter{
		PortalMethods:        portal,
		SignalFmtParams:      signalFormatParams,
		MatrixFmtParams:      matrixFormatParams,
		ConvertVoiceMessages: true,
		MaxFileSize:          br.MediaConfig.UploadSize,
	}
	go portal.messageLoop()

	return portal
}

func init() {
	event.TypeMap[event.StateBridge] = reflect.TypeOf(CustomBridgeInfoContent{})
	event.TypeMap[event.StateHalfShotBridge] = reflect.TypeOf(CustomBridgeInfoContent{})
}

var (
	_ bridge.Portal                    = (*Portal)(nil)
	_ bridge.ReadReceiptHandlingPortal = (*Portal)(nil)
	_ bridge.TypingPortal              = (*Portal)(nil)
	_ bridge.DisappearingPortal        = (*Portal)(nil)
	//_ bridge.MembershipHandlingPortal = (*Portal)(nil)
	//_ bridge.MetaHandlingPortal = (*Portal)(nil)
)

func (portal *Portal) IsEncrypted() bool {
	return portal.Encrypted
}

func (portal *Portal) MarkEncrypted() {
	portal.Encrypted = true
	err := portal.Update(context.TODO())
	if err != nil {
		portal.log.Err(err).Msg("Failed to update portal in database after marking as encrypted")
	}
}

func (portal *Portal) ReceiveMatrixEvent(user bridge.User, evt *event.Event) {
	if user.GetPermissionLevel() >= bridgeconfig.PermissionLevelUser || portal.HasRelaybot() {
		portal.matrixMessages <- portalMatrixMessage{user: user.(*User), evt: evt}
	}
}

func (portal *Portal) GetRelayUser() *User {
	if !portal.HasRelaybot() {
		return nil
	} else if portal.relayUser == nil {
		portal.relayUser = portal.bridge.GetUserByMXID(portal.RelayUserID)
	}
	return portal.relayUser
}

func (portal *Portal) IsPrivateChat() bool {
	return portal.UserID() != uuid.Nil
}

func (portal *Portal) IsNoteToSelf() bool {
	userID := portal.UserID()
	return userID != uuid.Nil && userID == portal.Receiver
}

func (portal *Portal) MainIntent() *appservice.IntentAPI {
	if portal.IsPrivateChat() {
		return portal.bridge.GetPuppetBySignalID(portal.UserID()).DefaultIntent()
	}

	return portal.bridge.Bot
}

type CustomBridgeInfoContent struct {
	event.BridgeEventContent
	RoomType string `json:"com.beeper.room_type,omitempty"`
}

func (portal *Portal) getBridgeInfo() (string, CustomBridgeInfoContent) {
	bridgeInfo := event.BridgeEventContent{
		BridgeBot: portal.bridge.Bot.UserID,
		Creator:   portal.MainIntent().UserID,
		Protocol: event.BridgeInfoSection{
			ID:          "signal",
			DisplayName: "Signal",
			AvatarURL:   portal.bridge.Config.AppService.Bot.ParsedAvatar.CUString(),
			ExternalURL: "https://signal.org/",
		},
		Channel: event.BridgeInfoSection{
			ID:          portal.ChatID,
			DisplayName: portal.Name,
			AvatarURL:   portal.AvatarURL.CUString(),
		},
	}
	bridgeInfoStateKey := fmt.Sprintf("fi.mau.signal://signal/%s", portal.ChatID)
	bridgeInfo.Channel.ExternalURL = fmt.Sprintf("https://signal.me/#p/%s", portal.ChatID)
	var roomType string
	if portal.IsPrivateChat() {
		roomType = "dm"
	}
	return bridgeInfoStateKey, CustomBridgeInfoContent{bridgeInfo, roomType}
}

func (portal *Portal) UpdateBridgeInfo(ctx context.Context) {
	if len(portal.MXID) == 0 {
		portal.log.Debug().Msg("Not updating bridge info: no Matrix room created")
		return
	}
	portal.log.Debug().Msg("Updating bridge info...")
	stateKey, content := portal.getBridgeInfo()
	_, err := portal.MainIntent().SendStateEvent(ctx, portal.MXID, event.StateBridge, stateKey, content)
	if err != nil {
		portal.log.Warn().Err(err).Msg("Failed to update m.bridge")
	}
	// TODO remove this once https://github.com/matrix-org/matrix-doc/pull/2346 is in spec
	_, err = portal.MainIntent().SendStateEvent(ctx, portal.MXID, event.StateHalfShotBridge, stateKey, content)
	if err != nil {
		portal.log.Warn().Err(err).Msg("Failed to update uk.half-shot.bridge")
	}
}

func (portal *Portal) messageLoop() {
	for {
		select {
		case msg := <-portal.matrixMessages:
			portal.handleMatrixMessages(msg)
		case msg := <-portal.signalMessages:
			portal.handleSignalMessage(msg)
		}
	}
}

func (portal *Portal) handleMatrixMessages(msg portalMatrixMessage) {
	log := portal.log.With().
		Str("action", "handle matrix event").
		Stringer("event_id", msg.evt.ID).
		Str("event_type", msg.evt.Type.String()).
		Logger()
	ctx := log.WithContext(context.TODO())

	switch msg.evt.Type {
	case event.EventMessage, event.EventSticker:
		portal.handleMatrixMessage(ctx, msg.user, msg.evt)
	case event.EventRedaction:
		portal.handleMatrixRedaction(ctx, msg.user, msg.evt)
	case event.EventReaction:
		portal.handleMatrixReaction(ctx, msg.user, msg.evt)
	default:
		log.Warn().Str("type", msg.evt.Type.Type).Msg("Unhandled matrix message type")
	}
}

func (portal *Portal) handleMatrixMessage(ctx context.Context, sender *User, evt *event.Event) {
	log := zerolog.Ctx(ctx)
	evtTS := time.UnixMilli(evt.Timestamp)
	timings := messageTimings{
		initReceive:  evt.Mautrix.ReceivedAt.Sub(evtTS),
		decrypt:      evt.Mautrix.DecryptionDuration,
		totalReceive: time.Since(evtTS),
	}
	implicitRRStart := time.Now()
	portal.handleMatrixReadReceipt(sender, "", uint64(evt.Timestamp), false)
	timings.implicitRR = time.Since(implicitRRStart)
	start := time.Now()

	messageAge := timings.totalReceive
	ms := metricSender{portal: portal, timings: &timings, ctx: ctx}
	log.Debug().
		Stringer("sender", evt.Sender).
		Dur("age", messageAge).
		Msg("Received message")

	errorAfter := portal.bridge.Config.Bridge.MessageHandlingTimeout.ErrorAfter
	deadline := portal.bridge.Config.Bridge.MessageHandlingTimeout.Deadline
	isScheduled, _ := evt.Content.Raw["com.beeper.scheduled"].(bool)
	if isScheduled {
		log.Debug().Msg("Message is a scheduled message, extending handling timeouts")
		errorAfter *= 10
		deadline *= 10
	}

	if errorAfter > 0 {
		remainingTime := errorAfter - messageAge
		if remainingTime < 0 {
			go ms.sendMessageMetrics(evt, errTimeoutBeforeHandling, "Timeout handling", true)
			return
		} else if remainingTime < 1*time.Second {
			log.Warn().
				Dur("remaining_time", remainingTime).
				Dur("max_timeout", errorAfter).
				Msg("Message was delayed before reaching the bridge")
		}
		go func() {
			time.Sleep(remainingTime)
			ms.sendMessageMetrics(evt, errMessageTakingLong, "Timeout handling", false)
		}()
	}

	if deadline > 0 {
		var cancel context.CancelFunc
		ctx, cancel = context.WithTimeout(ctx, deadline)
		defer cancel()
	}

	timings.preproc = time.Since(start)
	start = time.Now()

	content, ok := evt.Content.Parsed.(*event.MessageEventContent)
	if !ok {
		log.Error().Type("content_type", content).Msg("Unexpected parsed content type")
		go ms.sendMessageMetrics(evt, fmt.Errorf("%w %T", errUnexpectedParsedContentType, evt.Content.Parsed), "Error converting", true)
		return
	}

	realSenderMXID := sender.MXID
	isRelay := false
	if !sender.IsLoggedIn() {
		sender = portal.GetRelayUser()
		if sender == nil {
			go ms.sendMessageMetrics(evt, errUserNotLoggedIn, "Ignoring", true)
			return
		} else if !sender.IsLoggedIn() {
			go ms.sendMessageMetrics(evt, errRelaybotNotLoggedIn, "Ignoring", true)
			return
		}
		isRelay = true
	}

	var editTargetMsg *database.Message
	if editTarget := content.RelatesTo.GetReplaceID(); editTarget != "" {
		var err error
		editTargetMsg, err = portal.bridge.DB.Message.GetByMXID(ctx, editTarget)
		if err != nil {
			log.Err(err).Stringer("edit_target_mxid", editTarget).Msg("Failed to get edit target message")
			go ms.sendMessageMetrics(evt, errFailedToGetEditTarget, "Error converting", true)
			return
		} else if editTargetMsg == nil {
			log.Err(err).Stringer("edit_target_mxid", editTarget).Msg("Edit target message not found")
			go ms.sendMessageMetrics(evt, errEditUnknownTarget, "Error converting", true)
			return
		} else if editTargetMsg.Sender != sender.SignalID {
			go ms.sendMessageMetrics(evt, errEditDifferentSender, "Error converting", true)
			return
		}
		if content.NewContent != nil {
			content = content.NewContent
			evt.Content.Parsed = content
		}
	}

	relaybotFormatted := isRelay && portal.addRelaybotFormat(ctx, realSenderMXID, evt, content)
	if content.MsgType == event.MsgNotice && !portal.bridge.Config.Bridge.BridgeNotices {
		go ms.sendMessageMetrics(evt, errMNoticeDisabled, "Error converting", true)
		return
	}
	ctx = context.WithValue(ctx, msgconvContextKeyClient, sender.Client)
	msg, err := portal.MsgConv.ToSignal(ctx, evt, content, relaybotFormatted)
	if err != nil {
		log.Err(err).Msg("Failed to convert message")
		go ms.sendMessageMetrics(evt, err, "Error converting", true)
		return
	}
	var wrappedMsg *signalpb.Content
	if editTargetMsg == nil {
		wrappedMsg = &signalpb.Content{
			DataMessage: msg,
		}
	} else {
		wrappedMsg = &signalpb.Content{
			EditMessage: &signalpb.EditMessage{
				TargetSentTimestamp: proto.Uint64(editTargetMsg.Timestamp),
				DataMessage:         msg,
			},
		}
	}

	timings.convert = time.Since(start)
	start = time.Now()

	err = portal.sendSignalMessage(ctx, wrappedMsg, sender, evt.ID)

	timings.totalSend = time.Since(start)
	go ms.sendMessageMetrics(evt, err, "Error sending", true)
	if err == nil {
		if editTargetMsg != nil {
			err = editTargetMsg.SetTimestamp(ctx, msg.GetTimestamp())
			if err != nil {
				log.Err(err).Msg("Failed to update message timestamp in database after editing")
			}
		} else {
			portal.storeMessageInDB(ctx, evt.ID, sender.SignalID, msg.GetTimestamp(), 0)
			if portal.ExpirationTime > 0 {
				portal.addDisappearingMessage(ctx, evt.ID, uint32(portal.ExpirationTime), true)
			}
		}
	}
}

func (portal *Portal) handleMatrixRedaction(ctx context.Context, sender *User, evt *event.Event) {
	log := zerolog.Ctx(ctx)
	// Find the original signal message based on eventID
	dbMessage, err := portal.bridge.DB.Message.GetByMXID(ctx, evt.Redacts)
	if err != nil {
		log.Err(err).Msg("Failed to get redaction target message")
	}
	// Might be a reaction redaction, find the original message for the reaction
	dbReaction, err := portal.bridge.DB.Reaction.GetByMXID(ctx, evt.Redacts)
	if err != nil {
		log.Err(err).Msg("Failed to get redaction target reaction")
	}

	if !sender.IsLoggedIn() {
		sender = portal.GetRelayUser()
		if sender == nil {
			portal.sendMessageStatusCheckpointFailed(ctx, evt, errUserNotLoggedIn)
			return
		} else if !sender.IsLoggedIn() {
			portal.sendMessageStatusCheckpointFailed(ctx, evt, errRelaybotNotLoggedIn)
			return
		}
	}

	if dbMessage != nil {
		if dbMessage.Sender != sender.SignalID {
			portal.sendMessageStatusCheckpointFailed(ctx, evt, errRedactionTargetSentBySomeoneElse)
			return
		}
		msg := signalmeow.DataMessageForDelete(dbMessage.Timestamp)
		err = portal.sendSignalMessage(ctx, msg, sender, evt.ID)
		if err != nil {
			portal.sendMessageStatusCheckpointFailed(ctx, evt, err)
			log.Err(err).Msg("Failed to send message redaction to Signal")
			return
		}
		err = dbMessage.Delete(ctx)
		if err != nil {
			log.Err(err).Msg("Failed to delete redacted message from database")
		} else if otherParts, err := portal.bridge.DB.Message.GetAllPartsBySignalID(ctx, dbMessage.Sender, dbMessage.Timestamp, portal.Receiver); err != nil {
			log.Err(err).Msg("Failed to get other parts of redacted message from database")
		} else if len(otherParts) > 0 {
			// If there are other parts of the message, send a redaction for each of them
			for _, otherPart := range otherParts {
				_, err = portal.MainIntent().RedactEvent(ctx, portal.MXID, otherPart.MXID, mautrix.ReqRedact{
					Reason: "Other part of Signal message redacted",
					TxnID:  "mxsg_partredact_" + otherPart.MXID.String(),
				})
				if err != nil {
					log.Err(err).
						Stringer("part_event_id", otherPart.MXID).
						Int("part_index", otherPart.PartIndex).
						Msg("Failed to redact other part of redacted message")
				}
				err = otherPart.Delete(ctx)
				if err != nil {
					log.Err(err).
						Stringer("part_event_id", otherPart.MXID).
						Int("part_index", otherPart.PartIndex).
						Msg("Failed to delete other part of redacted message from database")
				}
			}
		}
		portal.sendMessageStatusCheckpointSuccess(ctx, evt)
	} else if dbReaction != nil {
		if dbReaction.Author != sender.SignalID {
			portal.sendMessageStatusCheckpointFailed(ctx, evt, errUnreactTargetSentBySomeoneElse)
			return
		}
		msg := signalmeow.DataMessageForReaction(dbReaction.Emoji, dbReaction.MsgAuthor, dbReaction.MsgTimestamp, true)
		err = portal.sendSignalMessage(ctx, msg, sender, evt.ID)
		if err != nil {
			portal.sendMessageStatusCheckpointFailed(ctx, evt, err)
			log.Err(err).Msg("Failed to send reaction redaction to Signal")
			return
		}
		err = dbReaction.Delete(ctx)
		if err != nil {
			log.Err(err).Msg("Failed to delete redacted reaction from database")
		}
		portal.sendMessageStatusCheckpointSuccess(ctx, evt)
	} else {
		portal.sendMessageStatusCheckpointFailed(ctx, evt, errRedactionTargetNotFound)
	}
}

func (portal *Portal) handleMatrixReaction(ctx context.Context, sender *User, evt *event.Event) {
	log := zerolog.Ctx(ctx)
	if !sender.IsLoggedIn() {
		portal.sendMessageStatusCheckpointFailed(ctx, evt, errCantRelayReactions)
		return
	}
	// Find the original signal message based on eventID
	relatedEventID := evt.Content.AsReaction().RelatesTo.EventID
	targetMsg, err := portal.bridge.DB.Message.GetByMXID(ctx, relatedEventID)
	if err != nil {
		portal.sendMessageStatusCheckpointFailed(ctx, evt, err)
		log.Err(err).Msg("Failed to get reaction target message")
		return
	} else if targetMsg == nil {
		portal.sendMessageStatusCheckpointFailed(ctx, evt, errReactionTargetNotFound)
		log.Warn().Msg("Reaction target message not found")
		return
	}
	emoji := evt.Content.AsReaction().RelatesTo.Key
	signalEmoji := variationselector.FullyQualify(emoji) // Signal seems to require fully qualified emojis
	msg := signalmeow.DataMessageForReaction(signalEmoji, targetMsg.Sender, targetMsg.Timestamp, false)
	err = portal.sendSignalMessage(ctx, msg, sender, evt.ID)
	if err != nil {
		portal.sendMessageStatusCheckpointFailed(ctx, evt, err)
		log.Error().Msg("Failed to send reaction")
		return
	}

	// Signal only allows one reaction from each user
	// Check if there's an existing reaction in the database for this sender and redact/delete it
	dbReaction, err := portal.bridge.DB.Reaction.GetBySignalID(
		ctx,
		targetMsg.Sender,
		targetMsg.Timestamp,
		sender.SignalID,
		portal.Receiver,
	)
	if err != nil {
		log.Err(err).Msg("Failed to get existing reaction from database")
	} else if dbReaction != nil {
		log.Debug().Stringer("existing_event_id", dbReaction.MXID).Msg("Redacting existing reaction after sending new one")
		_, err = portal.MainIntent().RedactEvent(ctx, portal.MXID, dbReaction.MXID)
		if err != nil {
			log.Err(err).Msg("Failed to redact existing reaction")
		}
	}
	if dbReaction != nil {
		dbReaction.MXID = evt.ID
		dbReaction.Emoji = signalEmoji
		err = dbReaction.Update(ctx)
		if err != nil {
			log.Err(err).Msg("Failed to update reaction in database")
		}
	} else {
		dbReaction = portal.bridge.DB.Reaction.New()
		dbReaction.MXID = evt.ID
		dbReaction.RoomID = portal.MXID
		dbReaction.SignalChatID = portal.ChatID
		dbReaction.SignalReceiver = portal.Receiver
		dbReaction.Author = sender.SignalID
		dbReaction.MsgAuthor = targetMsg.Sender
		dbReaction.MsgTimestamp = targetMsg.Timestamp
		dbReaction.Emoji = signalEmoji
		err = dbReaction.Insert(ctx)
		if err != nil {
			log.Err(err).Msg("Failed to insert reaction to database")
		}
	}

	portal.sendMessageStatusCheckpointSuccess(ctx, evt)
}

func (portal *Portal) sendSignalMessage(ctx context.Context, msg *signalpb.Content, sender *User, evtID id.EventID) error {
	log := zerolog.Ctx(ctx).With().
		Str("action", "send signal message").
		Stringer("event_id", evtID).
		Str("portal_chat_id", portal.ChatID).
		Logger()
	ctx = log.WithContext(ctx)

	log.Debug().Msg("Sending event to Signal")

	// Check to see if portal.ChatID is a standard UUID (with dashes)
	if portal.IsPrivateChat() {
		// this is a 1:1 chat
		result := sender.Client.SendMessage(ctx, portal.UserID(), msg)
		if !result.WasSuccessful {
			return result.Error
		}
	} else {
		// this is a group chat
		groupID := types.GroupIdentifier(portal.ChatID)
		result, err := sender.Client.SendGroupMessage(ctx, groupID, msg)
		if err != nil {
			// check the start of the error string, see if it starts with "No group master key found for group identifier"
			if strings.HasPrefix(err.Error(), "No group master key found for group identifier") {
				portal.MainIntent().SendNotice(ctx, portal.MXID, "Missing group encryption key. Please ask a group member to send a message in this chat, then retry sending.")
			}
			log.Err(err).Msg("Error sending event to Signal group")
			return err
		}
		totalRecipients := len(result.FailedToSendTo) + len(result.SuccessfullySentTo)
		log = log.With().
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
	}
	return nil
}

func (portal *Portal) sendMessageStatusCheckpointSuccess(ctx context.Context, evt *event.Event) {
	portal.sendDeliveryReceipt(ctx, evt.ID)
	portal.bridge.SendMessageSuccessCheckpoint(evt, status.MsgStepRemote, 0)

	var deliveredTo *[]id.UserID
	if portal.IsPrivateChat() {
		deliveredTo = &[]id.UserID{}
	}
	portal.sendStatusEvent(ctx, evt.ID, "", nil, deliveredTo)
}

func (portal *Portal) sendMessageStatusCheckpointFailed(ctx context.Context, evt *event.Event, err error) {
	portal.sendDeliveryReceipt(ctx, evt.ID)
	portal.bridge.SendMessageErrorCheckpoint(evt, status.MsgStepRemote, err, true, 0)
	portal.sendStatusEvent(ctx, evt.ID, "", err, nil)
}

type msgconvContextKey int

const (
	msgconvContextKeyIntent msgconvContextKey = iota
	msgconvContextKeyClient
)

func (portal *Portal) UploadMatrixMedia(ctx context.Context, data []byte, fileName, contentType string) (id.ContentURIString, error) {
	intent := ctx.Value(msgconvContextKeyIntent).(*appservice.IntentAPI)
	req := mautrix.ReqUploadMedia{
		ContentBytes: data,
		ContentType:  contentType,
		FileName:     fileName,
	}
	if portal.bridge.Config.Homeserver.AsyncMedia {
		uploaded, err := intent.UploadAsync(ctx, req)
		if err != nil {
			return "", err
		}
		return uploaded.ContentURI.CUString(), nil
	} else {
		uploaded, err := intent.UploadMedia(ctx, req)
		if err != nil {
			return "", err
		}
		return uploaded.ContentURI.CUString(), nil
	}
}

func (portal *Portal) DownloadMatrixMedia(ctx context.Context, uriString id.ContentURIString) ([]byte, error) {
	parsedURI, err := uriString.Parse()
	if err != nil {
		return nil, fmt.Errorf("malformed content URI: %w", err)
	}
	return portal.MainIntent().DownloadBytes(ctx, parsedURI)
}

func (portal *Portal) GetData(ctx context.Context) *database.Portal {
	return portal.Portal
}

func (portal *Portal) GetClient(ctx context.Context) *signalmeow.Client {
	return ctx.Value(msgconvContextKeyClient).(*signalmeow.Client)
}

func (portal *Portal) GetMatrixReply(ctx context.Context, msg *signalpb.DataMessage_Quote) (replyTo id.EventID, replyTargetSender id.UserID) {
	if msg == nil {
		return
	}
	log := zerolog.Ctx(ctx).With().
		Str("reply_target_author", msg.GetAuthorAci()).
		Uint64("reply_target_ts", msg.GetId()).
		Logger()
	if senderUUID, err := uuid.Parse(msg.GetAuthorAci()); err != nil {
		log.Err(err).Msg("Failed to parse sender UUID in Signal quote")
	} else if message, err := portal.bridge.DB.Message.GetBySignalID(ctx, senderUUID, msg.GetId(), 0, portal.Receiver); err != nil {
		log.Err(err).Msg("Failed to get reply target message from database")
	} else if message == nil {
		log.Warn().Msg("Reply target message not found")
	} else {
		replyTo = message.MXID
		targetUser := portal.bridge.GetUserBySignalID(message.Sender)
		if targetUser != nil {
			replyTargetSender = targetUser.MXID
		} else {
			replyTargetSender = portal.bridge.FormatPuppetMXID(message.Sender)
		}
	}
	return
}

func (portal *Portal) GetSignalReply(ctx context.Context, content *event.MessageEventContent) *signalpb.DataMessage_Quote {
	replyToID := content.RelatesTo.GetReplyTo()
	if len(replyToID) == 0 {
		return nil
	}
	replyToMsg, err := portal.bridge.DB.Message.GetByMXID(ctx, replyToID)
	if err != nil {
		zerolog.Ctx(ctx).Err(err).
			Stringer("reply_to_mxid", replyToID).
			Msg("Failed to get reply target message from database")
	} else if replyToMsg == nil {
		zerolog.Ctx(ctx).Warn().
			Stringer("reply_to_mxid", replyToID).
			Msg("Reply target message not found")
	} else {
		return &signalpb.DataMessage_Quote{
			Id:        proto.Uint64(replyToMsg.Timestamp),
			AuthorAci: proto.String(replyToMsg.Sender.String()),
			Type:      signalpb.DataMessage_Quote_NORMAL.Enum(),

			// This is a hack to make Signal iOS and desktop render replies to file messages.
			// Unfortunately it also makes Signal Desktop show a file icon on replies to text messages.
			// TODO store file or text flag in database and fill this field only when replying to file messages.
			Attachments: make([]*signalpb.DataMessage_Quote_QuotedAttachment, 1),
		}
	}
	return nil
}

func (portal *Portal) handleSignalMessage(portalMessage portalSignalMessage) {
	sender := portal.bridge.GetPuppetBySignalID(portalMessage.evt.Info.Sender)
	if sender == nil {
		portal.log.Warn().
			Stringer("sender_uuid", portalMessage.evt.Info.Sender).
			Msg("Couldn't get puppet for message")
		return
	}
	switch typedEvt := portalMessage.evt.Event.(type) {
	case *signalpb.DataMessage:
		portal.handleSignalDataMessage(portalMessage.user, sender, typedEvt)
	case *signalpb.TypingMessage:
		portal.handleSignalTypingMessage(sender, typedEvt)
	case *signalpb.EditMessage:
		portal.handleSignalEditMessage(sender, typedEvt.GetTargetSentTimestamp(), typedEvt.GetDataMessage())
	default:
		portal.log.Error().
			Type("data_type", typedEvt).
			Msg("Invalid inner event type inside ChatEvent")
	}
}

func (portal *Portal) handleSignalDataMessage(source *User, sender *Puppet, msg *signalpb.DataMessage) {
	genericCtx := portal.log.With().
		Str("action", "handle signal data message").
		Uint64("msg_ts", msg.GetTimestamp()).
		Logger().WithContext(context.TODO())
	// Always update sender info when we receive a message from them, there's caching inside the function
	sender.UpdateInfo(genericCtx, source)
	// Handle earlier missed group changes here.
	// If this message is a group change, don't handle it here, it's handled below.
	if msg.GetGroupV2().GetGroupChange() == nil && portal.Revision < msg.GetGroupV2().GetRevision() {
		portal.UpdateInfo(genericCtx, source, nil, msg.GetGroupV2().GetRevision())
	} else if portal.IsPrivateChat() && portal.UserID() == portal.Receiver && portal.Name != NoteToSelfName {
		// Slightly hacky way to make note to self names backfill
		portal.UpdateDMInfo(genericCtx, false)
	}

	switch {
	case msgconv.CanConvertSignal(msg):
		portal.handleSignalNormalDataMessage(source, sender, msg)
	case msg.Reaction != nil:
		portal.handleSignalReaction(sender, msg.Reaction, msg.GetTimestamp())
	case msg.Delete != nil:
		portal.handleSignalDelete(sender, msg.Delete, msg.GetTimestamp())
	case msg.GetGroupV2().GetGroupChange() != nil:
		portal.handleSignalGroupChange(source, sender, msg.GroupV2, msg.GetTimestamp())
	case msg.StoryContext != nil, msg.GroupCallUpdate != nil:
		// ignore
	default:
		portal.log.Warn().
			Str("action", "handle signal message").
			Stringer("sender_uuid", sender.SignalID).
			Uint64("msg_ts", msg.GetTimestamp()).
			Msg("Unrecognized content in message")
	}
}

type groupChangeMemberAction struct {
	userID             uuid.UUID
	membership         event.Membership
	ensureJoined       bool
	joinFromInviteLink bool
	action             string
}

func (portal *Portal) handleSignalGroupChange(source *User, sender *Puppet, groupMeta *signalpb.GroupContextV2, ts uint64) {
	log := portal.log.With().
		Str("action", "handle signal group change").
		Stringer("sender_uuid", sender.SignalID).
		Uint64("change_ts", ts).
		Uint32("new_revision", groupMeta.GetRevision()).
		Logger()
	ctx := log.WithContext(context.TODO())
	groupChange, err := source.Client.DecryptGroupChange(ctx, groupMeta)
	if err != nil {
		log.Err(err).Msg("Handling GroupChange failed")
		return
	}
	if groupChange.Revision <= portal.Revision {
		return
	}
	portal.Revision = groupChange.Revision
	if groupChange.ModifyTitle != nil {
		portal.updateName(ctx, *groupChange.ModifyTitle, sender)
	}
	if groupChange.ModifyDescription != nil {
		portal.updateTopic(ctx, *groupChange.ModifyDescription, sender)
	}
	if groupChange.ModifyAvatar != nil {
		portal.updateAvatarWithInfo(ctx, source, groupChange, sender)
	}
	if groupChange.ModifyDisappearingMessagesDuration != nil {
		portal.updateExpirationTimer(ctx, *groupChange.ModifyDisappearingMessagesDuration)
	}
	intent := sender.IntentFor(portal)
	modifyRoles := groupChange.ModifyMemberRoles
	for _, deleteBannedMember := range groupChange.DeleteBannedMembers {
		_, err := portal.sendMembershipForPuppetAndUser(ctx, sender, *deleteBannedMember, event.MembershipLeave, "unbanned")
		if err != nil {
			log.Warn().Stringer("signal_user_id", deleteBannedMember).Msg("Couldn't get puppet for unban")
		}
	}
	for _, addMember := range groupChange.AddMembers {
		modifyRoles = append(modifyRoles, &signalmeow.RoleMember{UserID: addMember.UserID, Role: addMember.Role})
		var puppet *Puppet
		if addMember.JoinFromInviteLink {
			puppet = portal.bridge.GetPuppetBySignalID(addMember.UserID)
			if puppet != nil {
				if puppet.customIntent == nil {
					user := portal.bridge.GetUserBySignalID(addMember.UserID)
					if user != nil {
						portal.MainIntent().SendCustomMembershipEvent(ctx, portal.MXID, user.MXID, event.MembershipInvite, "Joined via invite Link")
					}
				}
				_, err = puppet.IntentFor(portal).SendCustomMembershipEvent(ctx, portal.MXID, puppet.IntentFor(portal).UserID, event.MembershipJoin, "")
				if errors.Is(err, mautrix.MForbidden) {
					_, err = portal.MainIntent().SendCustomMembershipEvent(ctx, portal.MXID, puppet.IntentFor(portal).UserID, event.MembershipInvite, "Joined via invite Link")
				} else if err == nil {
					continue
				}
			}
		} else {
			puppet, _ = portal.sendMembershipForPuppetAndUser(ctx, sender, addMember.UserID, event.MembershipInvite, "added")
		}
		if puppet != nil {
			puppet.IntentFor(portal).SendCustomMembershipEvent(ctx, portal.MXID, puppet.IntentFor(portal).UserID, event.MembershipJoin, "")
		} else {
			log.Warn().Stringer("signal_user_id", addMember.UserID).Msg("Couldn't get puppet for invite")
		}
	}
	bannedMembers := make(map[uuid.UUID]bool)
	for _, addBannedMember := range groupChange.AddBannedMembers {
		bannedMembers[addBannedMember.UserID] = true
		_, err := portal.sendMembershipForPuppetAndUser(ctx, sender, addBannedMember.UserID, event.MembershipBan, "banned")
		if err != nil {
			log.Warn().Stringer("signal_user_id", addBannedMember.UserID).Msg("Couldn't get puppet for ban")
		}
	}
	for _, deleteMember := range groupChange.DeleteMembers {
		if bannedMembers[*deleteMember] {
			continue
		}
		_, err := portal.sendMembershipForPuppetAndUser(ctx, sender, *deleteMember, event.MembershipLeave, "deleted")
		if err != nil {
			log.Warn().Stringer("signal_user_id", deleteMember).Msg("Couldn't get puppet for removal")
		}
	}
	for _, deletePendingMember := range groupChange.DeletePendingMembers {
		if bannedMembers[*deletePendingMember] {
			continue
		}
		_, err := portal.sendMembershipForPuppetAndUser(ctx, sender, *deletePendingMember, event.MembershipLeave, "invite withdrawn")
		if err != nil {
			log.Warn().Stringer("signal_user_id", deletePendingMember).Msg("Couldn't get puppet for removal")
		}
	}
	for _, deleteRequestingMember := range groupChange.DeleteRequestingMembers {
		if bannedMembers[*deleteRequestingMember] {
			continue
		}
		_, err := portal.sendMembershipForPuppetAndUser(ctx, sender, *deleteRequestingMember, event.MembershipLeave, "request rejected")
		if err != nil {
			log.Warn().Stringer("signal_user_id", deleteRequestingMember).Msg("Couldn't get puppet for removal")
		}
	}
	for _, promotePendingMember := range groupChange.PromotePendingMembers {
		puppet, err := portal.sendMembershipForPuppetAndUser(ctx, sender, promotePendingMember.UserID, event.MembershipInvite, "request accepted")
		if err == nil {
			puppet.IntentFor(portal).EnsureJoined(ctx, portal.MXID)
		} else {
			log.Warn().Stringer("signal_user_id", promotePendingMember.UserID).Msg("Couldn't get puppet for invite")
		}
	}
	for _, addPendingMember := range groupChange.AddPendingMembers {
		_, err := portal.sendMembershipForPuppetAndUser(ctx, sender, addPendingMember.UserID, event.MembershipInvite, "invited")
		if err != nil {
			log.Warn().Stringer("signal_user_id", addPendingMember.UserID).Msg("Couldn't get puppet for invite")
		}
		modifyRoles = append(modifyRoles, &signalmeow.RoleMember{UserID: addPendingMember.UserID, Role: addPendingMember.Role})
	}
	for _, promoteRequestingMember := range groupChange.PromoteRequestingMembers {
		puppet, err := portal.sendMembershipForPuppetAndUser(ctx, sender, promoteRequestingMember.UserID, event.MembershipInvite, "accepted")
		if err == nil {
			err = puppet.IntentFor(portal).EnsureJoined(ctx, portal.MXID)
			if err != nil {
				log.Warn().Stringer("signal_user_id", promoteRequestingMember.UserID).Msg("failed to join puppet")
			}
		} else {
			log.Warn().Stringer("signal_user_id", promoteRequestingMember.UserID).Msg("Couldn't get puppet for join")
		}
		modifyRoles = append(modifyRoles, &signalmeow.RoleMember{UserID: promoteRequestingMember.UserID, Role: promoteRequestingMember.Role})
	}
	for _, addRequestingMember := range groupChange.AddRequestingMembers {
		// sender and target should be the same SignalID
		puppet := portal.bridge.GetPuppetBySignalID(addRequestingMember.UserID)
		if puppet != nil {
			portal.sendMembershipWithPuppet(ctx, sender, puppet.IntentFor(portal).UserID, event.MembershipKnock, "knocked")
		}
	}

	if groupChange.ModifyAttributesAccess != nil || groupChange.ModifyAnnouncementsOnly != nil || groupChange.ModifyMemberAccess != nil || len(modifyRoles) > 0 {
		levels, err := portal.MainIntent().PowerLevels(ctx, portal.MXID)
		if err != nil {
			log.Err(err).Msg("Couldn't get power levels")
		} else {
			for _, modifyRole := range modifyRoles {
				puppet := portal.bridge.GetPuppetBySignalID(modifyRole.UserID)
				if puppet == nil {
					log.Warn().Stringer("signal_user_id", modifyRole.UserID).Msg("Couldn't get puppet for power level change")
					continue
				}
				powerLevel := 0
				if modifyRole.Role == signalmeow.GroupMember_ADMINISTRATOR {
					powerLevel = 50
				}
				levels.EnsureUserLevel(puppet.IntentFor(portal).UserID, powerLevel)
				if puppet.customIntent == nil {
					user := portal.bridge.GetUserBySignalID(modifyRole.UserID)
					if user != nil {
						levels.EnsureUserLevel(user.MXID, powerLevel)
					}
				}
			}
			if groupChange.ModifyAnnouncementsOnly != nil {
				levels.EventsDefault = 0
				if *groupChange.ModifyAnnouncementsOnly {
					levels.EventsDefault = 50
				}
			}
			if groupChange.ModifyAttributesAccess != nil {
				level := 0
				if *groupChange.ModifyAttributesAccess == signalmeow.AccessControl_ADMINISTRATOR {
					level = 50
				}
				levels.EnsureEventLevel(event.StateRoomName, level)
				levels.EnsureEventLevel(event.StateTopic, level)
				levels.EnsureEventLevel(event.StateRoomAvatar, level)
			}
			if groupChange.ModifyMemberAccess != nil {
				level := 0
				if *groupChange.ModifyMemberAccess == signalmeow.AccessControl_ADMINISTRATOR {
					level = 50
				}
				levels.InvitePtr = &level
			}
			_, err = intent.SetPowerLevels(ctx, portal.MXID, levels)
			if errors.Is(err, mautrix.MForbidden) {
				_, err = portal.MainIntent().SetPowerLevels(ctx, portal.MXID, levels)
			}
			if err != nil {
				log.Err(err).Msg("Couldn't set power levels")
			}
		}
	}
	if groupChange.ModifyAddFromInviteLinkAccess != nil {
		joinRule := event.JoinRuleInvite
		if *groupChange.ModifyAddFromInviteLinkAccess == signalmeow.AccessControl_ADMINISTRATOR {
			joinRule = event.JoinRuleKnock
		} else if *groupChange.ModifyAddFromInviteLinkAccess == signalmeow.AccessControl_ANY && portal.bridge.Config.Bridge.PublicPortals {
			joinRule = event.JoinRulePublic
		}
		_, err = intent.SendMassagedStateEvent(ctx, portal.MXID, event.StateJoinRules, "", &event.JoinRulesEventContent{JoinRule: joinRule}, int64(ts))
		if errors.Is(err, mautrix.MForbidden) {
			_, err = portal.MainIntent().SendMassagedStateEvent(ctx, portal.MXID, event.StateJoinRules, "", &event.JoinRulesEventContent{JoinRule: joinRule}, int64(ts))
		}
		if err != nil {
			log.Err(err).Msg("Couldn't set join rule")
		}
	}
	err = portal.Update(ctx)
	if err != nil {
		log.Err(err).Msg("Failed to save portal in database after processing group change")
	}
	portal.UpdateBridgeInfo(ctx)
}

func (portal *Portal) sendMembershipForPuppetAndUser(ctx context.Context, sender *Puppet, target uuid.UUID, membership event.Membership, action string) (puppet *Puppet, err error) {
	puppet = portal.bridge.GetPuppetBySignalID(target)
	if puppet == nil {
		err = fmt.Errorf("couldn't get Puppet for Signal uuid %s", target)
		return
	}
	err = portal.sendMembershipWithPuppet(ctx, sender, puppet.IntentFor(portal).UserID, membership, action)
	if puppet.customIntent == nil {
		user := portal.bridge.GetUserBySignalID(target)
		if user != nil {
			err = portal.sendMembershipWithPuppet(ctx, sender, user.MXID, membership, action)
		}
	}
	return
}

func (portal *Portal) sendMembershipWithPuppet(ctx context.Context, sender *Puppet, target id.UserID, membership event.Membership, action string) (err error) {
	_, err = sender.IntentFor(portal).SendCustomMembershipEvent(ctx, portal.MXID, target, membership, "")
	if errors.Is(err, mautrix.MForbidden) {
		_, err = portal.MainIntent().SendCustomMembershipEvent(ctx, portal.MXID, target, membership, fmt.Sprintf("%s by %s", action, sender.GetDisplayname()))
	}
	if err != nil {
		zerolog.Ctx(ctx).Warn().Stringer("Membership Action failed for user", target).Msg(action)
	}
	return
}

func (portal *Portal) handleSignalReaction(sender *Puppet, react *signalpb.DataMessage_Reaction, ts uint64) {
	log := portal.log.With().
		Str("action", "handle signal reaction").
		Stringer("sender_uuid", sender.SignalID).
		Uint64("target_msg_ts", react.GetTargetSentTimestamp()).
		Str("target_msg_sender", react.GetTargetAuthorAci()).
		Bool("remove", react.GetRemove()).
		Logger()
	ctx := log.WithContext(context.TODO())
	targetSenderUUID, err := uuid.Parse(react.GetTargetAuthorAci())
	if err != nil {
		log.Err(err).Msg("Failed to parse target message sender UUID")
		return
	}
	targetMsg, err := portal.bridge.DB.Message.GetBySignalID(ctx, targetSenderUUID, react.GetTargetSentTimestamp(), 0, portal.Receiver)
	if err != nil {
		log.Err(err).Msg("Failed to get target message from database")
		return
	} else if targetMsg == nil {
		log.Warn().Msg("Target message not found")
		return
	}
	existingReaction, err := portal.bridge.DB.Reaction.GetBySignalID(ctx, targetMsg.Sender, targetMsg.Timestamp, sender.SignalID, portal.Receiver)
	if err != nil {
		log.Err(err).Msg("Failed to get existing reaction from database")
		return
	} else if existingReaction != nil && existingReaction.Emoji == react.GetEmoji() {
		log.Debug().Msg("Ignoring duplicate reaction")
		return
	}
	intent := sender.IntentFor(portal)
	if existingReaction != nil {
		_, err = intent.RedactEvent(ctx, portal.MXID, existingReaction.MXID, mautrix.ReqRedact{
			TxnID: "mxsg_unreact_" + existingReaction.MXID.String(),
		})
		if errors.Is(err, mautrix.MForbidden) {
			log.Debug().Err(err).Msg("Failed to redact reaction with ghost, retrying with main intent")
			_, err = portal.MainIntent().RedactEvent(ctx, portal.MXID, existingReaction.MXID, mautrix.ReqRedact{
				TxnID: "mxsg_unreact_" + existingReaction.MXID.String(),
			})
		}
		if err != nil {
			log.Err(err).Msg("Failed to redact reaction")
		}
		if react.GetRemove() {
			err = existingReaction.Delete(ctx)
			if err != nil {
				log.Err(err).Msg("Failed to remove reaction from database after redacting")
			}
			return
		}
	} else if react.GetRemove() {
		log.Warn().Msg("Existing reaction for removal not found")
		return
	}
	// Create a new message event with the reaction
	content := &event.ReactionEventContent{
		RelatesTo: event.RelatesTo{
			Type:    event.RelAnnotation,
			Key:     variationselector.Add(react.GetEmoji()),
			EventID: targetMsg.MXID,
		},
	}
	resp, err := portal.sendMatrixEvent(ctx, intent, event.EventReaction, content, nil, int64(ts))
	if err != nil {
		log.Err(err).Msg("Failed to send reaction")
		return
	}
	if existingReaction == nil {
		dbReaction := portal.bridge.DB.Reaction.New()
		dbReaction.MXID = resp.EventID
		dbReaction.RoomID = portal.MXID
		dbReaction.SignalChatID = portal.ChatID
		dbReaction.SignalReceiver = portal.Receiver
		dbReaction.Author = sender.SignalID
		dbReaction.MsgAuthor = targetMsg.Sender
		dbReaction.MsgTimestamp = targetMsg.Timestamp
		dbReaction.Emoji = react.GetEmoji()
		err = dbReaction.Insert(ctx)
		if err != nil {
			log.Err(err).Msg("Failed to insert reaction to database")
		}
	} else {
		existingReaction.Emoji = react.GetEmoji()
		existingReaction.MXID = resp.EventID
		err = existingReaction.Update(ctx)
		if err != nil {
			log.Err(err).Msg("Failed to update reaction in database")
		}
	}
}

func (portal *Portal) handleSignalDelete(sender *Puppet, delete *signalpb.DataMessage_Delete, ts uint64) {
	log := portal.log.With().
		Str("action", "handle signal delete").
		Stringer("sender_uuid", sender.SignalID).
		Uint64("target_msg_ts", delete.GetTargetSentTimestamp()).
		Uint64("delete_ts", ts).
		Logger()
	ctx := log.WithContext(context.TODO())
	targetMsg, err := portal.bridge.DB.Message.GetAllPartsBySignalID(ctx, sender.SignalID, delete.GetTargetSentTimestamp(), portal.Receiver)
	if err != nil {
		log.Err(err).Msg("Failed to get target message from database")
		return
	} else if len(targetMsg) == 0 {
		log.Warn().Msg("Target message not found")
		return
	}
	intent := sender.IntentFor(portal)
	for _, part := range targetMsg {
		_, err = intent.RedactEvent(ctx, portal.MXID, part.MXID, mautrix.ReqRedact{
			TxnID: "mxsg_delete_" + part.MXID.String(),
		})
		if err != nil {
			log.Err(err).
				Int("part_index", part.PartIndex).
				Stringer("event_id", part.MXID).
				Msg("Failed to redact message")
		}
		err = part.Delete(ctx)
		if err != nil {
			log.Err(err).
				Int("part_index", part.PartIndex).
				Msg("Failed to delete message from database")
		}
	}
}

func (portal *Portal) handleSignalNormalDataMessage(source *User, sender *Puppet, msg *signalpb.DataMessage) {
	log := portal.log.With().
		Str("action", "handle signal message").
		Stringer("sender_uuid", sender.SignalID).
		Uint64("msg_ts", msg.GetTimestamp()).
		Logger()
	ctx := log.WithContext(context.TODO())
	if portal.MXID == "" {
		log.Debug().Msg("Creating Matrix room from incoming message")
		if err := portal.CreateMatrixRoom(ctx, source, msg.GetGroupV2().GetRevision()); err != nil {
			log.Error().Err(err).Msg("Failed to create portal room")
			return
		}
	} else if !portal.ensureUserInvited(ctx, source) {
		log.Warn().Stringer("user_id", source.MXID).Msg("Failed to ensure source user is joined to portal")
	}

	existingMessage, err := portal.bridge.DB.Message.GetBySignalID(ctx, sender.SignalID, msg.GetTimestamp(), 0, portal.Receiver)
	if err != nil {
		log.Err(err).Msg("Failed to check if message was already bridged")
		return
	} else if existingMessage != nil {
		log.Debug().Msg("Ignoring duplicate message")
		return
	}

	intent := sender.IntentFor(portal)
	ctx = context.WithValue(ctx, msgconvContextKeyIntent, intent)
	converted := portal.MsgConv.ToMatrix(ctx, msg)
	if portal.bridge.Config.Bridge.CaptionInMessage {
		converted.MergeCaption()
	}
	for i, part := range converted.Parts {
		resp, err := portal.sendMatrixEvent(ctx, intent, part.Type, part.Content, part.Extra, int64(converted.Timestamp))
		if err != nil {
			log.Err(err).Int("part_index", i).Msg("Failed to send message to Matrix")
			continue
		}
		portal.storeMessageInDB(ctx, resp.EventID, sender.SignalID, converted.Timestamp, i)
		if converted.DisappearIn != 0 {
			portal.addDisappearingMessage(ctx, resp.EventID, converted.DisappearIn, sender.SignalID == source.SignalID)
		}
	}
}

func (portal *Portal) handleSignalEditMessage(sender *Puppet, timestamp uint64, msg *signalpb.DataMessage) {
	log := portal.log.With().
		Str("action", "handle signal edit").
		Stringer("sender_uuid", sender.SignalID).
		Uint64("target_msg_ts", timestamp).
		Uint64("edit_msg_ts", msg.GetTimestamp()).
		Logger()
	if portal.MXID == "" {
		log.Debug().Msg("Dropping edit message in chat with no portal")
		return
	}
	ctx := log.WithContext(context.TODO())
	targetMessage, err := portal.bridge.DB.Message.GetAllPartsBySignalID(ctx, sender.SignalID, timestamp, portal.Receiver)
	if err != nil {
		log.Err(err).Msg("Failed to get target message")
		return
	} else if len(targetMessage) == 0 {
		log.Debug().Msg("Target message not found (edit may have been already handled)")
		return
	}

	intent := sender.IntentFor(portal)
	ctx = context.WithValue(ctx, msgconvContextKeyIntent, intent)
	converted := portal.MsgConv.ToMatrix(ctx, msg)
	if portal.bridge.Config.Bridge.CaptionInMessage {
		converted.MergeCaption()
	}
	if len(converted.Parts) != len(targetMessage) {
		log.Error().
			Int("target_parts", len(targetMessage)).
			Int("new_parts", len(converted.Parts)).
			Msg("Mismatched number of parts in edit")
		return
	}
	for i, part := range converted.Parts {
		part.Content.SetEdit(targetMessage[i].MXID)
		if part.Extra != nil {
			part.Extra = map[string]any{
				"m.new_content": part.Extra,
			}
		}
		_, err = portal.sendMatrixEvent(ctx, intent, part.Type, part.Content, part.Extra, int64(converted.Timestamp))
		if err != nil {
			log.Err(err).Int("part_index", i).Msg("Failed to send edit to Matrix")
		}
	}
	err = targetMessage[0].SetTimestamp(ctx, msg.GetTimestamp())
	if err != nil {
		log.Err(err).Msg("Failed to update message edit timestamp in database")
	}
}

const SignalTypingTimeout = 15 * time.Second

func (portal *Portal) handleSignalTypingMessage(sender *Puppet, msg *signalpb.TypingMessage) {
	if portal.MXID == "" {
		portal.log.Debug().Msg("Dropping typing message in chat with no portal")
		return
	}
	ctx := context.TODO()
	intent := sender.IntentFor(portal)
	// Don't bridge double puppeted typing notifications to avoid echoing
	if intent.IsCustomPuppet {
		return
	}
	var err error
	switch msg.GetAction() {
	case signalpb.TypingMessage_STARTED:
		_, err = intent.UserTyping(ctx, portal.MXID, true, SignalTypingTimeout)
	case signalpb.TypingMessage_STOPPED:
		_, err = intent.UserTyping(ctx, portal.MXID, false, 0)
	}
	if err != nil {
		portal.log.Err(err).
			Stringer("user_id", sender.SignalID).
			Msg("Failed to handle Signal typing notification")
	}
}

func (portal *Portal) storeMessageInDB(ctx context.Context, eventID id.EventID, senderSignalID uuid.UUID, timestamp uint64, partIndex int) {
	dbMessage := portal.bridge.DB.Message.New()
	dbMessage.MXID = eventID
	dbMessage.RoomID = portal.MXID
	dbMessage.Sender = senderSignalID
	dbMessage.Timestamp = timestamp
	dbMessage.PartIndex = partIndex
	dbMessage.SignalChatID = portal.ChatID
	dbMessage.SignalReceiver = portal.Receiver
	err := dbMessage.Insert(ctx)
	if err != nil {
		portal.log.Err(err).Msg("Failed to insert message into database")
	}
}

func (portal *Portal) addDisappearingMessage(ctx context.Context, eventID id.EventID, expireInSeconds uint32, startTimerNow bool) {
	portal.bridge.disappearingMessagesManager.AddDisappearingMessage(ctx, eventID, portal.MXID, time.Duration(expireInSeconds)*time.Second, startTimerNow)
}

func (portal *Portal) MarkDelivered(ctx context.Context, msg *database.Message) {
	if !portal.IsPrivateChat() {
		return
	}
	portal.bridge.SendRawMessageCheckpoint(&status.MessageCheckpoint{
		EventID:    msg.MXID,
		RoomID:     portal.MXID,
		Step:       status.MsgStepRemote,
		Timestamp:  jsontime.UnixMilliNow(),
		Status:     status.MsgStatusDelivered,
		ReportedBy: status.MsgReportedByBridge,
	})
	portal.sendStatusEvent(ctx, msg.MXID, "", nil, &[]id.UserID{portal.MainIntent().UserID})
}

type customReadReceipt struct {
	Timestamp          int64  `json:"ts,omitempty"`
	DoublePuppetSource string `json:"fi.mau.double_puppet_source,omitempty"`
}

type customReadMarkers struct {
	mautrix.ReqSetReadMarkers
	ReadExtra      customReadReceipt `json:"com.beeper.read.extra"`
	FullyReadExtra customReadReceipt `json:"com.beeper.fully_read.extra"`
}

func (portal *Portal) SendReadReceipt(ctx context.Context, sender *Puppet, msg *database.Message) error {
	intent := sender.IntentFor(portal)
	if intent.IsCustomPuppet {
		extra := customReadReceipt{DoublePuppetSource: portal.bridge.Name}
		return intent.SetReadMarkers(ctx, portal.MXID, &customReadMarkers{
			ReqSetReadMarkers: mautrix.ReqSetReadMarkers{
				Read:      msg.MXID,
				FullyRead: msg.MXID,
			},
			ReadExtra:      extra,
			FullyReadExtra: extra,
		})
	} else {
		return intent.MarkRead(ctx, portal.MXID, msg.MXID)
	}
}

func typingDiff(prev, new []id.UserID) (started, stopped []id.UserID) {
OuterNew:
	for _, userID := range new {
		for _, previousUserID := range prev {
			if userID == previousUserID {
				continue OuterNew
			}
		}
		started = append(started, userID)
	}
OuterPrev:
	for _, userID := range prev {
		for _, previousUserID := range new {
			if userID == previousUserID {
				continue OuterPrev
			}
		}
		stopped = append(stopped, userID)
	}
	return
}

func (portal *Portal) setTyping(userIDs []id.UserID, isTyping bool) {
	for _, userID := range userIDs {
		user := portal.bridge.GetUserByMXID(userID)
		if user == nil || !user.IsLoggedIn() {
			continue
		}

		// Check to see if portal.ChatID is a standard UUID (with dashes)
		// Note: not handling sending to a group right now, since that will
		// require SenderKey sending to not be terrible
		if portal.IsPrivateChat() {
			// this is a 1:1 chat
			portal.log.Debug().Msg("Sending Typing event to Signal")
			ctx := context.TODO()
			typingMessage := signalmeow.TypingMessage(isTyping)
			result := user.Client.SendMessage(ctx, portal.UserID(), typingMessage)
			if !result.WasSuccessful {
				portal.log.Err(result.FailedSendResult.Error).Msg("Error sending event to Signal")
			}
		}
	}
}

func (portal *Portal) HandleMatrixTyping(newTyping []id.UserID) {
	if portal.IsNoteToSelf() {
		return
	}

	portal.currentlyTypingLock.Lock()
	defer portal.currentlyTypingLock.Unlock()
	startedTyping, stoppedTyping := typingDiff(portal.currentlyTyping, newTyping)
	portal.currentlyTyping = newTyping
	portal.setTyping(startedTyping, true)
	portal.setTyping(stoppedTyping, false)
}

func (portal *Portal) HandleMatrixReadReceipt(brSender bridge.User, eventID id.EventID, receipt event.ReadReceipt) {
	portal.handleMatrixReadReceipt(brSender.(*User), eventID, uint64(receipt.Timestamp.UnixMilli()), true)
}

func (portal *Portal) handleMatrixReadReceipt(sender *User, eventID id.EventID, maxTimestamp uint64, isExplicit bool) {
	if !sender.IsLoggedIn() {
		return
	}
	logWith := portal.log.With().
		Stringer("event_id", eventID).
		Stringer("sender", sender.MXID).
		Bool("explicit", isExplicit)
	if isExplicit {
		logWith = logWith.Str("action", "handle matrix read receipt")
	}
	log := logWith.Logger()
	log.Debug().Msg("Handling Matrix read receipt")
	portal.ScheduleDisappearing()
	ctx := log.WithContext(context.TODO())

	if isExplicit {
		dbMessage, _ := portal.bridge.DB.Message.GetByMXID(ctx, eventID)
		if dbMessage != nil {
			maxTimestamp = dbMessage.Timestamp
		}
	}
	prevLastReadTS := sender.GetLastReadTS(ctx, portal.PortalKey)
	if maxTimestamp <= prevLastReadTS {
		log.Debug().
			Uint64("prev_last_read_ts", prevLastReadTS).
			Uint64("max_timestamp", maxTimestamp).
			Msg("Ignoring read receipt older than last read timestamp")
		return
	}
	minTimestamp := prevLastReadTS
	if minTimestamp == 0 {
		minTimestamp = maxTimestamp - 2000
	}
	dbMessages, err := portal.bridge.DB.Message.GetAllBetweenTimestamps(ctx, portal.PortalKey, minTimestamp, maxTimestamp)
	if err != nil {
		log.Err(err).Msg("Failed to get messages between timestamps to mark as read")
		return
	}
	messagesToRead := map[uuid.UUID][]uint64{}
	for _, msg := range dbMessages {
		messagesToRead[msg.Sender] = append(messagesToRead[msg.Sender], msg.Timestamp)
	}
	// Always update last read ts for non-explicit read receipts, because that means there's a message about to be sent
	if (len(dbMessages) > 0 || !isExplicit) && maxTimestamp != prevLastReadTS {
		sender.SetLastReadTS(ctx, portal.PortalKey, maxTimestamp)
	}
	if isExplicit || len(messagesToRead) > 0 {
		log.Debug().
			Any("targets", messagesToRead).
			Uint64("prev_last_read_ts", prevLastReadTS).
			Uint64("min_timestamp", minTimestamp).
			Uint64("max_timestamp", maxTimestamp).
			Msg("Collected read receipt target messages")
	}

	// TODO send sync message manually containing all read receipts instead of a separate message for each recipient

	for destination, messages := range messagesToRead {
		// Don't send read receipts for own messages
		if destination == sender.SignalID {
			continue
		}
		// Don't use portal.sendSignalMessage because we're sending this straight to
		// who sent the original message, not the portal's ChatID
		ctx, cancel := context.WithTimeout(ctx, 10*time.Second)
		result := sender.Client.SendMessage(ctx, destination, signalmeow.ReadReceptMessageForTimestamps(messages))
		cancel()
		if !result.WasSuccessful {
			log.Err(result.FailedSendResult.Error).
				Stringer("destination", destination).
				Uints64("message_ids", messages).
				Msg("Failed to send read receipt to Signal")
		} else {
			log.Debug().
				Stringer("destination", destination).
				Uints64("message_ids", messages).
				Msg("Sent read receipt to Signal")
		}
	}
}

func (portal *Portal) sendMainIntentMessage(ctx context.Context, content *event.MessageEventContent) (*mautrix.RespSendEvent, error) {
	return portal.sendMatrixEvent(ctx, portal.MainIntent(), event.EventMessage, content, nil, 0)
}

func (portal *Portal) encrypt(ctx context.Context, intent *appservice.IntentAPI, content *event.Content, eventType event.Type) (event.Type, error) {
	if !portal.Encrypted || portal.bridge.Crypto == nil {
		return eventType, nil
	}
	intent.AddDoublePuppetValue(content)
	// TODO maybe the locking should be inside mautrix-go?
	portal.encryptLock.Lock()
	defer portal.encryptLock.Unlock()
	err := portal.bridge.Crypto.Encrypt(ctx, portal.MXID, eventType, content)
	if err != nil {
		return eventType, fmt.Errorf("failed to encrypt event: %w", err)
	}
	return event.EventEncrypted, nil
}

func (portal *Portal) sendMatrixEvent(ctx context.Context, intent *appservice.IntentAPI, eventType event.Type, content any, extraContent map[string]any, timestamp int64) (*mautrix.RespSendEvent, error) {
	wrappedContent := event.Content{Parsed: content, Raw: extraContent}
	if eventType != event.EventReaction {
		var err error
		eventType, err = portal.encrypt(ctx, intent, &wrappedContent, eventType)
		if err != nil {
			return nil, err
		}
	}

	_, _ = intent.UserTyping(ctx, portal.MXID, false, 0)
	return intent.SendMassagedMessageEvent(ctx, portal.MXID, eventType, &wrappedContent, timestamp)
}

func (portal *Portal) getEncryptionEventContent() (evt *event.EncryptionEventContent) {
	evt = &event.EncryptionEventContent{Algorithm: id.AlgorithmMegolmV1}
	if rot := portal.bridge.Config.Bridge.Encryption.Rotation; rot.EnableCustom {
		evt.RotationPeriodMillis = rot.Milliseconds
		evt.RotationPeriodMessages = rot.Messages
	}
	return
}

func (portal *Portal) shouldSetDMRoomMetadata() bool {
	return !portal.IsPrivateChat() ||
		portal.bridge.Config.Bridge.PrivateChatPortalMeta == "always" ||
		(portal.IsEncrypted() && portal.bridge.Config.Bridge.PrivateChatPortalMeta != "never")
}

func (portal *Portal) ensureUserInvited(ctx context.Context, user *User) bool {
	return user.ensureInvited(ctx, portal.MainIntent(), portal.MXID, portal.IsPrivateChat())
}

func (portal *Portal) CreateMatrixRoom(ctx context.Context, user *User, groupRevision uint32) error {
	portal.roomCreateLock.Lock()
	defer portal.roomCreateLock.Unlock()
	if portal.MXID != "" {
		portal.log.Debug().Msg("Not creating room: already exists")
		return nil
	}
	portal.log.Debug().Msg("Creating matrix room")

	intent := portal.MainIntent()

	if err := intent.EnsureRegistered(ctx); err != nil {
		portal.log.Error().Err(err).Msg("failed to ensure registered")
		return err
	}

	bridgeInfoStateKey, bridgeInfo := portal.getBridgeInfo()
	initialState := []*event.Event{{
		Type:     event.StateBridge,
		Content:  event.Content{Parsed: bridgeInfo},
		StateKey: &bridgeInfoStateKey,
	}, {
		// TODO remove this once https://github.com/matrix-org/matrix-doc/pull/2346 is in spec
		Type:     event.StateHalfShotBridge,
		Content:  event.Content{Parsed: bridgeInfo},
		StateKey: &bridgeInfoStateKey,
	}}

	if !portal.AvatarURL.IsEmpty() {
		initialState = append(initialState, &event.Event{
			Type: event.StateRoomAvatar,
			Content: event.Content{Parsed: &event.RoomAvatarEventContent{
				URL: portal.AvatarURL,
			}},
		})
	}

	creationContent := make(map[string]interface{})
	if !portal.bridge.Config.Bridge.FederateRooms {
		creationContent["m.federate"] = false
	}

	var invite []id.UserID
	autoJoinInvites := portal.bridge.SpecVersions.Supports(mautrix.BeeperFeatureAutojoinInvites)
	if autoJoinInvites {
		invite = append(invite, user.MXID)
	}

	if portal.bridge.Config.Bridge.Encryption.Default {
		initialState = append(initialState, &event.Event{
			Type: event.StateEncryption,
			Content: event.Content{
				Parsed: portal.getEncryptionEventContent(),
			},
		})
		portal.Encrypted = true

		if portal.IsPrivateChat() {
			invite = append(invite, portal.bridge.Bot.UserID)
		}
	}

	var dmPuppet *Puppet
	var groupInfo *signalmeow.Group
	if portal.IsPrivateChat() {
		dmPuppet = portal.GetDMPuppet()
		dmPuppet.UpdateInfo(ctx, user)
		portal.UpdateDMInfo(ctx, false)
	} else {
		groupInfo = portal.UpdateGroupInfo(ctx, user, nil, groupRevision, true)
		if groupInfo == nil {
			portal.log.Error().Msg("Didn't get group info after updating portal")
			return errors.New("failed to get group info")
		}
		for member := range portal.SyncParticipants(ctx, user, groupInfo) {
			invite = append(invite, member)
		}
	}

	req := &mautrix.ReqCreateRoom{
		Visibility:      "private",
		Name:            portal.Name,
		Topic:           portal.Topic,
		Invite:          invite,
		Preset:          "private_chat",
		IsDirect:        portal.IsPrivateChat(),
		InitialState:    initialState,
		CreationContent: creationContent,

		BeeperAutoJoinInvites: autoJoinInvites,
	}
	resp, err := intent.CreateRoom(ctx, req)
	if err != nil {
		portal.log.Warn().Err(err).Msg("failed to create room")
		return err
	}
	portal.log = portal.log.With().Stringer("room_id", resp.RoomID).Logger()

	portal.NameSet = len(req.Name) > 0
	portal.TopicSet = len(req.Topic) > 0
	portal.AvatarSet = !portal.AvatarURL.IsEmpty()
	portal.MXID = resp.RoomID
	portal.bridge.portalsLock.Lock()
	portal.bridge.portalsByMXID[portal.MXID] = portal
	portal.bridge.portalsLock.Unlock()
	err = portal.Update(ctx)
	if err != nil {
		portal.log.Err(err).Msg("Failed to save portal room ID")
		return err
	}
	portal.log.Info().Msg("Created matrix room for portal")

	if !autoJoinInvites {
		if !portal.IsPrivateChat() {
			portal.SyncParticipants(ctx, user, groupInfo)
		} else if portal.Encrypted {
			err = portal.bridge.Bot.EnsureJoined(ctx, portal.MXID, appservice.EnsureJoinedParams{BotOverride: portal.MainIntent().Client})
			if err != nil {
				portal.log.Error().Err(err).Msg("Failed to ensure bridge bot is joined to private chat portal")
			}
		}
		user.ensureInvited(ctx, portal.MainIntent(), portal.MXID, portal.IsPrivateChat())
	}
	user.syncChatDoublePuppetDetails(portal, true)
	go portal.addToPersonalSpace(portal.log.WithContext(context.TODO()), user)

	if portal.IsPrivateChat() {
		user.UpdateDirectChats(ctx, map[id.UserID][]id.RoomID{
			dmPuppet.MXID: {portal.MXID},
		})
	}

	return nil
}

func (portal *Portal) GetDMPuppet() *Puppet {
	if !portal.IsPrivateChat() {
		return nil
	}
	return portal.bridge.GetPuppetBySignalID(portal.UserID())
}

func (portal *Portal) UpdateInfo(ctx context.Context, source *User, groupInfo *signalmeow.Group, revision uint32) {
	if portal.IsPrivateChat() {
		portal.UpdateDMInfo(ctx, false)
		return
	}
	groupInfo = portal.UpdateGroupInfo(ctx, source, groupInfo, revision, false)
	if groupInfo != nil {
		members := portal.SyncParticipants(ctx, source, groupInfo)
		portal.updatePowerLevelsAndJoinRule(ctx, groupInfo, members)
	}
}

const PrivateChatTopic = "Signal private chat"
const NoteToSelfName = "Signal Note to Self"

func (portal *Portal) UpdateDMInfo(ctx context.Context, forceSave bool) {
	log := zerolog.Ctx(ctx).With().
		Str("function", "UpdateDMInfo").
		Logger()
	log.Trace().Msg("Updating portal info")
	ctx = log.WithContext(ctx)
	puppet := portal.GetDMPuppet()

	update := forceSave
	if portal.UserID() == portal.Receiver {
		noteToSelfAvatar := portal.bridge.Config.Bridge.NoteToSelfAvatar.ParseOrIgnore()
		avatarHash := sha256.Sum256([]byte(noteToSelfAvatar.String()))

		update = portal.updateName(ctx, NoteToSelfName, nil) || update
		update = portal.updateAvatarWithMXC(ctx, "notetoself", hex.EncodeToString(avatarHash[:]), noteToSelfAvatar) || update
	} else if portal.shouldSetDMRoomMetadata() {
		update = portal.updateName(ctx, puppet.Name, nil) || update
		update = portal.updateAvatarWithMXC(ctx, puppet.AvatarPath, puppet.AvatarHash, puppet.AvatarURL) || update
	}
	topic := PrivateChatTopic
	if portal.bridge.Config.Bridge.NumberInTopic && puppet.Number != "" {
		topic = fmt.Sprintf("%s with %s", topic, puppet.Number)
	}
	update = portal.updateTopic(ctx, topic, nil) || update
	if update {
		err := portal.Update(ctx)
		if err != nil {
			log.Err(err).Msg("Failed to save portal in database after updating group info")
		}
		portal.UpdateBridgeInfo(ctx)
	}
}

func (portal *Portal) updatePowerLevelsAndJoinRule(ctx context.Context, info *signalmeow.Group, members map[id.UserID]int) {
	log := zerolog.Ctx(ctx).With().
		Str("function", "updatePowerLevelsAndJoinRule").
		Logger()
	log.Trace().Msg("Updating power levels and join rule")
	state, err := portal.MainIntent().State(ctx, portal.MXID)
	if err != nil {
		log.Err(err).Msg("Failed to get room state")
		return
	}
	joinRule := state[event.StateJoinRules][""].Content.AsJoinRules().JoinRule
	newJoinRule := event.JoinRuleInvite
	levels := state[event.StatePowerLevels][""].Content.AsPowerLevels()
	botLevel := levels.GetUserLevel(portal.MainIntent().UserID)
	changed := false
	for mxid, level := range members {
		if levels.GetUserLevel(mxid) < botLevel {
			changed = levels.EnsureUserLevel(mxid, level) || changed
		}
	}
	newEventsDefault := 0
	if info.AnnouncementsOnly {
		newEventsDefault = 50
	}
	if newEventsDefault != levels.EventsDefault {
		levels.EventsDefault = newEventsDefault
		changed = true
	}
	if info.AccessControl != nil {
		level := 0
		if info.AccessControl.Attributes == signalmeow.AccessControl_ADMINISTRATOR {
			level = 50
		}
		changed = levels.EnsureEventLevel(event.StateRoomName, level) || changed
		changed = levels.EnsureEventLevel(event.StateTopic, level) || changed
		changed = levels.EnsureEventLevel(event.StateRoomAvatar, level) || changed
		level = 0
		if info.AccessControl.Members == signalmeow.AccessControl_ADMINISTRATOR {
			level = 50
		}
		if levels.InvitePtr == nil || *levels.InvitePtr != level {
			levels.InvitePtr = &level
			changed = true
		}
		if info.AccessControl.AddFromInviteLink == signalmeow.AccessControl_ADMINISTRATOR {
			newJoinRule = event.JoinRuleKnock
		} else if info.AccessControl.AddFromInviteLink == signalmeow.AccessControl_ANY && (portal.bridge.Config.Bridge.PublicPortals || joinRule == event.JoinRulePublic) {
			newJoinRule = event.JoinRulePublic
		}
	}
	if newJoinRule != joinRule {
		_, err = portal.MainIntent().SendStateEvent(ctx, portal.MXID, event.StateJoinRules, "", &event.JoinRulesEventContent{JoinRule: joinRule})
		if err != nil {
			log.Err(err).Msg("Failed to set join rule")
		}
	}
	if changed {
		_, err = portal.MainIntent().SetPowerLevels(ctx, portal.MXID, levels)
		if err != nil {
			log.Err(err).Msg("Failed to set power levels")
		}
	}
}

func (portal *Portal) UpdateGroupInfo(ctx context.Context, source *User, info *signalmeow.Group, revision uint32, forceFetch bool) *signalmeow.Group {
	logWith := zerolog.Ctx(ctx).With().
		Str("function", "UpdateGroupInfo").
		Uint32("revision", revision).
		Stringer("source_user_mxid", source.MXID)
	if info != nil {
		logWith = logWith.Uint32("info_revision", info.Revision)
	}
	log := logWith.Logger()
	if info == nil {
		if revision <= portal.Revision && !forceFetch {
			log.Debug().Msg("Not fetching group info to update portal: given revision is not newer")
			return nil
		}
		log.Debug().Msg("Fetching group info to update portal")
		var err error
		info, err = source.Client.RetrieveGroupByID(ctx, portal.GroupID(), revision)
		if err != nil {
			log.Err(err).
				Stringer("source_user_id", source.MXID).
				Msg("Failed to fetch group info")
			return nil
		}
	}
	if portal.Revision > info.Revision {
		log.Debug().Uint32("current_revision", portal.Revision).Msg("Not updating portal with data from older revision")
		return info
	}
	logEvt := log.Trace()
	if portal.Revision != info.Revision {
		logEvt = log.Debug()
	}
	logEvt.Uint32("current_revision", portal.Revision).Msg("Updating portal info")
	ctx = log.WithContext(ctx)
	update := false
	if portal.Revision < info.Revision {
		portal.Revision = info.Revision
		update = true
	}
	update = portal.updateName(ctx, info.Title, nil) || update
	update = portal.updateTopic(ctx, info.Description, nil) || update
	update = portal.updateAvatarWithInfo(ctx, source, info, nil) || update
	update = portal.updateExpirationTimer(ctx, info.DisappearingMessagesDuration) || update
	if update {
		err := portal.Update(ctx)
		if err != nil {
			log.Err(err).Msg("Failed to save portal in database after updating group info")
		}
		portal.UpdateBridgeInfo(ctx)
	}
	return info
}

func (portal *Portal) updateExpirationTimer(ctx context.Context, newExpirationTimer uint32) bool {
	if portal.ExpirationTime == newExpirationTimer {
		return false
	}
	portal.ExpirationTime = newExpirationTimer
	if portal.MXID != "" {
		msg := portal.MsgConv.ConvertDisappearingTimerChangeToMatrix(ctx, newExpirationTimer, false)
		_, err := portal.sendMainIntentMessage(ctx, msg.Content)
		if err != nil {
			zerolog.Ctx(ctx).Err(err).Msg("Failed to send notice about disappearing message timer changing")
		}
	}
	return true
}

func (portal *Portal) updateName(ctx context.Context, newName string, sender *Puppet) bool {
	if portal.Name == newName && (portal.NameSet || portal.MXID == "") {
		return false
	}
	portal.Name = newName
	portal.NameSet = false
	if portal.MXID != "" {
		intent := portal.MainIntent()
		if sender != nil {
			intent = sender.IntentFor(portal)
		}
		_, err := intent.SetRoomName(ctx, portal.MXID, portal.Name)
		if errors.Is(err, mautrix.MForbidden) && intent != portal.MainIntent() {
			_, err = portal.MainIntent().SetRoomName(ctx, portal.MXID, portal.Name)
		}
		if err != nil {
			zerolog.Ctx(ctx).Err(err).Msg("Failed to update room name")
		} else {
			portal.NameSet = true
		}
	}
	return true
}

func (portal *Portal) updateTopic(ctx context.Context, newTopic string, sender *Puppet) bool {
	if portal.Topic == newTopic && (portal.TopicSet || portal.MXID == "") {
		return false
	}
	portal.Topic = newTopic
	portal.TopicSet = false
	if portal.MXID != "" {
		intent := portal.MainIntent()
		if sender != nil {
			intent = sender.IntentFor(portal)
		}
		_, err := intent.SetRoomTopic(ctx, portal.MXID, portal.Topic)
		if errors.Is(err, mautrix.MForbidden) && intent != portal.MainIntent() {
			_, err = portal.MainIntent().SetRoomTopic(ctx, portal.MXID, portal.Topic)
		}
		if err != nil {
			zerolog.Ctx(ctx).Err(err).Msg("Failed to update room topic")
		} else {
			portal.TopicSet = true
		}
	}
	return true
}

func (portal *Portal) updateAvatarWithInfo(ctx context.Context, source *User, group signalmeow.GroupAvatarMeta, sender *Puppet) bool {
	// If the avatar path is different, the avatar probably changed
	avatarPath := group.GetAvatarPath()
	if avatarPath == nil {
		return false
	}
	if portal.AvatarPath == *avatarPath &&
		// If the avatar mxc isn't set, we need to reupload it (except if the avatar is unset in Signal)
		(!portal.AvatarURL.IsEmpty() || *avatarPath == "") &&
		// If the avatar isn't set in the room, we need to update the room state (except if there's no Matrix room yet)
		(portal.AvatarSet || portal.MXID == "") {
		return false
	}
	if *avatarPath == "" {
		portal.AvatarPath = ""
		portal.AvatarSet = false
		portal.AvatarURL = id.ContentURI{}
		portal.AvatarHash = ""
		// Just clear the Matrix room avatar and return
		portal.updateAvatarInRoom(ctx, sender)
		return true
	}
	log := zerolog.Ctx(ctx)
	log.Debug().Str("avatar_path", portal.AvatarPath).Msg("Downloading new group avatar from Signal")
	avatarBytes, err := source.Client.DownloadGroupAvatar(ctx, group)
	if err != nil {
		log.Err(err).Msg("Failed to download new avatar for portal")
		return true
	}
	hash := sha256.Sum256(avatarBytes)
	newAvatarHash := hex.EncodeToString(hash[:])
	if portal.AvatarHash == newAvatarHash && (portal.AvatarSet || portal.MXID == "") {
		// No need to change anything else, but save the new path to the database
		return true
	}
	portal.AvatarPath = *avatarPath
	portal.AvatarSet = false
	portal.AvatarURL = id.ContentURI{}
	portal.AvatarHash = newAvatarHash
	log.Debug().Str("avatar_hash", portal.AvatarHash).Msg("Uploading new group avatar to Matrix")
	resp, err := portal.MainIntent().UploadBytes(ctx, avatarBytes, http.DetectContentType(avatarBytes))
	if err != nil {
		log.Err(err).Msg("Failed to upload new avatar for portal")
	} else {
		portal.AvatarURL = resp.ContentURI
		portal.updateAvatarInRoom(ctx, sender)
	}
	return true
}

func (portal *Portal) updateAvatarWithMXC(ctx context.Context, newAvatarPath, newAvatarHash string, newAvatarURI id.ContentURI) bool {
	if portal.AvatarHash == newAvatarHash && (portal.AvatarSet || portal.MXID == "") {
		return false
	}
	portal.AvatarPath = newAvatarPath
	portal.AvatarHash = newAvatarHash
	portal.AvatarURL = newAvatarURI
	portal.AvatarSet = false
	portal.updateAvatarInRoom(ctx, nil)
	return true
}

func (portal *Portal) updateAvatarInRoom(ctx context.Context, sender *Puppet) {
	if portal.MXID == "" || portal.AvatarSet {
		return
	}
	zerolog.Ctx(ctx).Debug().
		Str("avatar_path", portal.AvatarPath).
		Str("avatar_hash", portal.AvatarHash).
		Stringer("avatar_mxc", portal.AvatarURL).
		Msg("Updating avatar in Matrix room")
	intent := portal.MainIntent()
	if sender != nil {
		intent = sender.IntentFor(portal)
	}
	_, err := intent.SetRoomAvatar(ctx, portal.MXID, portal.AvatarURL)
	if errors.Is(err, mautrix.MForbidden) && intent != portal.MainIntent() {
		_, err = portal.MainIntent().SetRoomAvatar(ctx, portal.MXID, portal.AvatarURL)
	}
	if err != nil {
		zerolog.Ctx(ctx).Err(err).Msg("Failed to update room avatar")
	} else {
		portal.AvatarSet = true
	}
}

func (portal *Portal) SyncParticipants(ctx context.Context, source *User, info *signalmeow.Group) map[id.UserID]int {
	log := zerolog.Ctx(ctx)
	userIDs := make(map[id.UserID]int)
	currentMembers := make(map[id.UserID]event.Membership)
	if portal.MXID != "" {
		memberEventData, _ := portal.MainIntent().Members(ctx, portal.MXID, mautrix.ReqMembers{})
		for _, evt := range memberEventData.Chunk {
			evt.Content.ParseRaw(event.StateMember)
			currentMembers[id.UserID(*evt.StateKey)] = evt.Content.AsMember().Membership
		}
	}
	for _, member := range info.Members {
		puppet := portal.bridge.GetPuppetBySignalID(member.UserID)
		if puppet == nil {
			log.Warn().Stringer("signal_user_id", member.UserID).Msg("Couldn't get puppet for group member")
			continue
		}
		puppet.UpdateInfo(ctx, source)
		intent := puppet.IntentFor(portal)
		if member.UserID != source.SignalID && portal.MXID != "" {
			userIDs[intent.UserID] = ((int)(member.Role) >> 1) * 50
		}
		if portal.MXID != "" {
			err := intent.EnsureJoined(ctx, portal.MXID)
			if err != nil {
				log.Err(err).Stringer("signal_user_id", member.UserID).Msg("Failed to ensure user is joined to portal")
			}
			if puppet.customIntent == nil {
				user := portal.bridge.GetUserBySignalID(member.UserID)
				if user != nil {
					user.ensureInvited(ctx, intent, portal.MXID, false)
					userIDs[user.MXID] = ((int)(member.Role) >> 1) * 50
					delete(currentMembers, user.MXID)
				}
			}
		}
		delete(currentMembers, intent.UserID)
	}
	if portal.MXID == "" {
		return userIDs
	}
	for _, pendingMember := range info.PendingMembers {
		puppet := portal.bridge.GetPuppetBySignalID(pendingMember.UserID)
		if puppet == nil {
			log.Warn().Stringer("signal_user_id", pendingMember.UserID).Msg("Couldn't get puppet for group member")
			continue
		}
		mxid := puppet.IntentFor(portal).UserID
		membership := currentMembers[mxid]
		var err error
		if membership == event.MembershipJoin || membership == event.MembershipBan {
			_, err = portal.MainIntent().SendCustomMembershipEvent(ctx, portal.MXID, mxid, event.MembershipLeave, "")
		}
		if membership != event.MembershipInvite {
			_, err = portal.MainIntent().SendCustomMembershipEvent(ctx, portal.MXID, mxid, event.MembershipInvite, "")
		}
		if err != nil {
			log.Warn().Stringer("mxid", mxid).Msg("Couldn't change membership to invite")
		}
		userIDs[mxid] = ((int)(pendingMember.Role) >> 1) * 50
		delete(currentMembers, mxid)
		if puppet.customIntent == nil {
			user := portal.bridge.GetUserBySignalID(pendingMember.UserID)
			if user == nil {
				continue
			}
			mxid = user.MXID
			membership := currentMembers[mxid]
			err = nil
			if membership == event.MembershipJoin || membership == event.MembershipBan {
				_, err = portal.MainIntent().SendCustomMembershipEvent(ctx, portal.MXID, mxid, event.MembershipLeave, "")
			}
			if membership != event.MembershipInvite {
				_, err = portal.MainIntent().SendCustomMembershipEvent(ctx, portal.MXID, mxid, event.MembershipInvite, "")
			}
			if err != nil {
				log.Warn().Stringer("mxid", mxid).Msg("Couldn't change membership to invite")
			}
			userIDs[mxid] = ((int)(pendingMember.Role) >> 1) * 50
			delete(currentMembers, mxid)
		}
	}
	for _, requestingMember := range info.RequestingMembers {
		puppet := portal.bridge.GetPuppetBySignalID(requestingMember.UserID)
		if puppet == nil {
			log.Warn().Stringer("signal_user_id", requestingMember.UserID).Msg("Couldn't get puppet for group member")
			continue
		}
		mxid := puppet.IntentFor(portal).UserID
		membership := currentMembers[mxid]
		var err error
		if membership == event.MembershipJoin || membership == event.MembershipBan {
			_, err = portal.MainIntent().SendCustomMembershipEvent(ctx, portal.MXID, mxid, event.MembershipLeave, "")
		}
		if membership != event.MembershipKnock {
			_, err = puppet.IntentFor(portal).SendCustomMembershipEvent(ctx, portal.MXID, mxid, event.MembershipKnock, "")
		}
		if err != nil {
			log.Warn().Stringer("mxid", mxid).Msg("Couldn't change membership to knock")
		}
		delete(currentMembers, mxid)
	}
	for _, bannedMember := range info.BannedMembers {
		puppet := portal.bridge.GetPuppetBySignalID(bannedMember.UserID)
		if puppet == nil {
			log.Warn().Stringer("signal_user_id", bannedMember.UserID).Msg("Couldn't get puppet for group member")
			continue
		}
		mxid := puppet.IntentFor(portal).UserID
		var err error
		if currentMembers[mxid] != event.MembershipBan {
			_, err = portal.MainIntent().SendCustomMembershipEvent(ctx, portal.MXID, mxid, event.MembershipBan, "")
		}
		if err != nil {
			log.Warn().Stringer("mxid", mxid).Msg("Couldn't change membership to ban")
		}
		delete(currentMembers, mxid)
		if puppet.customIntent == nil {
			user := portal.bridge.GetUserBySignalID(bannedMember.UserID)
			if user == nil {
				continue
			}
			mxid = user.MXID
			err = nil
			if currentMembers[mxid] != event.MembershipBan {
				_, err = portal.MainIntent().SendCustomMembershipEvent(ctx, portal.MXID, mxid, event.MembershipBan, "")
			}
			if err != nil {
				log.Warn().Stringer("mxid", mxid).Msg("Couldn't change membership to ban")
			}
			delete(currentMembers, mxid)
		}
	}
	for mxid, _ := range currentMembers {
		user := portal.bridge.GetUserByMXIDIfExists(mxid)
		if user != nil {
			if user.IsLoggedIn() {
				_, err := portal.MainIntent().SendCustomMembershipEvent(ctx, portal.MXID, mxid, event.MembershipLeave, "")
				if err != nil {
					log.Warn().Stringer("mxid", mxid).Msg("Couldn't change membership to leave")
				}
			}
		} else {
			puppet := portal.bridge.GetPuppetByMXID(mxid)
			if puppet != nil {
				_, err := portal.MainIntent().SendCustomMembershipEvent(ctx, portal.MXID, mxid, event.MembershipLeave, "")
				if err != nil {
					log.Warn().Stringer("mxid", mxid).Msg("Couldn't change membership to leave")
				}
			}
		}
	}
	return userIDs
}

func (portal *Portal) getBridgeInfoStateKey() string {
	return fmt.Sprintf("net.maunium.signal://signal/%s", portal.ChatID)
}

func (portal *Portal) ScheduleDisappearing() {
	portal.bridge.disappearingMessagesManager.ScheduleDisappearingForRoom(context.TODO(), portal.MXID)
}

func (portal *Portal) addToPersonalSpace(ctx context.Context, user *User) bool {
	spaceID := user.GetSpaceRoom(ctx)
	if len(spaceID) == 0 || user.IsInSpace(ctx, portal.PortalKey) {
		return false
	}
	_, err := portal.bridge.Bot.SendStateEvent(ctx, spaceID, event.StateSpaceChild, portal.MXID.String(), &event.SpaceChildEventContent{
		Via: []string{portal.bridge.Config.Homeserver.Domain},
	})
	if err != nil {
		zerolog.Ctx(ctx).Err(err).
			Stringer("user_id", user.MXID).
			Stringer("space_id", spaceID).
			Msg("Failed to add room to user's personal filtering space")
		return false
	} else {
		zerolog.Ctx(ctx).Debug().
			Stringer("user_id", user.MXID).
			Stringer("space_id", spaceID).
			Msg("Added room to user's personal filtering space")
		user.MarkInSpace(ctx, portal.PortalKey)
		return true
	}
}

func (portal *Portal) HasRelaybot() bool {
	return portal.bridge.Config.Bridge.Relay.Enabled && len(portal.RelayUserID) > 0
}

func (portal *Portal) addRelaybotFormat(ctx context.Context, userID id.UserID, evt *event.Event, content *event.MessageEventContent) bool {
	member := portal.MainIntent().Member(ctx, portal.MXID, userID)
	if member == nil {
		member = &event.MemberEventContent{}
	}
	// Stickers can't have captions, so force them into images when relaying
	if evt.Type == event.EventSticker {
		content.MsgType = event.MsgImage
		evt.Type = event.EventMessage
	}
	content.EnsureHasHTML()
	data, err := portal.bridge.Config.Bridge.Relay.FormatMessage(content, userID, *member)
	if err != nil {
		portal.log.Err(err).Msg("Failed to apply relaybot format")
	}
	content.FormattedBody = data
	// Force FileName field so the formatted body is used as a caption
	if content.FileName == "" {
		content.FileName = content.Body
	}
	return true
}

func (portal *Portal) Delete() {
	err := portal.Portal.Delete(context.TODO())
	if err != nil {
		portal.log.Err(err).Msg("Failed to delete portal from db")
	}
	portal.bridge.portalsLock.Lock()
	delete(portal.bridge.portalsByID, portal.PortalKey)
	if len(portal.MXID) > 0 {
		delete(portal.bridge.portalsByMXID, portal.MXID)
	}
	if portal.Receiver == uuid.Nil {
		portal.bridge.usersLock.Lock()
		for _, user := range portal.bridge.usersBySignalID {
			user.RemoveInSpaceCache(portal.PortalKey)
		}
		portal.bridge.usersLock.Unlock()
	} else {
		user := portal.bridge.GetUserBySignalID(portal.Receiver)
		if user != nil {
			user.RemoveInSpaceCache(portal.PortalKey)
		}
	}
	portal.bridge.portalsLock.Unlock()
}

func (portal *Portal) Cleanup(ctx context.Context, puppetsOnly bool) {
	portal.bridge.CleanupRoom(ctx, &portal.log, portal.MainIntent(), portal.MXID, puppetsOnly)
}

func (br *SignalBridge) CleanupRoom(ctx context.Context, log *zerolog.Logger, intent *appservice.IntentAPI, mxid id.RoomID, puppetsOnly bool) {
	if len(mxid) == 0 {
		return
	}
	if br.SpecVersions.Supports(mautrix.BeeperFeatureRoomYeeting) {
		err := intent.BeeperDeleteRoom(ctx, mxid)
		if err == nil || errors.Is(err, mautrix.MNotFound) {
			return
		}
		log.Warn().Err(err).Msg("Failed to delete room using beeper yeet endpoint, falling back to normal behavior")
	}
	members, err := intent.JoinedMembers(ctx, mxid)
	if err != nil {
		log.Err(err).Msg("Failed to get portal members for cleanup")
		return
	}
	for member := range members.Joined {
		if member == intent.UserID {
			continue
		}
		puppet := br.GetPuppetByMXID(member)
		if puppet != nil {
			_, err = puppet.DefaultIntent().LeaveRoom(ctx, mxid)
			if err != nil {
				log.Err(err).Msg("Failed to leave as puppet while cleaning up portal")
			}
		} else if !puppetsOnly {
			_, err = intent.KickUser(ctx, mxid, &mautrix.ReqKickUser{UserID: member, Reason: "Deleting portal"})
			if err != nil {
				log.Err(err).Msg("Failed to kick user while cleaning up portal")
			}
		}
	}
	_, err = intent.LeaveRoom(ctx, mxid)
	if err != nil {
		log.Err(err).Msg("Failed to leave room while cleaning up portal")
	}
}
