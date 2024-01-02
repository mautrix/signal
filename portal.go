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
	"bytes"
	"context"
	"errors"
	"fmt"
	"image"
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
	"maunium.net/go/mautrix/crypto/attachment"
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

	latestReadTimestamp uint64 // Cache the latest read timestamp to avoid unnecessary read receipts

	relayUser *User
}

const recentMessageBufferSize = 32

func init() {
	event.TypeMap[event.StateBridge] = reflect.TypeOf(CustomBridgeInfoContent{})
	event.TypeMap[event.StateHalfShotBridge] = reflect.TypeOf(CustomBridgeInfoContent{})
}

// ** Interfaces that Portal implements **

var _ bridge.Portal = (*Portal)(nil)

var _ bridge.ReadReceiptHandlingPortal = (*Portal)(nil)
var _ bridge.TypingPortal = (*Portal)(nil)
var _ bridge.DisappearingPortal = (*Portal)(nil)

//var _ bridge.MembershipHandlingPortal = (*Portal)(nil)
//var _ bridge.MetaHandlingPortal = (*Portal)(nil)

// ** bridge.Portal Interface **

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

func isUUID(s string) bool {
	if _, uuidErr := uuid.Parse(s); uuidErr == nil {
		return true
	}
	return false
}

func (portal *Portal) IsPrivateChat() bool {
	// If ChatID is a UUID, it's a private chat, otherwise it's base64 and a group chat
	return isUUID(portal.ChatID)
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
	var bridgeInfoStateKey string
	bridgeInfoStateKey = fmt.Sprintf("fi.mau.signal://signal/%s", portal.ChatID)
	bridgeInfo.Channel.ExternalURL = fmt.Sprintf("https://signal.me/#p/%s", portal.ChatID)
	var roomType string
	if portal.IsPrivateChat() {
		roomType = "dm"
	}
	return bridgeInfoStateKey, CustomBridgeInfoContent{bridgeInfo, roomType}
}

func (portal *Portal) UpdateBridgeInfo() {
	if len(portal.MXID) == 0 {
		portal.log.Debug().Msg("Not updating bridge info: no Matrix room created")
		return
	}
	portal.log.Debug().Msg("Updating bridge info...")
	stateKey, content := portal.getBridgeInfo()
	_, err := portal.MainIntent().SendStateEvent(portal.MXID, event.StateBridge, stateKey, content)
	if err != nil {
		portal.log.Warn().Msgf("Failed to update m.bridge: %v", err)
	}
	// TODO remove this once https://github.com/matrix-org/matrix-doc/pull/2346 is in spec
	_, err = portal.MainIntent().SendStateEvent(portal.MXID, event.StateHalfShotBridge, stateKey, content)
	if err != nil {
		portal.log.Warn().Msgf("Failed to update uk.half-shot.bridge: %v", err)
	}
}

// ** bridge.ChildOverride methods (for SignalBridge in main.go) **

func (br *SignalBridge) GetAllPortalsWithMXID() []*Portal {
	portals, err := br.dbPortalsToPortals(br.DB.Portal.GetAllWithMXID(context.TODO()))
	if err != nil {
		br.ZLog.Err(err).Msg("Failed to get all portals with mxid")
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

// ** Portal Creation and Message Handling **

var signalFormatParams *signalfmt.FormatParams
var matrixFormatParams *matrixfmt.HTMLParser

func (br *SignalBridge) NewPortal(dbPortal *database.Portal) *Portal {
	portal := &Portal{
		Portal: dbPortal,
		bridge: br,
		log:    br.ZLog.With().Str("chat_id", dbPortal.ChatID).Logger(),

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
	// If we have no SignalDevice, the bridge isn't logged in properly,
	// so send BAD_CREDENTIALS so the user knows
	if !msg.user.SignalDevice.IsDeviceLoggedIn() && !portal.HasRelaybot() {
		go portal.sendMessageMetrics(msg.evt, errUserNotLoggedIn, "Ignoring", nil)
		msg.user.BridgeState.Send(status.BridgeState{StateEvent: status.StateBadCredentials, Message: "You have been logged out of Signal, please reconnect"})
		return
	}
	log := portal.log.With().
		Str("action", "handle matrix event").
		Str("event_id", msg.evt.ID.String()).
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
		log.Warn().Str("type", msg.evt.Type.String()).Msg("Unhandled matrix message type")
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
	timings.implicitRR = time.Since(implicitRRStart)
	start := time.Now()

	messageAge := timings.totalReceive
	ms := metricSender{portal: portal, timings: &timings}
	log.Debug().
		Str("sender", evt.Sender.String()).
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
		if !portal.HasRelaybot() {
			go ms.sendMessageMetrics(evt, errUserNotLoggedIn, "Error converting", true)
			return
		}
		sender = portal.GetRelayUser()
		if !sender.IsLoggedIn() {
			go ms.sendMessageMetrics(evt, errRelaybotNotLoggedIn, "Error converting", true)
			return
		}
		isRelay = true
	}

	var editTargetMsg *database.Message
	if editTarget := content.RelatesTo.GetReplaceID(); editTarget != "" {
		var err error
		editTargetMsg, err = portal.bridge.DB.Message.GetByMXID(ctx, editTarget)
		if err != nil {
			log.Err(err).Str("edit_target_mxid", editTarget.String()).Msg("Failed to get edit target message")
			go ms.sendMessageMetrics(evt, errFailedToGetEditTarget, "Error converting", true)
			return
		} else if editTargetMsg == nil {
			log.Err(err).Str("edit_target_mxid", editTarget.String()).Msg("Edit target message not found")
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

	if evt.Type == event.EventSticker {
		content.MsgType = event.MessageType(event.EventSticker.Type)
	}
	relaybotFormatted := isRelay && portal.addRelaybotFormat(realSenderMXID, content)
	if relaybotFormatted && content.FileName == "" {
		content.FileName = content.Body
	}
	if content.MsgType == event.MsgNotice && !portal.bridge.Config.Bridge.BridgeNotices {
		go ms.sendMessageMetrics(evt, errMNoticeDisabled, "Error converting", true)
		return
	}
	if content.MsgType == event.MsgEmote && !relaybotFormatted {
		content.Body = "/me " + content.Body
		if content.FormattedBody != "" {
			content.FormattedBody = "/me " + content.FormattedBody
		}
	}
	trustTimestamp := !relaybotFormatted
	ctx = context.WithValue(ctx, msgconvContextKeyClient, sender.SignalDevice)
	msg, err := portal.MsgConv.ToSignal(ctx, evt, trustTimestamp)
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
	if dbMessage == nil && dbReaction == nil {
		portal.sendMessageStatusCheckpointFailed(evt, errors.New("could not find original message or reaction"))
		log.Warn().Msg("No target message or reaction found for redaction")
		return
	}

	if !sender.IsLoggedIn() {
		sender = portal.GetRelayUser()
	}

	// If this is a message redaction, send a redaction to Signal
	if dbMessage != nil {
		msg := signalmeow.DataMessageForDelete(dbMessage.Timestamp)
		err = portal.sendSignalMessage(ctx, msg, sender, evt.ID)
		if err != nil {
			portal.sendMessageStatusCheckpointFailed(evt, err)
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
				_, err = portal.MainIntent().RedactEvent(portal.MXID, otherPart.MXID, mautrix.ReqRedact{
					Reason: "Other part of Signal message redacted",
					TxnID:  "mxsg_partredact_" + otherPart.MXID.String(),
				})
				if err != nil {
					log.Err(err).
						Str("part_event_id", otherPart.MXID.String()).
						Int("part_index", otherPart.PartIndex).
						Msg("Failed to redact other part of redacted message")
				}
				err = otherPart.Delete(ctx)
				if err != nil {
					log.Err(err).
						Str("part_event_id", otherPart.MXID.String()).
						Int("part_index", otherPart.PartIndex).
						Msg("Failed to delete other part of redacted message from database")
				}
			}
		}

	}

	if dbReaction != nil {
		msg := signalmeow.DataMessageForReaction(dbReaction.Emoji, dbReaction.MsgAuthor, dbReaction.MsgTimestamp, true)
		err = portal.sendSignalMessage(ctx, msg, sender, evt.ID)
		if err != nil {
			portal.sendMessageStatusCheckpointFailed(evt, err)
			log.Err(err).Msg("Failed to send reaction redaction to Signal")
			return
		}
		err = dbReaction.Delete(ctx)
		if err != nil {
			log.Err(err).Msg("Failed to delete redacted reaction from database")
		}
	}

	portal.sendMessageStatusCheckpointSuccess(evt)
}

func (portal *Portal) handleMatrixReaction(ctx context.Context, sender *User, evt *event.Event) {
	log := zerolog.Ctx(ctx)
	if !sender.IsLoggedIn() {
		log.Error().Msg("Cannot relay reaction from non-logged-in user. Ignoring")
		return
	}
	// Find the original signal message based on eventID
	relatedEventID := evt.Content.AsReaction().RelatesTo.EventID
	dbMessage, err := portal.bridge.DB.Message.GetByMXID(ctx, relatedEventID)
	if err != nil {
		portal.sendMessageStatusCheckpointFailed(evt, err)
		log.Err(err).Msg("Failed to get reaction target message")
		return
	} else if dbMessage == nil {
		portal.sendMessageStatusCheckpointFailed(evt, errors.New("could not find original message for reaction"))
		log.Warn().Msg("No target message found for reaction")
		return
	}
	emoji := evt.Content.AsReaction().RelatesTo.Key
	signalEmoji := variationselector.FullyQualify(emoji) // Signal seems to require fully qualified emojis
	targetAuthorUUID := dbMessage.Sender
	targetTimestamp := dbMessage.Timestamp
	msg := signalmeow.DataMessageForReaction(signalEmoji, targetAuthorUUID, targetTimestamp, false)
	err = portal.sendSignalMessage(ctx, msg, sender, evt.ID)
	if err != nil {
		portal.sendMessageStatusCheckpointFailed(evt, err)
		portal.log.Error().Msgf("Failed to send reaction %s", evt.ID)
		return
	}

	// Signal only allows one reaction from each user
	// Check if there's an existing reaction in the database for this sender and redact/delete it
	dbReaction, err := portal.bridge.DB.Reaction.GetBySignalID(
		ctx,
		targetAuthorUUID,
		targetTimestamp,
		sender.SignalID,
		portal.Receiver,
	)
	if err != nil {
		log.Err(err).Msg("Failed to get existing reaction from database")
	} else if dbReaction != nil {
		log.Debug().Str("existing_event_id", dbReaction.MXID.String()).Msg("Redacting existing reaction after sending new one")
		_, err = portal.MainIntent().RedactEvent(portal.MXID, dbReaction.MXID)
		if err != nil {
			log.Err(err).Msg("Failed to redact existing reaction")
		}
		// TODO update instead of deleting
		err = dbReaction.Delete(ctx)
		if err != nil {
			log.Err(err).Msg("Failed to delete reaction from database")
		}
	}

	// Store our new reaction in the database
	portal.storeReactionInDB(ctx, evt.ID, sender.SignalID, targetAuthorUUID, targetTimestamp, signalEmoji)

	portal.sendMessageStatusCheckpointSuccess(evt)
}

func (portal *Portal) sendSignalMessage(ctx context.Context, msg *signalpb.Content, sender *User, evtID id.EventID) error {
	recipientSignalID := portal.ChatID
	portal.log.Debug().Msgf("Sending event %s to Signal %s", evtID, recipientSignalID)

	// Check to see if recipientSignalID is a standard UUID (with dashes)
	var err error
	if _, uuidErr := uuid.Parse(recipientSignalID); uuidErr == nil {
		// this is a 1:1 chat
		result := signalmeow.SendMessage(ctx, sender.SignalDevice, recipientSignalID, msg)
		if !result.WasSuccessful {
			err = result.FailedSendResult.Error
			portal.log.Error().Msgf("Error sending event %s to Signal %s: %s", evtID, recipientSignalID, err)
		}
	} else {
		// this is a group chat
		groupID := types.GroupIdentifier(recipientSignalID)
		result, err := signalmeow.SendGroupMessage(ctx, sender.SignalDevice, groupID, msg)
		if err != nil {
			// check the start of the error string, see if it starts with "No group master key found for group identifier"
			if strings.HasPrefix(err.Error(), "No group master key found for group identifier") {
				portal.MainIntent().SendNotice(portal.MXID, "Missing group encryption key. Please ask a group member to send a message in this chat, then retry sending.")
			}
			portal.log.Error().Msgf("Error sending event %s to Signal group %s: %s", evtID, recipientSignalID, err)
			return err
		}
		totalRecipients := len(result.FailedToSendTo) + len(result.SuccessfullySentTo)
		if len(result.FailedToSendTo) > 0 {
			portal.log.Error().Msgf("Failed to send event %s to %d of %d members of Signal group %s", evtID, len(result.FailedToSendTo), totalRecipients, recipientSignalID)
		}
		if len(result.SuccessfullySentTo) == 0 && len(result.FailedToSendTo) == 0 {
			portal.log.Debug().Msgf("No successes or failures - Probably sent to myself")
		} else if len(result.SuccessfullySentTo) == 0 {
			portal.log.Error().Msgf("Failed to send event %s to all %d members of Signal group %s", evtID, totalRecipients, recipientSignalID)
			err = errors.New("failed to send to any members of Signal group")
		} else if len(result.SuccessfullySentTo) < totalRecipients {
			portal.log.Warn().Msgf("Only sent event %s to %d of %d members of Signal group %s", evtID, len(result.SuccessfullySentTo), totalRecipients, recipientSignalID)
		} else {
			portal.log.Debug().Msgf("Sent event %s to all %d members of Signal group %s", evtID, totalRecipients, recipientSignalID)
		}
	}
	return err
}

func (portal *Portal) sendMessageStatusCheckpointSuccess(evt *event.Event) {
	portal.sendDeliveryReceipt(evt.ID)
	portal.bridge.SendMessageSuccessCheckpoint(evt, status.MsgStepRemote, 0)

	var deliveredTo *[]id.UserID
	if portal.IsPrivateChat() {
		deliveredTo = &[]id.UserID{}
	}
	portal.sendStatusEvent(evt.ID, "", nil, deliveredTo)
}

func (portal *Portal) sendMessageStatusCheckpointFailed(evt *event.Event, err error) {
	portal.sendDeliveryReceipt(evt.ID)
	portal.bridge.SendMessageErrorCheckpoint(evt, status.MsgStepRemote, err, true, 0)
	portal.sendStatusEvent(evt.ID, "", err, nil)
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
		uploaded, err := intent.UploadAsync(req)
		if err != nil {
			return "", err
		}
		return uploaded.ContentURI.CUString(), nil
	} else {
		uploaded, err := intent.UploadMedia(req)
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
	return portal.MainIntent().DownloadBytesContext(ctx, parsedURI)
}

func (portal *Portal) GetData(ctx context.Context) *database.Portal {
	return portal.Portal
}

func (portal *Portal) GetClient(ctx context.Context) *signalmeow.Device {
	return ctx.Value(msgconvContextKeyClient).(*signalmeow.Device)
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
			Str("reply_to_mxid", replyToID.String()).
			Msg("Failed to get reply target message from database")
	} else if replyToMsg == nil {
		zerolog.Ctx(ctx).Warn().
			Str("reply_to_mxid", replyToID.String()).
			Msg("Reply target message not found")
	} else {
		return &signalpb.DataMessage_Quote{
			Id:        proto.Uint64(replyToMsg.Timestamp),
			AuthorAci: proto.String(replyToMsg.Sender.String()),
			Type:      signalpb.DataMessage_Quote_NORMAL.Enum(),

			// This is a hack to make Signal iOS and desktop render replies to file messages.
			// Unfortunately it also makes Signal Desktop show a file icon on replies to text messages.
			// TODO store file or text flag in database and fill this field only when replying to file messages.
			Attachments: make([]*signalpb.DataMessage_Quote_QuotedAttachment, 0),
		}
	}
	return nil
}

func (portal *Portal) handleSignalMessage(portalMessage portalSignalMessage) {
	sender := portal.bridge.GetPuppetBySignalID(portalMessage.evt.Info.Sender)
	if sender == nil {
		portal.log.Warn().
			Str("sender_uuid", portalMessage.evt.Info.Sender.String()).
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
	// FIXME hacky
	updatePuppetWithSignalContact(context.TODO(), source, sender, nil)

	switch {
	case msgconv.CanConvertSignal(msg):
		portal.handleSignalNormalDataMessage(source, sender, msg)
	case msg.Reaction != nil:
		portal.handleSignalReaction(sender, msg.Reaction, msg.GetTimestamp())
	case msg.Delete != nil:
		portal.handleSignalDelete(sender, msg.Delete, msg.GetTimestamp())
	case msg.StoryContext != nil, msg.GroupCallUpdate != nil:
		// ignore
	default:
		portal.log.Warn().
			Str("action", "handle signal message").
			Str("sender_uuid", sender.SignalID.String()).
			Uint64("msg_ts", msg.GetTimestamp()).
			Msg("Unrecognized content in message")
	}
}

func (portal *Portal) handleSignalReaction(sender *Puppet, react *signalpb.DataMessage_Reaction, ts uint64) {
	log := portal.log.With().
		Str("action", "handle signal reaction").
		Str("sender_uuid", sender.SignalID.String()).
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
	}
	intent := sender.IntentFor(portal)
	if existingReaction != nil {
		_, err = intent.RedactEvent(portal.MXID, existingReaction.MXID, mautrix.ReqRedact{
			TxnID: "mxsg_unreact_" + existingReaction.MXID.String(),
		})
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
	resp, err := portal.sendMatrixEvent(intent, event.EventReaction, content, nil, int64(ts))
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
		Str("sender_uuid", sender.SignalID.String()).
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
		_, err = intent.RedactEvent(portal.MXID, part.MXID, mautrix.ReqRedact{
			TxnID: "mxsg_delete_" + part.MXID.String(),
		})
		if err != nil {
			log.Err(err).
				Int("part_index", part.PartIndex).
				Str("event_id", part.MXID.String()).
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
		Str("sender_uuid", sender.SignalID.String()).
		Uint64("msg_ts", msg.GetTimestamp()).
		Logger()
	ctx := log.WithContext(context.TODO())
	if portal.MXID == "" {
		log.Debug().Msg("Creating Matrix room from incoming message")
		if err := portal.CreateMatrixRoom(source, nil); err != nil {
			log.Error().Err(err).Msg("Failed to create portal room")
			return
		}
		// FIXME hacky
		ensureGroupPuppetsAreJoinedToPortal(context.Background(), source, portal)
		signalmeow.SendContactSyncRequest(context.TODO(), source.SignalDevice)
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
		resp, err := portal.sendMatrixEvent(intent, part.Type, part.Content, part.Extra, int64(converted.Timestamp))
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
		Str("sender_uuid", sender.SignalID.String()).
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
		_, err = portal.sendMatrixEvent(intent, part.Type, part.Content, part.Extra, int64(converted.Timestamp))
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
	intent := sender.IntentFor(portal)
	// Don't bridge double puppeted typing notifications to avoid echoing
	if intent.IsCustomPuppet {
		return
	}
	var err error
	switch msg.GetAction() {
	case signalpb.TypingMessage_STARTED:
		_, err = intent.UserTyping(portal.MXID, true, SignalTypingTimeout)
	case signalpb.TypingMessage_STOPPED:
		_, err = intent.UserTyping(portal.MXID, false, 0)
	}
	if err != nil {
		portal.log.Err(err).
			Str("user_id", sender.SignalID.String()).
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

func (portal *Portal) storeReactionInDB(
	ctx context.Context,
	eventID id.EventID,
	senderSignalID,
	msgAuthor uuid.UUID,
	msgTimestamp uint64,
	emoji string,
) {
	dbReaction := portal.bridge.DB.Reaction.New()
	dbReaction.MXID = eventID
	dbReaction.RoomID = portal.MXID
	dbReaction.SignalChatID = portal.ChatID
	dbReaction.SignalReceiver = portal.Receiver
	dbReaction.Author = senderSignalID
	dbReaction.MsgAuthor = msgAuthor
	dbReaction.MsgTimestamp = msgTimestamp
	dbReaction.Emoji = emoji
	err := dbReaction.Insert(ctx)
	if err != nil {
		portal.log.Err(err).Msg("Failed to insert reaction into database")
	}
}

func (portal *Portal) addDisappearingMessage(ctx context.Context, eventID id.EventID, expireInSeconds uint32, startTimerNow bool) {
	portal.bridge.disappearingMessagesManager.AddDisappearingMessage(ctx, eventID, portal.MXID, time.Duration(expireInSeconds)*time.Second, startTimerNow)
}

func (portal *Portal) MarkDelivered(msg *database.Message) {
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
	portal.sendStatusEvent(msg.MXID, "", nil, &[]id.UserID{portal.MainIntent().UserID})
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

func (portal *Portal) SendReadReceipt(sender *Puppet, msg *database.Message) error {
	intent := sender.IntentFor(portal)
	if intent.IsCustomPuppet {
		extra := customReadReceipt{DoublePuppetSource: portal.bridge.Name}
		return intent.SetReadMarkers(portal.MXID, &customReadMarkers{
			ReqSetReadMarkers: mautrix.ReqSetReadMarkers{
				Read:      msg.MXID,
				FullyRead: msg.MXID,
			},
			ReadExtra:      extra,
			FullyReadExtra: extra,
		})
	} else {
		return intent.MarkRead(portal.MXID, msg.MXID)
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
		recipientSignalID := portal.ChatID

		// Check to see if recipientSignalID is a standard UUID (with dashes)
		// Note: not handling sending to a group right now, since that will
		// require SenderKey sending to not be terrible
		var err error
		if _, uuidErr := uuid.Parse(recipientSignalID); uuidErr == nil {
			// this is a 1:1 chat
			portal.log.Debug().Msgf("Sending Typing event to Signal %s", recipientSignalID)
			ctx := context.Background()
			typingMessage := signalmeow.TypingMessage(isTyping)
			result := signalmeow.SendMessage(ctx, user.SignalDevice, recipientSignalID, typingMessage)
			if !result.WasSuccessful {
				err = result.FailedSendResult.Error
				portal.log.Error().Msgf("Error sending event to Signal %s: %s", recipientSignalID, err)
			}
		}
	}
}

// mautrix-go TypingPortal interface
func (portal *Portal) HandleMatrixTyping(newTyping []id.UserID) {
	portal.currentlyTypingLock.Lock()
	defer portal.currentlyTypingLock.Unlock()
	startedTyping, stoppedTyping := typingDiff(portal.currentlyTyping, newTyping)
	portal.currentlyTyping = newTyping
	portal.setTyping(startedTyping, true)
	portal.setTyping(stoppedTyping, false)
}

// mautrix-go ReadReceiptHandlingPortal interface
func (portal *Portal) HandleMatrixReadReceipt(sender bridge.User, eventID id.EventID, receipt event.ReadReceipt) {
	log := portal.log.With().
		Str("action", "handle matrix read receipt").
		Str("event_id", eventID.String()).
		Str("sender", sender.GetMXID().String()).
		Logger()
	log.Debug().Msg("Received read receipt")
	portal.ScheduleDisappearing()

	// Find event in the DB
	dbMessage, err := portal.bridge.DB.Message.GetByMXID(context.TODO(), eventID)
	if err != nil {
		log.Err(err).Msg("Failed to get read receipt target message")
		return
	} else if dbMessage == nil {
		log.Debug().Msg("Read receipt target message not found")
		return
	}
	// TODO find all messages that haven't been marked as read by the user
	msg := signalmeow.ReadReceptMessageForTimestamps([]uint64{dbMessage.Timestamp})
	receiptDestination := dbMessage.Sender
	receiptSender := sender.(*User)

	// Don't use portal.sendSignalMessage because we're sending this straight to
	// who sent the original message, not the portal's ChatID
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	result := signalmeow.SendMessage(ctx, receiptSender.SignalDevice, receiptDestination.String(), msg)
	if !result.WasSuccessful {
		log.Err(result.FailedSendResult.Error).
			Str("receipt_destination", receiptDestination.String()).
			Msg("Failed to send read receipt to Signal")
	} else {
		log.Debug().Str("receipt_destination", receiptDestination.String()).Msg("Sent read receipt to Signal")
	}
}

func (portal *Portal) sendMainIntentMessage(content *event.MessageEventContent) (*mautrix.RespSendEvent, error) {
	return portal.sendMatrixEvent(portal.MainIntent(), event.EventMessage, content, nil, 0)
}

func (portal *Portal) encrypt(intent *appservice.IntentAPI, content *event.Content, eventType event.Type) (event.Type, error) {
	if !portal.Encrypted || portal.bridge.Crypto == nil {
		return eventType, nil
	}
	intent.AddDoublePuppetValue(content)
	// TODO maybe the locking should be inside mautrix-go?
	portal.encryptLock.Lock()
	defer portal.encryptLock.Unlock()
	err := portal.bridge.Crypto.Encrypt(portal.MXID, eventType, content)
	if err != nil {
		return eventType, fmt.Errorf("failed to encrypt event: %w", err)
	}
	return event.EventEncrypted, nil
}

func (portal *Portal) encryptFileInPlace(data []byte, mimeType string) (string, *event.EncryptedFileInfo) {
	if !portal.Encrypted {
		return mimeType, nil
	}

	file := &event.EncryptedFileInfo{
		EncryptedFile: *attachment.NewEncryptedFile(),
		URL:           "",
	}
	file.EncryptInPlace(data)
	return "application/octet-stream", file
}

func (portal *Portal) uploadMediaToMatrix(intent *appservice.IntentAPI, data []byte, content *event.MessageEventContent) error {
	uploadMimeType, file := portal.encryptFileInPlace(data, content.Info.MimeType)

	req := mautrix.ReqUploadMedia{
		ContentBytes: data,
		ContentType:  uploadMimeType,
	}
	var mxc id.ContentURI
	if portal.bridge.Config.Homeserver.AsyncMedia {
		uploaded, err := intent.UploadAsync(req)
		if err != nil {
			return err
		}
		mxc = uploaded.ContentURI
	} else {
		uploaded, err := intent.UploadMedia(req)
		if err != nil {
			return err
		}
		mxc = uploaded.ContentURI
	}

	if file != nil {
		file.URL = mxc.CUString()
		content.File = file
	} else {
		content.URL = mxc.CUString()
	}

	content.Info.Size = len(data)
	if content.Info.Width == 0 && content.Info.Height == 0 && strings.HasPrefix(content.Info.MimeType, "image/") {
		cfg, _, _ := image.DecodeConfig(bytes.NewReader(data))
		content.Info.Width, content.Info.Height = cfg.Width, cfg.Height
	}

	// This is a hack for bad clients like Element iOS that require a thumbnail (https://github.com/vector-im/element-ios/issues/4004)
	if strings.HasPrefix(content.Info.MimeType, "image/") && content.Info.ThumbnailInfo == nil {
		infoCopy := *content.Info
		content.Info.ThumbnailInfo = &infoCopy
		if content.File != nil {
			content.Info.ThumbnailFile = file
		} else {
			content.Info.ThumbnailURL = content.URL
		}
	}
	return nil
}

func (portal *Portal) sendMatrixEvent(intent *appservice.IntentAPI, eventType event.Type, content any, extraContent map[string]any, timestamp int64) (*mautrix.RespSendEvent, error) {
	wrappedContent := event.Content{Parsed: content, Raw: extraContent}
	if eventType != event.EventReaction {
		var err error
		eventType, err = portal.encrypt(intent, &wrappedContent, eventType)
		if err != nil {
			return nil, err
		}
	}

	_, _ = intent.UserTyping(portal.MXID, false, 0)
	return intent.SendMassagedMessageEvent(portal.MXID, eventType, &wrappedContent, timestamp)
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

func (portal *Portal) ensureUserInvited(user *User) bool {
	return user.ensureInvited(portal.MainIntent(), portal.MXID, portal.IsPrivateChat())
}

func (portal *Portal) CreateMatrixRoom(user *User, meta *any) error {
	portal.roomCreateLock.Lock()
	defer portal.roomCreateLock.Unlock()
	if portal.MXID != "" {
		portal.log.Debug().Msg("Not creating room: already exists")
		return nil
	}
	portal.log.Debug().Msg("Creating matrix room")

	//meta = portal.UpdateInfo(user, meta)
	//if meta == nil {
	//	return fmt.Errorf("didn't find metadata")
	//}

	intent := portal.MainIntent()

	if err := intent.EnsureRegistered(); err != nil {
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

	resp, err := intent.CreateRoom(&mautrix.ReqCreateRoom{
		Visibility:      "private",
		Name:            portal.Name,
		Topic:           portal.Topic,
		Invite:          invite,
		Preset:          "private_chat",
		IsDirect:        portal.IsPrivateChat(),
		InitialState:    initialState,
		CreationContent: creationContent,
	})
	if err != nil {
		portal.log.Warn().Err(err).Msg("failed to create room")
		return err
	}

	portal.NameSet = true
	//portal.TopicSet = true
	portal.AvatarSet = !portal.AvatarURL.IsEmpty()
	portal.MXID = resp.RoomID
	portal.bridge.portalsLock.Lock()
	portal.bridge.portalsByMXID[portal.MXID] = portal
	portal.bridge.portalsLock.Unlock()
	err = portal.Update(context.TODO())
	if err != nil {
		portal.log.Err(err).Msg("Failed to save created portal mxid")
	}
	portal.log.Info().Msgf("Created matrix room %s", portal.MXID)

	if portal.Encrypted && portal.IsPrivateChat() {
		err = portal.bridge.Bot.EnsureJoined(portal.MXID, appservice.EnsureJoinedParams{BotOverride: portal.MainIntent().Client})
		if err != nil {
			portal.log.Error().Err(err).Msg("Failed to ensure bridge bot is joined to private chat portal")
		}
	}

	user.ensureInvited(portal.MainIntent(), portal.MXID, portal.IsPrivateChat())
	user.syncChatDoublePuppetDetails(portal, true)

	//portal.syncParticipants(user, channel.Recipients)

	if portal.IsPrivateChat() {
		portal.log.Debug().Msgf("Portal is private chat, updating direct chats: %s", portal.MXID)
		puppet := user.bridge.GetPuppetBySignalID(portal.Receiver)
		if puppet == nil {
			portal.log.Error().Msgf("Failed to find puppet for portal receiver %s", portal.Receiver)
			return nil
		}

		chats := map[id.UserID][]id.RoomID{puppet.MXID: {portal.MXID}}
		user.UpdateDirectChats(chats)
	}

	return nil
}

func (portal *Portal) UpdateInfo(user *User, meta *any) *any {
	return nil
}

// ** Portal loading and fetching **
var (
	portalCreationDummyEvent = event.Type{Type: "fi.mau.dummy.portal_created", Class: event.MessageEventType}
)

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

func (portal *Portal) getBridgeInfoStateKey() string {
	return fmt.Sprintf("net.maunium.signal://signal/%s", portal.ChatID)
}

// ** DisappearingPortal interface **
func (portal *Portal) ScheduleDisappearing() {
	portal.bridge.disappearingMessagesManager.ScheduleDisappearingForRoom(context.TODO(), portal.MXID)
}

func (portal *Portal) HasRelaybot() bool {
	return portal.bridge.Config.Bridge.Relay.Enabled && len(portal.RelayUserID) > 0
}

func (portal *Portal) addRelaybotFormat(userID id.UserID, content *event.MessageEventContent) bool {
	member := portal.MainIntent().Member(portal.MXID, userID)
	if member == nil {
		member = &event.MemberEventContent{}
	}
	content.EnsureHasHTML()
	data, err := portal.bridge.Config.Bridge.Relay.FormatMessage(content, userID, *member)
	if err != nil {
		portal.log.Err(err).Msg("Failed to apply relaybot format")
	}
	content.FormattedBody = data
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
	//portal.resetChildSpaceStatus()
	portal.bridge.portalsLock.Unlock()
}

func (portal *Portal) Cleanup(puppetsOnly bool) {
	portal.bridge.CleanupRoom(&portal.log, portal.MainIntent(), portal.MXID, puppetsOnly)
}

func (br *SignalBridge) CleanupRoom(log *zerolog.Logger, intent *appservice.IntentAPI, mxid id.RoomID, puppetsOnly bool) {
	if len(mxid) == 0 {
		return
	}
	if br.SpecVersions.Supports(mautrix.BeeperFeatureRoomYeeting) {
		err := intent.BeeperDeleteRoom(mxid)
		if err == nil || errors.Is(err, mautrix.MNotFound) {
			return
		}
		log.Warn().Err(err).Msg("Failed to delete room using beeper yeet endpoint, falling back to normal behavior")
	}
	members, err := intent.JoinedMembers(mxid)
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
			_, err = puppet.DefaultIntent().LeaveRoom(mxid)
			if err != nil {
				log.Err(err).Msg("Failed to leave as puppet while cleaning up portal")
			}
		} else if !puppetsOnly {
			_, err = intent.KickUser(mxid, &mautrix.ReqKickUser{UserID: member, Reason: "Deleting portal"})
			if err != nil {
				log.Err(err).Msg("Failed to kick user while cleaning up portal")
			}
		}
	}
	_, err = intent.LeaveRoom(mxid)
	if err != nil {
		log.Err(err).Msg("Failed to leave room while cleaning up portal")
	}
}
