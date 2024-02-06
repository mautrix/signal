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

package main

import (
	"context"
	"errors"
	"fmt"
	"sync"
	"time"

	"github.com/rs/zerolog"
	"maunium.net/go/mautrix"
	"maunium.net/go/mautrix/bridge/status"
	"maunium.net/go/mautrix/event"
	"maunium.net/go/mautrix/id"

	"go.mau.fi/mautrix-signal/msgconv"
)

var (
	errUserNotConnected            = errors.New("you are not connected to Signal")
	errDifferentUser               = errors.New("user is not the recipient of this private chat portal")
	errUserNotLoggedIn             = errors.New("user is not logged in and chat has no relay bot")
	errRelaybotNotLoggedIn         = errors.New("neither user nor relay bot of chat are logged in")
	errCantRelayReactions          = errors.New("user is not logged in and reactions can't be relayed")
	errMNoticeDisabled             = errors.New("bridging m.notice messages is disabled")
	errUnexpectedParsedContentType = errors.New("unexpected parsed content type")

	errRedactionTargetNotFound          = errors.New("redaction target message was not found")
	errRedactionTargetSentBySomeoneElse = errors.New("redaction target message was sent by someone else")
	errUnreactTargetSentBySomeoneElse   = errors.New("redaction target reaction was sent by someone else")
	errReactionTargetNotFound           = errors.New("reaction target message not found")
	errEditUnknownTarget                = errors.New("unknown edit target message")
	errFailedToGetEditTarget            = errors.New("failed to get edit target message")
	errEditDifferentSender              = errors.New("can't edit message sent by another user")
	errEditTooOld                       = errors.New("message is too old to be edited")

	errMessageTakingLong     = errors.New("bridging the message is taking longer than usual")
	errTimeoutBeforeHandling = errors.New("message timed out before handling was started")
)

func errorToStatusReason(err error) (reason event.MessageStatusReason, status event.MessageStatus, isCertain, sendNotice bool, humanMessage string) {
	switch {
	case errors.Is(err, errUnexpectedParsedContentType),
		errors.Is(err, msgconv.ErrUnsupportedMsgType),
		errors.Is(err, msgconv.ErrInvalidGeoURI):
		return event.MessageStatusUnsupported, event.MessageStatusFail, true, true, ""
	case errors.Is(err, errMNoticeDisabled):
		return event.MessageStatusUnsupported, event.MessageStatusFail, true, false, ""
	case errors.Is(err, errEditDifferentSender),
		errors.Is(err, errEditTooOld),
		errors.Is(err, errEditUnknownTarget):
		return event.MessageStatusUnsupported, event.MessageStatusFail, true, true, err.Error()
	case errors.Is(err, errTimeoutBeforeHandling):
		return event.MessageStatusTooOld, event.MessageStatusRetriable, true, true, "the message was too old when it reached the bridge, so it was not handled"
	case errors.Is(err, context.DeadlineExceeded):
		return event.MessageStatusTooOld, event.MessageStatusRetriable, false, true, "handling the message took too long and was cancelled"
	case errors.Is(err, errMessageTakingLong):
		return event.MessageStatusTooOld, event.MessageStatusPending, false, true, err.Error()
	case errors.Is(err, errRedactionTargetNotFound),
		errors.Is(err, errReactionTargetNotFound),
		errors.Is(err, errRedactionTargetSentBySomeoneElse),
		errors.Is(err, errUnreactTargetSentBySomeoneElse):
		return event.MessageStatusGenericError, event.MessageStatusFail, true, false, ""
	case errors.Is(err, errUserNotConnected):
		return event.MessageStatusGenericError, event.MessageStatusRetriable, true, true, ""
	case errors.Is(err, errUserNotLoggedIn),
		errors.Is(err, errDifferentUser),
		errors.Is(err, errRelaybotNotLoggedIn):
		return event.MessageStatusGenericError, event.MessageStatusRetriable, true, false, ""
	default:
		return event.MessageStatusGenericError, event.MessageStatusRetriable, false, true, ""
	}
}

func (portal *Portal) sendErrorMessage(ctx context.Context, evt *event.Event, err error, confirmed bool, editID id.EventID) id.EventID {
	if !portal.bridge.Config.Bridge.MessageErrorNotices {
		return ""
	}
	certainty := "may not have been"
	if confirmed {
		certainty = "was not"
	}
	var msgType string
	switch evt.Type {
	case event.EventMessage:
		msgType = "message"
	case event.EventReaction:
		msgType = "reaction"
	case event.EventRedaction:
		msgType = "redaction"
	//case TypeMSC3381PollResponse, TypeMSC3381V2PollResponse:
	//	msgType = "poll response"
	//case TypeMSC3381PollStart:
	//	msgType = "poll start"
	default:
		msgType = "unknown event"
	}
	msg := fmt.Sprintf("\u26a0 Your %s %s bridged: %v", msgType, certainty, err)
	if errors.Is(err, errMessageTakingLong) {
		msg = fmt.Sprintf("\u26a0 Bridging your %s is taking longer than usual", msgType)
	}
	content := &event.MessageEventContent{
		MsgType: event.MsgNotice,
		Body:    msg,
	}
	if editID != "" {
		content.SetEdit(editID)
	} else {
		content.SetReply(evt)
	}
	resp, err := portal.sendMainIntentMessage(ctx, content)
	if err != nil {
		portal.log.Err(err).Msg("Failed to send bridging error message")
		return ""
	}
	return resp.EventID
}

func (portal *Portal) sendStatusEvent(ctx context.Context, evtID, lastRetry id.EventID, err error, deliveredTo *[]id.UserID) {
	if !portal.bridge.Config.Bridge.MessageStatusEvents {
		return
	}
	if lastRetry == evtID {
		lastRetry = ""
	}
	intent := portal.bridge.Bot
	if !portal.Encrypted {
		// Bridge bot isn't present in unencrypted DMs
		intent = portal.MainIntent()
	}
	content := event.BeeperMessageStatusEventContent{
		Network: portal.getBridgeInfoStateKey(),
		RelatesTo: event.RelatesTo{
			Type:    event.RelReference,
			EventID: evtID,
		},
		DeliveredToUsers: deliveredTo,
		LastRetry:        lastRetry,
	}
	if err == nil {
		content.Status = event.MessageStatusSuccess
	} else {
		content.Reason, content.Status, _, _, content.Message = errorToStatusReason(err)
		content.Error = err.Error()
	}
	_, err = intent.SendMessageEvent(ctx, portal.MXID, event.BeeperMessageStatus, &content)
	if err != nil {
		portal.log.Err(err).Msg("Failed to send message status event")
	}
}

func (portal *Portal) sendDeliveryReceipt(ctx context.Context, eventID id.EventID) {
	if portal.bridge.Config.Bridge.DeliveryReceipts {
		err := portal.bridge.Bot.SendReceipt(ctx, portal.MXID, eventID, event.ReceiptTypeRead, nil)
		if err != nil {
			portal.log.Debug().Err(err).Stringer("event_id", eventID).Msg("Failed to send delivery receipt")
		}
	}
}

func (portal *Portal) sendMessageMetrics(ctx context.Context, evt *event.Event, err error, part string, ms *metricSender) {
	log := portal.log.With().
		Str("handling_step", part).
		Str("event_type", evt.Type.String()).
		Stringer("event_id", evt.ID).
		Stringer("sender", evt.Sender).
		Logger()
	if evt.Type == event.EventRedaction {
		log = log.With().Stringer("redacts", evt.Redacts).Logger()
	}
	ctx = log.WithContext(ctx)

	origEvtID := evt.ID
	if retryMeta := evt.Content.AsMessage().MessageSendRetry; retryMeta != nil {
		origEvtID = retryMeta.OriginalEventID
	}
	if err != nil {
		logEvt := log.Error()
		if part == "Ignoring" {
			logEvt = log.Debug()
		}
		logEvt.Err(err).Msg("Sending message metrics for event")
		reason, statusCode, isCertain, sendNotice, _ := errorToStatusReason(err)
		checkpointStatus := status.ReasonToCheckpointStatus(reason, statusCode)
		portal.bridge.SendMessageCheckpoint(evt, status.MsgStepRemote, err, checkpointStatus, ms.getRetryNum())
		if sendNotice {
			ms.setNoticeID(portal.sendErrorMessage(ctx, evt, err, isCertain, ms.getNoticeID()))
		}
		portal.sendStatusEvent(ctx, origEvtID, evt.ID, err, nil)
	} else {
		log.Debug().Msg("Sending metrics for successfully handled Matrix event")
		portal.sendDeliveryReceipt(ctx, evt.ID)
		portal.bridge.SendMessageSuccessCheckpoint(evt, status.MsgStepRemote, ms.getRetryNum())
		var deliveredTo *[]id.UserID
		if portal.IsPrivateChat() {
			deliveredTo = &[]id.UserID{}
		}
		portal.sendStatusEvent(ctx, origEvtID, evt.ID, nil, deliveredTo)
		if prevNotice := ms.popNoticeID(); prevNotice != "" {
			_, _ = portal.MainIntent().RedactEvent(ctx, portal.MXID, prevNotice, mautrix.ReqRedact{
				Reason: "error resolved",
			})
		}
	}
	if ms != nil {
		log.Debug().Object("timings", ms.timings).Msg("Timings for event")
	}
}

type messageTimings struct {
	initReceive  time.Duration
	decrypt      time.Duration
	implicitRR   time.Duration
	portalQueue  time.Duration
	totalReceive time.Duration

	preproc   time.Duration
	convert   time.Duration
	totalSend time.Duration
}

func niceRound(dur time.Duration) time.Duration {
	switch {
	case dur < time.Millisecond:
		return dur
	case dur < time.Second:
		return dur.Round(100 * time.Microsecond)
	default:
		return dur.Round(time.Millisecond)
	}
}

func (mt *messageTimings) MarshalZerologObject(evt *zerolog.Event) {
	evt.
		Dict("bridge", zerolog.Dict().
			Stringer("init_receive", niceRound(mt.initReceive)).
			Stringer("decrypt", niceRound(mt.decrypt)).
			Stringer("queue", niceRound(mt.portalQueue)).
			Stringer("total_hs_to_portal", niceRound(mt.totalReceive))).
		Dict("portal", zerolog.Dict().
			Stringer("implicit_rr", niceRound(mt.implicitRR)).
			Stringer("preproc", niceRound(mt.preproc)).
			Stringer("convert", niceRound(mt.convert)).
			Stringer("total_send", niceRound(mt.totalSend)))
}

type metricSender struct {
	portal         *Portal
	previousNotice id.EventID
	lock           sync.Mutex
	completed      bool
	retryNum       int
	timings        *messageTimings
	ctx            context.Context
}

func (ms *metricSender) getRetryNum() int {
	if ms != nil {
		return ms.retryNum
	}
	return 0
}

func (ms *metricSender) getNoticeID() id.EventID {
	if ms == nil {
		return ""
	}
	return ms.previousNotice
}

func (ms *metricSender) popNoticeID() id.EventID {
	if ms == nil {
		return ""
	}
	evtID := ms.previousNotice
	ms.previousNotice = ""
	return evtID
}

func (ms *metricSender) setNoticeID(evtID id.EventID) {
	if ms != nil && ms.previousNotice == "" {
		ms.previousNotice = evtID
	}
}

func (ms *metricSender) sendMessageMetrics(evt *event.Event, err error, part string, completed bool) {
	ms.lock.Lock()
	defer ms.lock.Unlock()
	if !completed && ms.completed {
		return
	}
	ms.portal.sendMessageMetrics(ms.ctx, evt, err, part, ms)
	ms.retryNum++
	ms.completed = completed
}
