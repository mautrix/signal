package main

import (
	"context"
	"errors"
	"fmt"
	"sync"
	"time"

	"maunium.net/go/mautrix"
	"maunium.net/go/mautrix/bridge/status"
	"maunium.net/go/mautrix/event"
	"maunium.net/go/mautrix/id"
)

var (
	errUserNotConnected            = errors.New("you are not connected to WhatsApp")
	errDifferentUser               = errors.New("user is not the recipient of this private chat portal")
	errUserNotLoggedIn             = errors.New("user is not logged in and chat has no relay bot")
	errMNoticeDisabled             = errors.New("bridging m.notice messages is disabled")
	errUnexpectedParsedContentType = errors.New("unexpected parsed content type")
	errInvalidGeoURI               = errors.New("invalid `geo:` URI in message")
	errUnknownMsgType              = errors.New("unknown msgtype")
	errMediaDownloadFailed         = errors.New("failed to download media")
	errMediaDecryptFailed          = errors.New("failed to decrypt media")
	errMediaConvertFailed          = errors.New("failed to convert media")
	errMediaWhatsAppUploadFailed   = errors.New("failed to upload media to WhatsApp")
	errMediaUnsupportedType        = errors.New("unsupported media type")
	errTargetNotFound              = errors.New("target event not found")
	errReactionDatabaseNotFound    = errors.New("reaction database entry not found")
	errReactionTargetNotFound      = errors.New("reaction target message not found")
	errTargetIsFake                = errors.New("target is a fake event")
	errReactionSentBySomeoneElse   = errors.New("target reaction was sent by someone else")
	errDMSentByOtherUser           = errors.New("target message was sent by the other user in a DM")
	errPollMissingQuestion         = errors.New("poll message is missing question")
	errPollDuplicateOption         = errors.New("poll options must be unique")

	errEditUnknownTarget     = errors.New("unknown edit target message")
	errEditUnknownTargetType = errors.New("unsupported edited message type")
	errEditDifferentSender   = errors.New("can't edit message sent by another user")
	errEditTooOld            = errors.New("message is too old to be edited")

	errBroadcastReactionNotSupported = errors.New("reacting to status messages is not currently supported")
	errBroadcastSendDisabled         = errors.New("sending status messages is disabled")

	errMessageTakingLong     = errors.New("bridging the message is taking longer than usual")
	errTimeoutBeforeHandling = errors.New("message timed out before handling was started")
)

func errorToStatusReason(err error) (reason event.MessageStatusReason, status event.MessageStatus, isCertain, sendNotice bool, humanMessage string) {
	switch {
	case errors.Is(err, errUnexpectedParsedContentType),
		errors.Is(err, errUnknownMsgType),
		errors.Is(err, errInvalidGeoURI),
		errors.Is(err, errBroadcastReactionNotSupported),
		errors.Is(err, errBroadcastSendDisabled):
		return event.MessageStatusUnsupported, event.MessageStatusFail, true, true, ""
	case errors.Is(err, errMNoticeDisabled):
		return event.MessageStatusUnsupported, event.MessageStatusFail, true, false, ""
	case errors.Is(err, errMediaUnsupportedType),
		errors.Is(err, errPollMissingQuestion),
		errors.Is(err, errPollDuplicateOption),
		errors.Is(err, errEditDifferentSender),
		errors.Is(err, errEditTooOld),
		errors.Is(err, errEditUnknownTarget),
		errors.Is(err, errEditUnknownTargetType):
		return event.MessageStatusUnsupported, event.MessageStatusFail, true, true, err.Error()
	case errors.Is(err, errTimeoutBeforeHandling):
		return event.MessageStatusTooOld, event.MessageStatusRetriable, true, true, "the message was too old when it reached the bridge, so it was not handled"
	case errors.Is(err, context.DeadlineExceeded):
		return event.MessageStatusTooOld, event.MessageStatusRetriable, false, true, "handling the message took too long and was cancelled"
	case errors.Is(err, errMessageTakingLong):
		return event.MessageStatusTooOld, event.MessageStatusPending, false, true, err.Error()
	case errors.Is(err, errTargetNotFound),
		errors.Is(err, errTargetIsFake),
		errors.Is(err, errReactionDatabaseNotFound),
		errors.Is(err, errReactionTargetNotFound),
		errors.Is(err, errReactionSentBySomeoneElse),
		errors.Is(err, errDMSentByOtherUser):
		return event.MessageStatusGenericError, event.MessageStatusFail, true, false, ""
	case errors.Is(err, errUserNotConnected):
		return event.MessageStatusGenericError, event.MessageStatusRetriable, true, true, ""
	case errors.Is(err, errUserNotLoggedIn),
		errors.Is(err, errDifferentUser):
		return event.MessageStatusGenericError, event.MessageStatusRetriable, true, false, ""
	default:
		return event.MessageStatusGenericError, event.MessageStatusRetriable, false, true, ""
	}
}

func (portal *Portal) sendErrorMessage(evt *event.Event, err error, msgType string, confirmed bool, editID id.EventID) id.EventID {
	if !portal.bridge.Config.Bridge.MessageErrorNotices {
		return ""
	}
	certainty := "may not have been"
	if confirmed {
		certainty = "was not"
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
	resp, err := portal.sendMainIntentMessage(content)
	if err != nil {
		portal.log.Err(err).Msg("Failed to send bridging error message")
		return ""
	}
	return resp.EventID
}

func (portal *Portal) sendStatusEvent(evtID, lastRetry id.EventID, err error) {
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
		LastRetry: lastRetry,
	}
	if err == nil {
		content.Status = event.MessageStatusSuccess
	} else {
		content.Reason, content.Status, _, _, content.Message = errorToStatusReason(err)
		content.Error = err.Error()
	}
	_, err = intent.SendMessageEvent(portal.MXID, event.BeeperMessageStatus, &content)
	if err != nil {
		portal.log.Err(err).Msg("Failed to send message status event")
	}
}

func (portal *Portal) sendDeliveryReceipt(eventID id.EventID) {
	if portal.bridge.Config.Bridge.DeliveryReceipts {
		err := portal.bridge.Bot.SendReceipt(portal.MXID, eventID, event.ReceiptTypeRead, nil)
		if err != nil {
			portal.log.Debug().Msgf("Failed to send delivery receipt for %s: %v", eventID, err)
		}
	}
}

func (portal *Portal) sendMessageMetrics(evt *event.Event, err error, part string, ms *metricSender) {
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
	evtDescription := evt.ID.String()
	if evt.Type == event.EventRedaction {
		evtDescription += fmt.Sprintf(" of %s", evt.Redacts)
	}
	origEvtID := evt.ID
	if retryMeta := evt.Content.AsMessage().MessageSendRetry; retryMeta != nil {
		origEvtID = retryMeta.OriginalEventID
	}
	if err != nil {
		logError := true
		if part == "Ignoring" {
			logError = false
		}
		if logError {
			portal.log.Err(err).Msgf("%s %s %s from %s", part, msgType, evtDescription, evt.Sender)
		} else {
			portal.log.Debug().Msgf("%s %s %s from %s: %v", part, msgType, evtDescription, evt.Sender, err)
		}
		reason, statusCode, isCertain, sendNotice, _ := errorToStatusReason(err)
		checkpointStatus := status.ReasonToCheckpointStatus(reason, statusCode)
		portal.bridge.SendMessageCheckpoint(evt, status.MsgStepRemote, err, checkpointStatus, ms.getRetryNum())
		if sendNotice {
			ms.setNoticeID(portal.sendErrorMessage(evt, err, msgType, isCertain, ms.getNoticeID()))
		}
		portal.sendStatusEvent(origEvtID, evt.ID, err)
	} else {
		portal.log.Debug().Msgf("Handled Matrix %s %s", msgType, evtDescription)
		portal.sendDeliveryReceipt(evt.ID)
		portal.bridge.SendMessageSuccessCheckpoint(evt, status.MsgStepRemote, ms.getRetryNum())
		portal.sendStatusEvent(origEvtID, evt.ID, nil)
		if prevNotice := ms.popNoticeID(); prevNotice != "" {
			_, _ = portal.MainIntent().RedactEvent(portal.MXID, prevNotice, mautrix.ReqRedact{
				Reason: "error resolved",
			})
		}
	}
	if ms != nil {
		portal.log.Debug().Msgf("Timings for %s: %s", evt.ID, ms.timings.String())
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

func (mt *messageTimings) String() string {
	mt.initReceive = niceRound(mt.initReceive)
	mt.decrypt = niceRound(mt.decrypt)
	mt.portalQueue = niceRound(mt.portalQueue)
	mt.totalReceive = niceRound(mt.totalReceive)
	mt.implicitRR = niceRound(mt.implicitRR)
	mt.preproc = niceRound(mt.preproc)
	mt.convert = niceRound(mt.convert)
	mt.totalSend = niceRound(mt.totalSend)
	whatsmeowTimings := "N/A"
	return fmt.Sprintf("BRIDGE: receive: %s, decrypt: %s, queue: %s, total hs->portal: %s, implicit rr: %s -- PORTAL: preprocess: %s, convert: %s, total send: %s -- WHATSMEOW: %s", mt.initReceive, mt.decrypt, mt.implicitRR, mt.portalQueue, mt.totalReceive, mt.preproc, mt.convert, mt.totalSend, whatsmeowTimings)
}

type metricSender struct {
	portal         *Portal
	previousNotice id.EventID
	lock           sync.Mutex
	completed      bool
	retryNum       int
	timings        *messageTimings
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
	ms.portal.sendMessageMetrics(evt, err, part, ms)
	ms.retryNum++
	ms.completed = completed
}
