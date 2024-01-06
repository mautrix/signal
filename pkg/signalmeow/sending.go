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
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/rs/zerolog"
	"go.mau.fi/util/exfmt"
	"google.golang.org/protobuf/proto"

	"go.mau.fi/mautrix-signal/pkg/libsignalgo"
	signalpb "go.mau.fi/mautrix-signal/pkg/signalmeow/protobuf"
	"go.mau.fi/mautrix-signal/pkg/signalmeow/types"
	"go.mau.fi/mautrix-signal/pkg/signalmeow/web"
)

// Sending

func (cli *Client) senderCertificate(ctx context.Context) (*libsignalgo.SenderCertificate, error) {
	if cli.SenderCertificate != nil {
		expiry, err := cli.SenderCertificate.GetExpiration()
		if err != nil {
			zerolog.Ctx(ctx).Err(err).Msg("Failed to check sender certificate expiry")
		} else if time.Until(expiry) < 1*exfmt.Day {
			zerolog.Ctx(ctx).Debug().Msg("Sender certificate expired, fetching new one")
			cli.SenderCertificate = nil
		} else {
			return cli.SenderCertificate, nil
		}
	}

	type response struct {
		Certificate []byte `json:"certificate"`
	}
	var r response

	username, password := cli.Store.BasicAuthCreds()
	opts := &web.HTTPReqOpt{Username: &username, Password: &password}
	resp, err := web.SendHTTPRequest(http.MethodGet, "/v1/certificate/delivery", opts)
	if err != nil {
		return nil, err
	}
	err = web.DecodeHTTPResponseBody(ctx, &r, resp)
	if err != nil {
		return nil, err
	}

	cert, err := libsignalgo.DeserializeSenderCertificate(r.Certificate)
	cli.SenderCertificate = cert
	return cert, err
}

type MyMessage struct {
	Type                      int    `json:"type"`
	DestinationDeviceID       int    `json:"destinationDeviceId"`
	DestinationRegistrationID int    `json:"destinationRegistrationId"`
	Content                   string `json:"content"`
}

type MyMessages struct {
	Timestamp int64       `json:"timestamp"`
	Online    bool        `json:"online"`
	Urgent    bool        `json:"urgent"`
	Messages  []MyMessage `json:"messages"`
}

func padBlock(block *[]byte, pos int) error {
	if pos >= len(*block) {
		return errors.New("Padding error: position exceeds block length")
	}

	(*block)[pos] = 0x80
	for i := pos + 1; i < len(*block); i++ {
		(*block)[i] = 0
	}

	return nil
}

func addPadding(version uint32, contents []byte) ([]byte, error) {
	if version < 2 {
		return nil, fmt.Errorf("Unknown version %d", version)
	} else if version == 2 {
		return contents, nil
	} else {
		messageLength := len(contents)
		messageLengthWithTerminator := len(contents) + 1
		messagePartCount := messageLengthWithTerminator / 160
		if messageLengthWithTerminator%160 != 0 {
			messagePartCount++
		}

		messageLengthWithPadding := messagePartCount * 160

		buffer := make([]byte, messageLengthWithPadding)
		copy(buffer[:messageLength], contents)

		err := padBlock(&buffer, messageLength)
		if err != nil {
			return nil, errors.New(fmt.Sprintf("Invalid message padding: %v", err))
		}
		return buffer, nil
	}
}

func checkForErrorWithSessions(err error, addresses []*libsignalgo.Address, sessionRecords []*libsignalgo.SessionRecord) error {
	if err != nil {
		return err
	}
	if addresses == nil || sessionRecords == nil {
		return fmt.Errorf("addresses or session records are nil")
	}
	if len(addresses) != len(sessionRecords) {
		return fmt.Errorf("mismatched number of addresses (%d) and session records (%d)", len(addresses), len(sessionRecords))
	}
	if len(addresses) == 0 || len(sessionRecords) == 0 {
		return fmt.Errorf("no addresses or session records")
	}
	return nil
}

func (cli *Client) howManyOtherDevicesDoWeHave(ctx context.Context) int {
	addresses, _, err := cli.Store.SessionStoreExtras.AllSessionsForUUID(ctx, cli.Store.ACI)
	if err != nil {
		return 0
	}
	// Filter out our deviceID
	otherDevices := 0
	for _, address := range addresses {
		deviceID, err := address.DeviceID()
		if err != nil {
			zerolog.Ctx(ctx).Err(err).Msg("Error getting deviceID from address")
			continue
		}
		if deviceID != uint(cli.Store.DeviceID) {
			otherDevices++
		}
	}
	return otherDevices
}

func (cli *Client) buildMessagesToSend(ctx context.Context, recipientUUID uuid.UUID, content *signalpb.Content, unauthenticated bool) ([]MyMessage, error) {
	// We need to prevent multiple encryption operations from happening at once, or else ratchets can race
	cli.encryptionLock.Lock()
	defer cli.encryptionLock.Unlock()

	messages := []MyMessage{}

	addresses, sessionRecords, err := cli.Store.SessionStoreExtras.AllSessionsForUUID(ctx, recipientUUID)
	if err == nil && (len(addresses) == 0 || len(sessionRecords) == 0) {
		// No sessions, make one with prekey
		cli.FetchAndProcessPreKey(ctx, recipientUUID, -1)
		addresses, sessionRecords, err = cli.Store.SessionStoreExtras.AllSessionsForUUID(ctx, recipientUUID)
	}
	err = checkForErrorWithSessions(err, addresses, sessionRecords)
	if err != nil {
		return nil, err
	}

	for i, recipientAddress := range addresses {
		recipientDeviceID, err := recipientAddress.DeviceID()
		if err != nil {
			return nil, err
		}

		// Don't send to this device that we are sending from
		if recipientUUID == cli.Store.ACI && recipientDeviceID == uint(cli.Store.DeviceID) {
			zerolog.Ctx(ctx).Debug().
				Uint("recipient_device_id", recipientDeviceID).
				Msg("Not sending to the device I'm sending from")
			continue
		}

		// Build message payload
		serializedMessage, err := proto.Marshal(content)
		if err != nil {
			return nil, err
		}
		paddedMessage, err := addPadding(3, []byte(serializedMessage)) // TODO: figure out how to get actual version
		if err != nil {
			return nil, err
		}
		sessionRecord := sessionRecords[i]

		var envelopeType int
		var encryptedPayload []byte
		if unauthenticated {
			envelopeType, encryptedPayload, err = cli.buildSSMessageToSend(ctx, recipientAddress, paddedMessage)
		} else {
			envelopeType, encryptedPayload, err = cli.buildAuthedMessageToSend(ctx, recipientAddress, paddedMessage)
		}
		if err != nil {
			return nil, err
		}

		destinationRegistrationID, err := sessionRecord.GetRemoteRegistrationID()
		if err != nil {
			return nil, err
		}
		outgoingMessage := MyMessage{
			Type:                      envelopeType,
			DestinationDeviceID:       int(recipientDeviceID),
			DestinationRegistrationID: int(destinationRegistrationID),
			Content:                   base64.StdEncoding.EncodeToString(encryptedPayload),
		}
		messages = append(messages, outgoingMessage)
	}

	return messages, nil
}

func (cli *Client) buildAuthedMessageToSend(ctx context.Context, recipientAddress *libsignalgo.Address, paddedMessage []byte) (envelopeType int, encryptedPayload []byte, err error) {
	cipherTextMessage, err := libsignalgo.Encrypt(
		ctx,
		[]byte(paddedMessage),
		recipientAddress,
		cli.Store.SessionStore,
		cli.Store.IdentityStore,
	)
	if err != nil {
		return 0, nil, err
	}
	encryptedPayload, err = cipherTextMessage.Serialize()
	if err != nil {
		return 0, nil, err
	}

	// OMG Signal are you serious why can't your magic numbers just align
	cipherMessageType, _ := cipherTextMessage.MessageType()
	if cipherMessageType == libsignalgo.CiphertextMessageTypePreKey { // 3 -> 3
		envelopeType = int(signalpb.Envelope_PREKEY_BUNDLE)
	} else if cipherMessageType == libsignalgo.CiphertextMessageTypeWhisper { // 2 -> 1
		envelopeType = int(signalpb.Envelope_CIPHERTEXT)
	} else {
		return 0, nil, fmt.Errorf("unknown message type: %v", cipherMessageType)
	}
	return envelopeType, encryptedPayload, nil
}

func (cli *Client) buildSSMessageToSend(ctx context.Context, recipientAddress *libsignalgo.Address, paddedMessage []byte) (envelopeType int, encryptedPayload []byte, err error) {
	cert, err := cli.senderCertificate(ctx)
	if err != nil {
		return 0, nil, err
	}
	encryptedPayload, err = libsignalgo.SealedSenderEncryptPlaintext(
		ctx,
		[]byte(paddedMessage),
		recipientAddress,
		cert,
		cli.Store.SessionStore,
		cli.Store.IdentityStore,
	)
	envelopeType = int(signalpb.Envelope_UNIDENTIFIED_SENDER)

	return envelopeType, encryptedPayload, nil
}

type SuccessfulSendResult struct {
	RecipientUUID uuid.UUID
	Unidentified  bool
}
type FailedSendResult struct {
	RecipientUUID uuid.UUID
	Error         error
}
type SendMessageResult struct {
	WasSuccessful bool
	*SuccessfulSendResult
	*FailedSendResult
}
type GroupMessageSendResult struct {
	SuccessfullySentTo []SuccessfulSendResult
	FailedToSendTo     []FailedSendResult
}

func contentFromDataMessage(dataMessage *signalpb.DataMessage) *signalpb.Content {
	return &signalpb.Content{
		DataMessage: dataMessage,
	}
}
func syncMessageFromGroupDataMessage(dataMessage *signalpb.DataMessage, results []SuccessfulSendResult) *signalpb.Content {
	unidentifiedStatuses := []*signalpb.SyncMessage_Sent_UnidentifiedDeliveryStatus{}
	for _, result := range results {
		unidentifiedStatuses = append(unidentifiedStatuses, &signalpb.SyncMessage_Sent_UnidentifiedDeliveryStatus{
			DestinationServiceId: proto.String(result.RecipientUUID.String()),
			Unidentified:         &result.Unidentified,
		})
	}
	return &signalpb.Content{
		SyncMessage: &signalpb.SyncMessage{
			Sent: &signalpb.SyncMessage_Sent{
				Message:            dataMessage,
				Timestamp:          dataMessage.Timestamp,
				UnidentifiedStatus: unidentifiedStatuses,
			},
		},
	}
}
func syncMessageFromGroupEditMessage(editMessage *signalpb.EditMessage, results []SuccessfulSendResult) *signalpb.Content {
	unidentifiedStatuses := []*signalpb.SyncMessage_Sent_UnidentifiedDeliveryStatus{}
	for _, result := range results {
		unidentifiedStatuses = append(unidentifiedStatuses, &signalpb.SyncMessage_Sent_UnidentifiedDeliveryStatus{
			DestinationServiceId: proto.String(result.RecipientUUID.String()),
			Unidentified:         &result.Unidentified,
		})
	}
	return &signalpb.Content{
		SyncMessage: &signalpb.SyncMessage{
			Sent: &signalpb.SyncMessage_Sent{
				EditMessage:        editMessage,
				Timestamp:          editMessage.GetDataMessage().Timestamp,
				UnidentifiedStatus: unidentifiedStatuses,
			},
		},
	}
}

func syncMessageFromSoloDataMessage(dataMessage *signalpb.DataMessage, result SuccessfulSendResult) *signalpb.Content {
	return &signalpb.Content{
		SyncMessage: &signalpb.SyncMessage{
			Sent: &signalpb.SyncMessage_Sent{
				Message:              dataMessage,
				DestinationServiceId: proto.String(result.RecipientUUID.String()),
				Timestamp:            dataMessage.Timestamp,
				UnidentifiedStatus: []*signalpb.SyncMessage_Sent_UnidentifiedDeliveryStatus{
					{
						DestinationServiceId: proto.String(result.RecipientUUID.String()),
						Unidentified:         &result.Unidentified,
					},
				},
			},
		},
	}
}

func syncMessageFromSoloEditMessage(editMessage *signalpb.EditMessage, result SuccessfulSendResult) *signalpb.Content {
	return &signalpb.Content{
		SyncMessage: &signalpb.SyncMessage{
			Sent: &signalpb.SyncMessage_Sent{
				EditMessage:          editMessage,
				DestinationServiceId: proto.String(result.RecipientUUID.String()),
				Timestamp:            editMessage.DataMessage.Timestamp,
				UnidentifiedStatus: []*signalpb.SyncMessage_Sent_UnidentifiedDeliveryStatus{
					{
						DestinationServiceId: proto.String(result.RecipientUUID.String()),
						Unidentified:         &result.Unidentified,
					},
				},
			},
		},
	}
}

func syncMessageForContactRequest() *signalpb.Content {
	return &signalpb.Content{
		SyncMessage: &signalpb.SyncMessage{
			Request: &signalpb.SyncMessage_Request{
				Type: signalpb.SyncMessage_Request_CONTACTS.Enum(),
			},
		},
	}
}

func syncMessageFromReadReceiptMessage(ctx context.Context, receiptMessage *signalpb.ReceiptMessage, messageSender uuid.UUID) *signalpb.Content {
	if *receiptMessage.Type != signalpb.ReceiptMessage_READ {
		zerolog.Ctx(ctx).Warn().
			Any("receipt_message_type", receiptMessage.Type).
			Msg("syncMessageFromReadReceiptMessage called with non-read receipt message")
		return nil
	}
	read := []*signalpb.SyncMessage_Read{}
	for _, timestamp := range receiptMessage.Timestamp {
		read = append(read, &signalpb.SyncMessage_Read{
			Timestamp: proto.Uint64(timestamp),
			SenderAci: proto.String(messageSender.String()),
		})
	}
	return &signalpb.Content{
		SyncMessage: &signalpb.SyncMessage{
			Read: read,
		},
	}
}

func (cli *Client) SendContactSyncRequest(ctx context.Context) error {
	if cli.LastContactRequestTime == nil {
		cli.LastContactRequestTime = new(int64)
	}
	currentUnixTime := time.Now().Unix()
	lastRequestTime := cli.LastContactRequestTime
	log := zerolog.Ctx(ctx).With().
		Str("action", "send contact sync request").
		Int64("current_unix_time", currentUnixTime).
		Int64("last_request_time", *lastRequestTime).
		Int64("seconds_since_last_request", currentUnixTime-*lastRequestTime).
		Logger()
	ctx = log.WithContext(ctx)
	// If we've requested in the last minute, don't request again
	if lastRequestTime != nil && currentUnixTime-*lastRequestTime < 60 {
		log.Warn().Msg("Not sending contact sync request because we already requested it in the past minute")
		return nil
	}

	groupRequest := syncMessageForContactRequest()
	_, err := cli.sendContent(ctx, cli.Store.ACI, uint64(currentUnixTime), groupRequest, 0)
	if err != nil {
		log.Err(err).Msg("Failed to send contact sync request message to myself")
		return err
	}
	cli.LastContactRequestTime = &currentUnixTime
	return nil
}

func TypingMessage(isTyping bool) *signalpb.Content {
	// Note: not handling sending to a group ATM since that will require
	// SenderKey sending to not be terrible
	timestamp := currentMessageTimestamp()
	var action signalpb.TypingMessage_Action
	if isTyping {
		action = signalpb.TypingMessage_STARTED
	} else {
		action = signalpb.TypingMessage_STOPPED
	}
	tm := &signalpb.TypingMessage{
		Timestamp: &timestamp,
		Action:    &action,
	}
	return &signalpb.Content{
		TypingMessage: tm,
	}
}

func DeliveredReceiptMessageForTimestamps(timestamps []uint64) *signalpb.Content {
	rm := &signalpb.ReceiptMessage{
		Timestamp: timestamps,
		Type:      signalpb.ReceiptMessage_DELIVERY.Enum(),
	}
	return &signalpb.Content{
		ReceiptMessage: rm,
	}
}

func ReadReceptMessageForTimestamps(timestamps []uint64) *signalpb.Content {
	rm := &signalpb.ReceiptMessage{
		Timestamp: timestamps,
		Type:      signalpb.ReceiptMessage_READ.Enum(),
	}
	return &signalpb.Content{
		ReceiptMessage: rm,
	}
}

func DataMessageForReaction(reaction string, targetMessageSender uuid.UUID, targetMessageTimestamp uint64, removing bool) *signalpb.Content {
	timestamp := currentMessageTimestamp()
	dm := &signalpb.DataMessage{
		Timestamp:               &timestamp,
		RequiredProtocolVersion: proto.Uint32(uint32(signalpb.DataMessage_REACTIONS)),
		Reaction: &signalpb.DataMessage_Reaction{
			Emoji:               proto.String(reaction),
			Remove:              proto.Bool(removing),
			TargetAuthorAci:     proto.String(targetMessageSender.String()),
			TargetSentTimestamp: proto.Uint64(targetMessageTimestamp),
		},
	}
	return wrapDataMessageInContent(dm)
}

func DataMessageForDelete(targetMessageTimestamp uint64) *signalpb.Content {
	timestamp := currentMessageTimestamp()
	dm := &signalpb.DataMessage{
		Timestamp: &timestamp,
		Delete: &signalpb.DataMessage_Delete{
			TargetSentTimestamp: proto.Uint64(targetMessageTimestamp),
		},
	}
	return wrapDataMessageInContent(dm)
}

func wrapDataMessageInContent(dm *signalpb.DataMessage) *signalpb.Content {
	return &signalpb.Content{
		DataMessage: dm,
	}
}

func (cli *Client) SendGroupMessage(ctx context.Context, gid types.GroupIdentifier, content *signalpb.Content) (*GroupMessageSendResult, error) {
	log := zerolog.Ctx(ctx).With().
		Str("action", "send group message").
		Stringer("group_id", gid).
		Logger()
	ctx = log.WithContext(ctx)
	group, err := cli.RetrieveGroupByID(ctx, gid, 0)
	if err != nil {
		return nil, err
	}

	var messageTimestamp uint64
	if content.GetDataMessage() != nil {
		messageTimestamp = content.DataMessage.GetTimestamp()
		content.DataMessage.GroupV2 = groupMetadataForDataMessage(*group)
	} else if content.GetEditMessage().GetDataMessage() != nil {
		messageTimestamp = content.EditMessage.DataMessage.GetTimestamp()
		content.EditMessage.DataMessage.GroupV2 = groupMetadataForDataMessage(*group)
	}

	// Send to each member of the group
	result := &GroupMessageSendResult{
		SuccessfullySentTo: []SuccessfulSendResult{},
		FailedToSendTo:     []FailedSendResult{},
	}
	for _, member := range group.Members {
		if member.UserID == cli.Store.ACI {
			// Don't send normal DataMessages to ourselves
			continue
		}
		log := log.With().Stringer("member", member.UserID).Logger()
		ctx := log.WithContext(ctx)
		sentUnidentified, err := cli.sendContent(ctx, member.UserID, messageTimestamp, content, 0)
		if err != nil {
			result.FailedToSendTo = append(result.FailedToSendTo, FailedSendResult{
				RecipientUUID: member.UserID,
				Error:         err,
			})
			log.Err(err).Msg("Failed to send to user")
		} else {
			result.SuccessfullySentTo = append(result.SuccessfullySentTo, SuccessfulSendResult{
				RecipientUUID: member.UserID,
				Unidentified:  sentUnidentified,
			})
			log.Trace().Msg("Successfully sent to user")
		}
	}

	// No need to send to ourselves if we don't have any other devices
	if cli.howManyOtherDevicesDoWeHave(ctx) > 0 {
		var syncContent *signalpb.Content
		if content.GetDataMessage() != nil {
			syncContent = syncMessageFromGroupDataMessage(content.DataMessage, result.SuccessfullySentTo)
		} else if content.GetEditMessage() != nil {
			syncContent = syncMessageFromGroupEditMessage(content.EditMessage, result.SuccessfullySentTo)
		}
		_, selfSendErr := cli.sendContent(ctx, cli.Store.ACI, messageTimestamp, syncContent, 0)
		if selfSendErr != nil {
			log.Err(selfSendErr).Msg("Failed to send sync message to myself")
		}
	}

	if len(result.FailedToSendTo) == 0 && len(result.SuccessfullySentTo) == 0 {
		return result, nil // I only sent to myself
	}
	if len(result.SuccessfullySentTo) == 0 {
		lastError := result.FailedToSendTo[len(result.FailedToSendTo)-1].Error
		return nil, fmt.Errorf("failed to send to any group members: %w", lastError)
	}

	return result, nil
}

func (cli *Client) SendMessage(ctx context.Context, recipientID uuid.UUID, content *signalpb.Content) SendMessageResult {
	// Assemble the content to send
	var messageTimestamp uint64
	if content.GetDataMessage() != nil {
		messageTimestamp = *content.DataMessage.Timestamp
	} else if content.GetEditMessage().GetDataMessage() != nil {
		messageTimestamp = *content.EditMessage.DataMessage.Timestamp
	} else {
		messageTimestamp = currentMessageTimestamp()
	}

	// Send to the recipient
	sentUnidentified, err := cli.sendContent(ctx, recipientID, messageTimestamp, content, 0)
	if err != nil {
		return SendMessageResult{
			WasSuccessful: false,
			FailedSendResult: &FailedSendResult{
				RecipientUUID: recipientID,
				Error:         err,
			},
		}
	}
	result := SendMessageResult{
		WasSuccessful: true,
		SuccessfulSendResult: &SuccessfulSendResult{
			RecipientUUID: recipientID,
			Unidentified:  sentUnidentified,
		},
	}

	// TODO: don't fetch every time
	// (But for now this makes sure we know about all our other devices)
	// ((Actually I don't think this is necessary?))
	//FetchAndProcessPreKey(ctx, device, device.Data.ACI, -1)

	// If we have other devices, send Sync messages to them too
	if cli.howManyOtherDevicesDoWeHave(ctx) > 0 {
		var syncContent *signalpb.Content
		if content.GetDataMessage() != nil {
			syncContent = syncMessageFromSoloDataMessage(content.DataMessage, *result.SuccessfulSendResult)
		} else if content.GetEditMessage() != nil {
			syncContent = syncMessageFromSoloEditMessage(content.EditMessage, *result.SuccessfulSendResult)
		} else if content.GetReceiptMessage().GetType() == signalpb.ReceiptMessage_READ {
			syncContent = syncMessageFromReadReceiptMessage(ctx, content.ReceiptMessage, recipientID)
		}
		if syncContent != nil {
			_, selfSendErr := cli.sendContent(ctx, cli.Store.ACI, messageTimestamp, syncContent, 0)
			if selfSendErr != nil {
				zerolog.Ctx(ctx).Err(selfSendErr).Msg("Failed to send sync message to myself")
			}
		}
	}
	return result
}

func currentMessageTimestamp() uint64 {
	return uint64(time.Now().UnixMilli())
}

func (cli *Client) sendContent(
	ctx context.Context,
	recipientUUID uuid.UUID,
	messageTimestamp uint64,
	content *signalpb.Content,
	retryCount int, // For ending recursive retries
) (sentUnidentified bool, err error) {
	log := zerolog.Ctx(ctx).With().
		Str("action", "send content").
		Stringer("recipient", recipientUUID).
		Uint64("timestamp", messageTimestamp).
		Logger()
	ctx = log.WithContext(ctx)
	printContentFieldString(ctx, content, "Outgoing message")
	log.Trace().Any("raw_content", content).Msg("Raw data of outgoing message")

	// If it's a data message, add our profile key
	if content.DataMessage != nil {
		profileKey, err := cli.ProfileKeyForSignalID(ctx, cli.Store.ACI)
		if err != nil {
			log.Err(err).Msg("Error getting profile key, not adding to outgoing message")
		} else {
			content.DataMessage.ProfileKey = profileKey.Slice()
		}
	}

	if retryCount > 3 {
		log.Error().Int("retry_count", retryCount).Msg("sendContent too many retries")
		return false, fmt.Errorf("too many retries")
	}

	useUnidentifiedSender := true
	// Don't use unauthed websocket to send a payload to my own other devices
	if recipientUUID == cli.Store.ACI {
		useUnidentifiedSender = false
	}
	profileKey, err := cli.ProfileKeyForSignalID(ctx, recipientUUID)
	if err != nil || profileKey == nil {
		log.Err(err).Msg("Error getting profile key")
		useUnidentifiedSender = false
		// Try to self heal by requesting contact sync, though this is slow and not guaranteed to help
		cli.SendContactSyncRequest(ctx)
	}
	var accessKey *libsignalgo.AccessKey
	if profileKey != nil {
		accessKey, err = profileKey.DeriveAccessKey()
		if err != nil {
			log.Err(err).Msg("Error deriving access key")
			useUnidentifiedSender = false
		}
	}
	// TODO: JUST FOR DEBUGGING
	//if content.DataMessage != nil {
	//	if *content.DataMessage.Body == "UNSEAL" {
	//		useUnidentifiedSender = false
	//	}
	//}

	// Encrypt messages
	var messages []MyMessage
	messages, err = cli.buildMessagesToSend(ctx, recipientUUID, content, useUnidentifiedSender)
	if err != nil {
		log.Err(err).Msg("Error building messages to send")
		return false, err
	}

	outgoingMessages := MyMessages{
		Timestamp: int64(messageTimestamp),
		Online:    false,
		Urgent:    true,
		Messages:  messages,
	}
	jsonBytes, err := json.Marshal(outgoingMessages)
	if err != nil {
		return false, err
	}
	path := fmt.Sprintf("/v1/messages/%v", recipientUUID)
	request := web.CreateWSRequest(http.MethodPut, path, jsonBytes, nil, nil)

	var response *signalpb.WebSocketResponseMessage
	if useUnidentifiedSender {
		log.Trace().Msg("Sending message over unidentified WS")
		base64AccessKey := base64.StdEncoding.EncodeToString(accessKey[:])
		request.Headers = append(request.Headers, "unidentified-access-key:"+base64AccessKey)
		response, err = cli.UnauthedWS.SendRequest(ctx, request)
	} else {
		log.Trace().Msg("Sending message over authed WS")
		response, err = cli.AuthedWS.SendRequest(ctx, request)
	}
	sentUnidentified = useUnidentifiedSender
	if err != nil {
		return sentUnidentified, err
	}
	log = log.With().
		Uint64("response_id", *response.Id).
		Uint32("response_status", *response.Status).
		Logger()
	ctx = log.WithContext(ctx)
	log.Trace().Msg("Received a response to a message send")

	retryableStatuses := []uint32{409, 410, 428, 500, 503}

	// Check to see if our status is retryable
	needToRetry := false
	for _, status := range retryableStatuses {
		if *response.Status == status {
			needToRetry = true
			break
		}
	}

	if needToRetry {
		var err error
		if *response.Status == 409 {
			err = cli.handle409(ctx, recipientUUID, response)
		} else if *response.Status == 410 {
			err = cli.handle410(ctx, recipientUUID, response)
		} else if *response.Status == 428 {
			err = cli.handle428(ctx, recipientUUID, response)
		}
		if err != nil {
			return false, err
		}
		// Try to send again (**RECURSIVELY**)
		sentUnidentified, err = cli.sendContent(ctx, recipientUUID, messageTimestamp, content, retryCount+1)
		if err != nil {
			log.Err(err).Msg("2nd try sendMessage error")
			return sentUnidentified, err
		}
	} else if *response.Status != 200 {
		return sentUnidentified, fmt.Errorf("unexpected status code while sending: %d", *response.Status)
	}

	return sentUnidentified, nil
}

// A 409 means our device list was out of date, so we will fix it up
func (cli *Client) handle409(ctx context.Context, recipientUUID uuid.UUID, response *signalpb.WebSocketResponseMessage) error {
	log := zerolog.Ctx(ctx)
	// Decode json body
	var body map[string]interface{}
	err := json.Unmarshal(response.Body, &body)
	if err != nil {
		log.Err(err).Msg("Unmarshal error")
		return err
	}
	// check for missingDevices and extraDevices
	if body["missingDevices"] != nil {
		missingDevices := body["missingDevices"].([]any)
		log.Debug().Any("missing_devices", missingDevices).Msg("missing devices found in 409 response")
		// TODO: establish session with missing devices
		for _, missingDevice := range missingDevices {
			cli.FetchAndProcessPreKey(ctx, recipientUUID, int(missingDevice.(float64)))
		}
	}
	if body["extraDevices"] != nil {
		extraDevices := body["extraDevices"].([]any)
		log.Debug().Any("extra_devices", extraDevices).Msg("extra devices found in 409 response")
		for _, extraDevice := range extraDevices {
			// Remove extra device from the sessionstore
			recipient, err := libsignalgo.NewUUIDAddress(
				recipientUUID,
				uint(extraDevice.(float64)),
			)
			if err != nil {
				log.Err(err).Msg("NewAddress error")
				return err
			}
			err = cli.Store.SessionStoreExtras.RemoveSession(ctx, recipient)
			if err != nil {
				log.Err(err).Msg("RemoveSession error")
				return err
			}
		}
	}
	return err
}

// A 410 means we have a stale device, so get rid of it
func (cli *Client) handle410(ctx context.Context, recipientUUID uuid.UUID, response *signalpb.WebSocketResponseMessage) error {
	log := zerolog.Ctx(ctx)
	// Decode json body
	var body map[string]interface{}
	err := json.Unmarshal(response.Body, &body)
	if err != nil {
		log.Err(err).Msg("Unmarshal error")
		return err
	}
	// check for staleDevices and make new sessions with them
	if body["staleDevices"] != nil {
		staleDevices := body["staleDevices"].([]any)
		log.Debug().Any("stale_devices", staleDevices).Msg("stale devices found in 410 response")
		for _, staleDevice := range staleDevices {
			recipient, err := libsignalgo.NewUUIDAddress(
				recipientUUID,
				uint(staleDevice.(float64)),
			)
			if err != nil {
				log.Err(err).Msg("error creating new UUID Address")
				return err
			}
			err = cli.Store.SessionStoreExtras.RemoveSession(ctx, recipient)
			if err != nil {
				log.Err(err).Msg("RemoveSession error")
				return err
			}
			cli.FetchAndProcessPreKey(ctx, recipientUUID, int(staleDevice.(float64)))
		}
	}
	return err
}

// We got rate limited.
// We ~~will~~ could try sending a "pushChallenge" response, but if that doesn't work we just gotta wait.
// TODO: explore captcha response
func (cli *Client) handle428(ctx context.Context, recipientUUID uuid.UUID, response *signalpb.WebSocketResponseMessage) error {
	log := zerolog.Ctx(ctx)
	// Decode json body
	var body map[string]interface{}
	err := json.Unmarshal(response.Body, &body)
	if err != nil {
		log.Err(err).Msg("Unmarshal error")
		return err
	}

	// Sample response:
	//id:25 status:428 message:"Precondition Required" headers:"Retry-After:86400"
	//headers:"Content-Type:application/json" headers:"Content-Length:88"
	//body:"{\"token\":\"07af0d73-e05d-42c3-9634-634922061966\",\"options\":[\"recaptcha\",\"pushChallenge\"]}"
	var retryAfterSeconds uint64 = 0
	// Find retry after header
	for _, header := range response.Headers {
		key, value := strings.Split(header, ":")[0], strings.Split(header, ":")[1]
		if key == "Retry-After" {
			retryAfterSeconds, err = strconv.ParseUint(value, 10, 64)
			if err != nil {
				log.Err(err).Msg("ParseUint error")
			}
		}
	}
	if retryAfterSeconds > 0 {
		log.Warn().Uint64("retry_after_seconds", retryAfterSeconds).Msg("Got rate limited")
	}
	// TODO: responding to a pushChallenge this way doesn't work, server just returns 422
	// Luckily challenges seem rare when sending with sealed sender
	//if body["options"] != nil {
	//	options := body["options"].([]interface{})
	//	for _, option := range options {
	//		if option == "pushChallenge" {
	//			zlog.Info().Msg("Got pushChallenge, sending response")
	//			token := body["token"].(string)
	//			username, password := device.Data.BasicAuthCreds()
	//			response, err := web.SendHTTPRequest(
	//				http.MethodPut,
	//				"/v1/challenge",
	//				&web.HTTPReqOpt{
	//					Body:     []byte(fmt.Sprintf("{\"token\":\"%v\",\"type\":\"pushChallenge\"}", token)),
	//					Username: &username,
	//					Password: &password,
	//				},
	//			)
	//			if err != nil {
	//				zlog.Err(err).Msg("SendHTTPRequest error")
	//				return err
	//			}
	//			if response.StatusCode != 200 {
	//				zlog.Info().Msg("Unexpected status code: %v", response.StatusCode)
	//				return fmt.Errorf("Unexpected status code: %v", response.StatusCode)
	//			}
	//		}
	//	}
	//}
	return nil
}
