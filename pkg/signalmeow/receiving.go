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
	"fmt"
	"strings"
	"time"

	"github.com/google/uuid"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/reflect/protoreflect"

	"go.mau.fi/mautrix-signal/pkg/libsignalgo"
	signalpb "go.mau.fi/mautrix-signal/pkg/signalmeow/protobuf"
	"go.mau.fi/mautrix-signal/pkg/signalmeow/web"
)

type SignalConnectionEvent int

const (
	SignalConnectionEventNone SignalConnectionEvent = iota
	SignalConnectionEventConnected
	SignalConnectionEventDisconnected
	SignalConnectionEventLoggedOut
	SignalConnectionEventError
	SignalConnectionCleanShutdown
)

// mapping from SignalConnectionEvent to its string representation
var signalConnectionEventNames = map[SignalConnectionEvent]string{
	SignalConnectionEventNone:         "SignalConnectionEventNone",
	SignalConnectionEventConnected:    "SignalConnectionEventConnected",
	SignalConnectionEventDisconnected: "SignalConnectionEventDisconnected",
	SignalConnectionEventLoggedOut:    "SignalConnectionEventLoggedOut",
	SignalConnectionEventError:        "SignalConnectionEventError",
	SignalConnectionCleanShutdown:     "SignalConnectionCleanShutdown",
}

// Implement the fmt.Stringer interface
func (s SignalConnectionEvent) String() string {
	return signalConnectionEventNames[s]
}

type SignalConnectionStatus struct {
	Event SignalConnectionEvent
	Err   error
}

func StartReceiveLoops(ctx context.Context, d *Device) (chan SignalConnectionStatus, error) {
	ctx, cancel := context.WithCancel(ctx)
	d.Connection.WSCancel = cancel
	authChan, err := d.Connection.ConnectAuthedWS(ctx, d.Data, d.incomingRequestHandler)
	if err != nil {
		cancel()
		return nil, err
	}
	zlog.Info().Msg("Authed websocket connecting")
	unauthChan, err := d.Connection.ConnectUnauthedWS(ctx, d.Data)
	if err != nil {
		cancel()
		return nil, err
	}
	zlog.Info().Msg("Unauthed websocket connecting")
	statusChan := make(chan SignalConnectionStatus, 10000)

	initialConnectChan := make(chan struct{})

	// Combine both websocket status channels into a single, more generic "Signal" connection status channel
	go func() {
		defer close(statusChan)
		defer cancel()
		var currentStatus, lastAuthStatus, lastUnauthStatus web.SignalWebsocketConnectionStatus
		var lastSentStatus SignalConnectionStatus
		for {
			if d == nil {
				zlog.Info().Msg("Device is nil, exiting websocket status loop")
				return
			}
			select {
			case <-ctx.Done():
				zlog.Info().Msg("Context done, exiting websocket status loop")
				return
			case status := <-authChan:
				lastAuthStatus = status
				currentStatus = status

				if status.Event == web.SignalWebsocketConnectionEventConnected {
					zlog.Info().Msg("Authed websocket connected")
				} else if status.Event == web.SignalWebsocketConnectionEventDisconnected {
					zlog.Err(status.Err).Msg("Authed websocket disconnected")
				} else if status.Event == web.SignalWebsocketConnectionEventLoggedOut {
					zlog.Err(status.Err).Msg("Authed websocket logged out")
					// TODO: Also make sure unauthed websocket is disconnected
					//StopReceiveLoops(d)
				} else if status.Event == web.SignalWebsocketConnectionEventError {
					zlog.Err(status.Err).Msg("Authed websocket error")
				} else if status.Event == web.SignalWebsocketConnectionEventCleanShutdown {
					zlog.Info().Msg("Authed websocket clean shutdown")
				}
			case status := <-unauthChan:
				lastUnauthStatus = status
				currentStatus = status

				if status.Event == web.SignalWebsocketConnectionEventConnected {
					zlog.Info().Msg("Unauthed websocket connected")
					zlog.Info().Msgf("lastUnauthStatus: %v, lastAuthStatus: %v, currentStatus: %v", lastUnauthStatus, lastAuthStatus, currentStatus)
				} else if status.Event == web.SignalWebsocketConnectionEventDisconnected {
					zlog.Err(status.Err).Msg("Unauthed websocket disconnected")
				} else if status.Event == web.SignalWebsocketConnectionEventLoggedOut {
					zlog.Err(status.Err).Msg("Unauthed websocket logged out ** THIS SHOULD BE IMPOSSIBLE **")
				} else if status.Event == web.SignalWebsocketConnectionEventError {
					zlog.Err(status.Err).Msg("Unauthed websocket error")
				} else if status.Event == web.SignalWebsocketConnectionEventCleanShutdown {
					zlog.Info().Msg("Unauthed websocket clean shutdown")
				}
			}

			var statusToSend SignalConnectionStatus
			if lastAuthStatus.Event == web.SignalWebsocketConnectionEventConnected && lastUnauthStatus.Event == web.SignalWebsocketConnectionEventConnected {
				statusToSend = SignalConnectionStatus{
					Event: SignalConnectionEventConnected,
				}
				if initialConnectChan != nil {
					close(initialConnectChan)
					initialConnectChan = nil
				}
			} else if currentStatus.Event == web.SignalWebsocketConnectionEventDisconnected {
				statusToSend = SignalConnectionStatus{
					Event: SignalConnectionEventDisconnected,
					Err:   currentStatus.Err,
				}
			} else if currentStatus.Event == web.SignalWebsocketConnectionEventLoggedOut {
				statusToSend = SignalConnectionStatus{
					Event: SignalConnectionEventLoggedOut,
					Err:   currentStatus.Err,
				}
			} else if currentStatus.Event == web.SignalWebsocketConnectionEventError {
				statusToSend = SignalConnectionStatus{
					Event: SignalConnectionEventError,
					Err:   currentStatus.Err,
				}
			} else if currentStatus.Event == web.SignalWebsocketConnectionEventCleanShutdown {
				statusToSend = SignalConnectionStatus{
					Event: SignalConnectionCleanShutdown,
				}
			}
			if statusToSend.Event != 0 && statusToSend.Event != lastSentStatus.Event {
				zlog.Info().Msgf("Sending connection status: %v", statusToSend)
				statusChan <- statusToSend
				lastSentStatus = statusToSend
			}
		}
	}()

	// Send sync message once both websockets are connected
	go func() {
		for {
			select {
			case <-ctx.Done():
				return
			case <-initialConnectChan:
				zlog.Info().Msg("Both websockets connected, sending contacts sync request")
				SendContactSyncRequest(ctx, d)
				return
			}
		}
	}()

	return statusChan, nil
}

func StopReceiveLoops(d *Device) error {
	defer func() {
		d.Connection.AuthedWS = nil
		d.Connection.UnauthedWS = nil
	}()
	authErr := d.Connection.AuthedWS.Close()
	unauthErr := d.Connection.UnauthedWS.Close()
	if d.Connection.WSCancel != nil {
		d.Connection.WSCancel()
	}
	if authErr != nil {
		return authErr
	}
	if unauthErr != nil {
		return unauthErr
	}
	return nil
}

// If a bridge can't decrypt prekeys, it's probably because the prekeys are broken so force re-registration
func checkDecryptionErrorAndDisconnect(err error, device *Device) {
	if err != nil {
		if strings.Contains(err.Error(), "30: invalid PreKey message: decryption failed") ||
			strings.Contains(err.Error(), "70: invalid signed prekey identifier") {
			zlog.Warn().Msg("Failed decrypting a PreKey message, probably our prekeys are broken, force re-registration")
			disconnectErr := device.ClearKeysAndDisconnect()
			if disconnectErr != nil {
				zlog.Err(disconnectErr).Msg("ClearKeysAndDisconnect error")
			}
		}
	}
}

func (d *Device) incomingRequestHandler(ctx context.Context, req *signalpb.WebSocketRequestMessage) (*web.SimpleResponse, error) {
	if *req.Verb == "PUT" && *req.Path == "/api/v1/message" {
		return d.incomingAPIMessageHandler(ctx, req)
	} else if *req.Verb == "PUT" && *req.Path == "/api/v1/queue/empty" {
		zlog.Trace().Msgf("Received queue empty. verb: %v, path: %v", *req.Verb, *req.Path)
	} else {
		zlog.Warn().Msgf("######## Don't know what I received ########## req: %v", req)
	}
	return &web.SimpleResponse{
		Status: 200,
	}, nil
}

func (d *Device) incomingAPIMessageHandler(ctx context.Context, req *signalpb.WebSocketRequestMessage) (*web.SimpleResponse, error) {
	responseCode := 200
	envelope := &signalpb.Envelope{}
	err := proto.Unmarshal(req.Body, envelope)
	if err != nil {
		zlog.Err(err).Msg("Unmarshal error")
		return nil, err
	}
	var result *DecryptionResult

	switch *envelope.Type {
	case signalpb.Envelope_UNIDENTIFIED_SENDER:
		zlog.Trace().Msgf("Received envelope type UNIDENTIFIED_SENDER, verb: %v, path: %v", *req.Verb, *req.Path)
		ctx := context.Background()
		usmc, err := libsignalgo.SealedSenderDecryptToUSMC(
			envelope.GetContent(),
			d.IdentityStore,
			libsignalgo.NewCallbackContext(ctx),
		)
		if err != nil || usmc == nil {
			if err == nil {
				err = fmt.Errorf("usmc is nil")
			}
			zlog.Err(err).Msg("SealedSenderDecryptToUSMC error")
			return nil, err
		}

		messageType, err := usmc.GetMessageType()
		if err != nil {
			zlog.Err(err).Msg("GetMessageType error")
		}
		senderCertificate, err := usmc.GetSenderCertificate()
		if err != nil {
			zlog.Err(err).Msg("GetSenderCertificate error")
		}
		senderUUID, err := senderCertificate.GetSenderUUID()
		if err != nil {
			zlog.Err(err).Msg("GetSenderUUID error")
		}
		senderDeviceID, err := senderCertificate.GetDeviceID()
		if err != nil {
			zlog.Err(err).Msg("GetDeviceID error")
		}
		senderAddress, err := libsignalgo.NewAddress(senderUUID.String(), uint(senderDeviceID))
		if err != nil {
			zlog.Err(err).Msg("NewAddress error")
		}
		senderE164, err := senderCertificate.GetSenderE164()
		if err != nil {
			zlog.Err(err).Msg("GetSenderE164 error")
		}
		usmcContents, err := usmc.GetContents()
		if err != nil {
			zlog.Err(err).Msg("GetContents error")
		}
		zlog.Trace().Msgf("SealedSender senderUUID: %v, senderDeviceID: %v", senderUUID, senderDeviceID)

		d.UpdateContactE164(senderUUID.String(), senderE164)

		switch messageType {
		case libsignalgo.CiphertextMessageTypeSenderKey:
			zlog.Trace().Msg("SealedSender messageType is CiphertextMessageTypeSenderKey ")
			decryptedText, err := libsignalgo.GroupDecrypt(
				usmcContents,
				senderAddress,
				d.SenderKeyStore,
				libsignalgo.NewCallbackContext(ctx),
			)
			if err != nil {
				if strings.Contains(err.Error(), "message with old counter") {
					zlog.Warn().Msg("Duplicate message, ignoring")
				} else {
					zlog.Err(err).Msg("GroupDecrypt error")
				}
			} else {
				err = stripPadding(&decryptedText)
				if err != nil {
					return nil, fmt.Errorf("stripPadding error: %v", err)
				}
				content := signalpb.Content{}
				err = proto.Unmarshal(decryptedText, &content)
				if err != nil {
					zlog.Err(err).Msg("Unmarshal error")
				}
				result = &DecryptionResult{
					SenderAddress: *senderAddress,
					Content:       &content,
					SealedSender:  true,
				}
			}

		case libsignalgo.CiphertextMessageTypePreKey:
			zlog.Trace().Msg("SealedSender messageType is CiphertextMessageTypePreKey")
			result, err = prekeyDecrypt(*senderAddress, usmcContents, d, ctx)
			if err != nil {
				zlog.Err(err).Msg("prekeyDecrypt error")
			}

		case libsignalgo.CiphertextMessageTypeWhisper:
			zlog.Trace().Msg("SealedSender messageType is CiphertextMessageTypeWhisper")
			message, err := libsignalgo.DeserializeMessage(usmcContents)
			if err != nil {
				zlog.Err(err).Msg("DeserializeMessage error")
			}
			decryptedText, err := libsignalgo.Decrypt(
				message,
				senderAddress,
				d.SessionStore,
				d.IdentityStore,
				libsignalgo.NewCallbackContext(ctx),
			)
			if err != nil {
				zlog.Err(err).Msg("Sealed sender Whisper Decryption error")
			} else {
				err = stripPadding(&decryptedText)
				if err != nil {
					return nil, fmt.Errorf("stripPadding error: %v", err)
				}
				content := signalpb.Content{}
				err = proto.Unmarshal(decryptedText, &content)
				if err != nil {
					zlog.Err(err).Msg("Unmarshal error")
				}
				result = &DecryptionResult{
					SenderAddress: *senderAddress,
					Content:       &content,
					SealedSender:  true,
				}
			}

		case libsignalgo.CiphertextMessageTypePlaintext:
			zlog.Debug().Msg("SealedSender messageType is CiphertextMessageTypePlaintext")
			// TODO: handle plaintext (usually DecryptionErrorMessage) and retries
			// when implementing SenderKey groups

			//plaintextContent, err := libsignalgo.DeserializePlaintextContent(usmcContents)
			//if err != nil {
			//	zlog.Err(err).Msg("DeserializePlaintextContent error")
			//}
			//body, err := plaintextContent.GetBody()
			//if err != nil {
			//	zlog.Err(err).Msg("PlaintextContent GetBody error")
			//}
			//content := signalpb.Content{}
			//err = proto.Unmarshal(body, &content)
			//if err != nil {
			//	zlog.Err(err).Msg("PlaintextContent Unmarshal error")
			//}
			//result = &DecryptionResult{
			//	SenderAddress: *senderAddress,
			//	Content:       &content,
			//	SealedSender:  true,
			//}

			return &web.SimpleResponse{
				Status: responseCode,
			}, nil

		default:
			zlog.Warn().Msg("SealedSender messageType is unknown")
		}

		// If we couldn't decrypt with specific decryption methods, try sealedSenderDecrypt
		if result == nil || responseCode != 200 {
			zlog.Debug().Msg("Didn't decrypt with specific methods, trying sealedSenderDecrypt")
			var err error
			result, err = sealedSenderDecrypt(envelope, d, ctx)
			if err != nil {
				if strings.Contains(err.Error(), "self send of a sealed sender message") {
					zlog.Debug().Msg("Message sent by us, ignoring")
				} else {
					zlog.Err(err).Msg("sealedSenderDecrypt error")
					checkDecryptionErrorAndDisconnect(err, d)
				}
			} else {
				zlog.Trace().Msgf("SealedSender decrypt result - address: %v, content: %v", result.SenderAddress, result.Content)
			}
		}

	case signalpb.Envelope_PREKEY_BUNDLE:
		zlog.Debug().Msgf("Received envelope type PREKEY_BUNDLE, verb: %v, path: %v", *req.Verb, *req.Path)
		sender, err := libsignalgo.NewAddress(
			*envelope.SourceServiceId,
			uint(*envelope.SourceDevice),
		)
		if err != nil {
			return nil, fmt.Errorf("NewAddress error: %v", err)
		}
		result, err = prekeyDecrypt(*sender, envelope.Content, d, ctx)
		if err != nil {
			zlog.Err(err).Msg("prekeyDecrypt error")
			checkDecryptionErrorAndDisconnect(err, d)
		} else {
			zlog.Trace().Msgf("prekey decrypt result -  address: %v, data: %v", result.SenderAddress, result.Content)
		}

	case signalpb.Envelope_PLAINTEXT_CONTENT:
		zlog.Debug().Msgf("Received envelope type PLAINTEXT_CONTENT, verb: %v, path: %v", *req.Verb, *req.Path)

	case signalpb.Envelope_CIPHERTEXT:
		zlog.Debug().Msgf("Received envelope type CIPHERTEXT, verb: %v, path: %v", *req.Verb, *req.Path)
		message, err := libsignalgo.DeserializeMessage(envelope.Content)
		if err != nil {
			zlog.Err(err).Msg("DeserializeMessage error")
		}
		senderAddress, err := libsignalgo.NewAddress(
			*envelope.SourceServiceId,
			uint(*envelope.SourceDevice),
		)
		decryptedText, err := libsignalgo.Decrypt(
			message,
			senderAddress,
			d.SessionStore,
			d.IdentityStore,
			libsignalgo.NewCallbackContext(ctx),
		)
		if err != nil {
			if strings.Contains(err.Error(), "message with old counter") {
				zlog.Info().Msg("Duplicate message, ignoring")
			} else {
				zlog.Err(err).Msg("Whisper Decryption error")
			}
		} else {
			err = stripPadding(&decryptedText)
			if err != nil {
				return nil, fmt.Errorf("stripPadding error: %v", err)
			}
			content := signalpb.Content{}
			err = proto.Unmarshal(decryptedText, &content)
			if err != nil {
				zlog.Err(err).Msg("Unmarshal error")
			}
			result = &DecryptionResult{
				SenderAddress: *senderAddress,
				Content:       &content,
			}
		}

	case signalpb.Envelope_RECEIPT:
		zlog.Debug().Msgf("Received envelope type RECEIPT, verb: %v, path: %v", *req.Verb, *req.Path)
		// TODO: handle receipt

	case signalpb.Envelope_KEY_EXCHANGE:
		zlog.Debug().Msgf("Received envelope type KEY_EXCHANGE, verb: %v, path: %v", *req.Verb, *req.Path)
		responseCode = 400

	case signalpb.Envelope_UNKNOWN:
		zlog.Warn().Msgf("Received envelope type UNKNOWN, verb: %v, path: %v", *req.Verb, *req.Path)
		responseCode = 400

	default:
		zlog.Warn().Msgf("Received actual unknown envelope type, verb: %v, path: %v", *req.Verb, *req.Path)
		responseCode = 400
	}

	// Handle content that is now decrypted
	if result != nil && result.Content != nil {
		content := result.Content

		name, _ := result.SenderAddress.Name()
		deviceId, _ := result.SenderAddress.DeviceID()
		zlog.Debug().Msgf("Decrypted message from %v:%v", name, deviceId)
		printMessage := fmt.Sprintf("Decrypted content fields (%v:%v)", name, deviceId)
		printContentFieldString(content, printMessage)

		// If there's a sender key distribution message, process it
		if content.GetSenderKeyDistributionMessage() != nil {
			zlog.Debug().Msg("content includes sender key distribution message")
			skdm, err := libsignalgo.DeserializeSenderKeyDistributionMessage(content.GetSenderKeyDistributionMessage())
			if err != nil {
				zlog.Err(err).Msg("DeserializeSenderKeyDistributionMessage error")
				return nil, err
			}
			err = libsignalgo.ProcessSenderKeyDistributionMessage(
				skdm,
				&result.SenderAddress,
				d.SenderKeyStore,
				libsignalgo.NewCallbackContext(ctx),
			)
			if err != nil {
				zlog.Err(err).Msg("ProcessSenderKeyDistributionMessage error")
				return nil, err
			}
		}

		theirUuid, err := result.SenderAddress.Name()
		if err != nil {
			zlog.Err(err).Msg("Name error")
			return nil, err
		}

		// TODO: handle more sync messages
		if content.SyncMessage != nil {
			if content.SyncMessage.Sent != nil {
				if content.SyncMessage.Sent.Message != nil {
					destination := content.SyncMessage.Sent.DestinationServiceId
					if content.SyncMessage.Sent.Message.GroupV2 != nil {
						zlog.Debug().Msgf("sync message sent group: %v", content.SyncMessage.Sent.Message.GroupV2)
						masterKeyBytes := libsignalgo.GroupMasterKey(content.SyncMessage.Sent.Message.GroupV2.MasterKey)
						masterKey := masterKeyFromBytes(masterKeyBytes)
						gid, err := StoreMasterKey(ctx, d, masterKey)
						if err != nil {
							zlog.Err(err).Msg("StoreMasterKey error")
							return nil, err
						}
						g := string(gid)
						destination = &g
					}
					if destination == nil {
						zlog.Warn().Msg("sync message sent destination is nil")
					} else if _, err = incomingDataMessage(ctx, d, content.SyncMessage.Sent.Message, d.Data.AciUuid, *destination); err != nil {
						zlog.Err(err).Msg("incomingDataMessage error")
						return nil, err
					}
				}
			}
			if content.SyncMessage.Contacts != nil {
				zlog.Debug().Msgf("Recieved sync message contacts")
				blob := content.SyncMessage.Contacts.Blob
				if blob != nil {
					contactsBytes, err := fetchAndDecryptAttachment(blob)
					if err != nil {
						zlog.Err(err).Msg("Contacts Sync fetchAndDecryptAttachment error")
					}
					// unmarshall contacts
					contacts, avatars, err := unmarshalContactDetailsMessages(contactsBytes)
					if err != nil {
						zlog.Err(err).Msg("Contacts Sync unmarshalContactDetailsMessages error")
					}
					zlog.Debug().Msgf("Contacts Sync received %v contacts", len(contacts))
					for i, signalContact := range contacts {
						if signalContact.Aci == nil || *signalContact.Aci == "" {
							zlog.Info().Msgf("Signal Contact UUID is nil, skipping: %v", signalContact)
							continue
						}
						if _, err := uuid.Parse(*signalContact.Aci); err != nil {
							zlog.Info().Msgf("Signal Contact UUID is not a UUID, skipping: %v", signalContact)
							continue
						}
						contact, contactAvatar, err := StoreContactDetailsAsContact(d, signalContact, &avatars[i])
						if err != nil {
							zlog.Err(err).Msg("StoreContactDetailsAsContact error")
							continue
						}
						// Model each contact as an incoming contact change message
						contactChange := IncomingSignalMessageContactChange{
							IncomingSignalMessageBase: IncomingSignalMessageBase{
								SenderUUID:    contact.UUID,
								RecipientUUID: d.Data.AciUuid,
								Timestamp:     currentMessageTimestamp(),
							},
							Contact: contact,
							Avatar:  contactAvatar,
						}
						d.Connection.IncomingSignalMessageHandler(contactChange)
					}
				}
			}
			if content.SyncMessage.Read != nil {
				zlog.Debug().Msgf("Recieved sync message read")
				currentTimestamp := currentMessageTimestamp()
				for _, read := range content.SyncMessage.Read {
					var receiptMessage = IncomingSignalMessageReceipt{
						IncomingSignalMessageBase: IncomingSignalMessageBase{
							SenderUUID:    d.Data.AciUuid,
							RecipientUUID: theirUuid,
							Timestamp:     currentTimestamp, // there is no timestmap on a receiptMessage
						},
						ReceiptType:       IncomingSignalMessageReceiptTypeRead,
						OriginalTimestamp: *read.Timestamp,
						OriginalSender:    *read.SenderAci,
					}
					d.Connection.IncomingSignalMessageHandler(receiptMessage)
				}
			}

		}

		if content.DataMessage != nil {
			deliveredTimestamps, err := incomingDataMessage(ctx, d, content.DataMessage, theirUuid, d.Data.AciUuid)
			if err != nil {
				zlog.Err(err).Msg("incomingDataMessage error")
				return nil, err
			}
			if len(deliveredTimestamps) > 0 {
				err := sendDeliveryReceipts(ctx, d, deliveredTimestamps, theirUuid)
				if err != nil {
					zlog.Err(err).Msg("sendDeliveryReceipts error")
				}
			}
		}

		if content.TypingMessage != nil {
			var isTyping = content.TypingMessage.GetAction() == signalpb.TypingMessage_STARTED
			var typingMessage = IncomingSignalMessageTyping{
				IncomingSignalMessageBase: IncomingSignalMessageBase{
					SenderUUID:    theirUuid,
					RecipientUUID: d.Data.AciUuid,
					Timestamp:     content.TypingMessage.GetTimestamp(),
				},
				IsTyping: isTyping,
			}
			if content.TypingMessage.GetGroupId() != nil {
				gidBytes := content.TypingMessage.GetGroupId()
				gid := GroupIdentifier(base64.StdEncoding.EncodeToString(gidBytes))
				typingMessage.GroupID = &gid
			}

			d.Connection.IncomingSignalMessageHandler(typingMessage)
		}

		// DM call message (group call is an opaque callMessage and a groupCallUpdate in a dataMessage)
		if content.CallMessage != nil && (content.CallMessage.Offer != nil || content.CallMessage.Hangup != nil) {
			callMessage := IncomingSignalMessageCall{
				IncomingSignalMessageBase: IncomingSignalMessageBase{
					SenderUUID:    theirUuid,
					RecipientUUID: d.Data.AciUuid,
					Timestamp:     currentMessageTimestamp(), // there is no timestmap on a callMessage
				},
			}
			if content.CallMessage.Offer != nil {
				callMessage.IsRinging = true
			} else if content.CallMessage.Hangup != nil {
				callMessage.IsRinging = false
			}
			d.Connection.IncomingSignalMessageHandler(callMessage)
		}

		// Read and delivery receipts
		if content.ReceiptMessage != nil {
			zlog.Debug().Msgf("Received receipt message: %v", content.ReceiptMessage)
			// If this is a delivery receipt from one of our other devices, ignore it
			if !(*content.ReceiptMessage.Type == signalpb.ReceiptMessage_DELIVERY && theirUuid == d.Data.AciUuid) {
				var receiptType IncomingSignalMessageReceiptType
				switch *content.ReceiptMessage.Type {
				case signalpb.ReceiptMessage_READ:
					receiptType = IncomingSignalMessageReceiptTypeRead
				case signalpb.ReceiptMessage_DELIVERY:
					receiptType = IncomingSignalMessageReceiptTypeDelivery
				default:
					zlog.Warn().Msgf("Unknown receipt type: %v", *content.ReceiptMessage.Type)
				}
				currentTimestamp := currentMessageTimestamp()
				// Send one incoming message for each timestamp, so they can be sent to different portals if necessary
				for _, timestamp := range content.ReceiptMessage.Timestamp {
					var receiptMessage = IncomingSignalMessageReceipt{
						IncomingSignalMessageBase: IncomingSignalMessageBase{
							SenderUUID:    theirUuid,
							RecipientUUID: d.Data.AciUuid,
							Timestamp:     currentTimestamp, // there is no timestmap on a receiptMessage
						},
						ReceiptType:       receiptType,
						OriginalTimestamp: timestamp,
						OriginalSender:    d.Data.AciUuid, // this is a receipt for a message we sent
					}
					d.Connection.IncomingSignalMessageHandler(receiptMessage)
				}
			} else {
				zlog.Debug().Msgf("Ignoring delivery receipt from self")
			}
		}
	}
	return &web.SimpleResponse{
		Status: responseCode,
	}, nil
}

func printStructFields(message protoreflect.Message, parent string, builder *strings.Builder) {
	message.Range(func(fd protoreflect.FieldDescriptor, v protoreflect.Value) bool {
		fieldName := string(fd.Name())
		currentField := parent + fieldName
		builder.WriteString(fmt.Sprintf("%s (%s), ", currentField, fd.Kind().String()))
		//builder.WriteString(fmt.Sprintf("%s (%s): %s, ", currentField, fd.Kind().String(), v.String())) // DEBUG: printing value, don't commit
		if fd.Kind() == protoreflect.MessageKind && !fd.IsList() && v.Message().IsValid() {
			builder.WriteString("{ ")
			printStructFields(v.Message(), "", builder)
			builder.WriteString("} ")
		} else if fd.Kind() == protoreflect.MessageKind && fd.IsList() {
			builder.WriteString("[ ")
			for i := 0; i < v.List().Len(); i++ {
				v := v.List().Get(i)
				builder.WriteString("{ ")
				printStructFields(v.Message(), "", builder)
				builder.WriteString("} ")
			}
			builder.WriteString("] ")
		} else if fd.IsList() {
			builder.WriteString("[ ")
			for i := 0; i < v.List().Len(); i++ {
				//v := v.List().Get(i)
				//builder.WriteString(fmt.Sprintf("%s, ", v.String())) // DEBUG: printing value, don't commit
				builder.WriteString("<>, ")
			}
			builder.WriteString("] ")
		}
		return true
	})
}

func printContentFieldString(c *signalpb.Content, message string) {
	go func() {
		// catch panic
		defer func() {
			if r := recover(); r != nil {
				zlog.Warn().Msgf("Panic in contentFieldsString: %v", r)
			}
		}()
		zlog.Debug().Msgf("%v: %v", message, contentFieldsString(c))
	}()
}

func contentFieldsString(c *signalpb.Content) string {
	builder := &strings.Builder{}
	printStructFields(c.ProtoReflect(), "", builder)
	return builder.String()
}

// HackyCaptionToggle is a hack to pass the bridge caption_in_message config option to the library.
// This won't be necessary after the redundant DataMessage -> custom struct conversion is removed
// (messages should just be converted DataMessage -> Matrix instead of DataMessage -> custom struct -> Matrix).
var HackyCaptionToggle bool

func incomingDataMessage(ctx context.Context, device *Device, dataMessage *signalpb.DataMessage, senderUUID string, recipientUUID string) ([]uint64, error) {
	deliveredTimestamps := make([]uint64, 0)

	// If there's a profile key, save it
	if dataMessage.ProfileKey != nil {
		profileKey := libsignalgo.ProfileKey(dataMessage.ProfileKey)
		err := device.ProfileKeyStore.StoreProfileKey(senderUUID, profileKey, ctx)
		if err != nil {
			zlog.Err(err).Msg("StoreProfileKey error")
			return deliveredTimestamps, err
		}
	}

	var incomingMessages []IncomingSignalMessage

	// If it's a group message, get the ID and invalidate cache if necessary
	var gidPointer *GroupIdentifier
	if dataMessage.GetGroupV2() != nil {
		// Pull out the master key then store it ASAP - we should pass around GroupIdentifier
		groupMasterKeyBytes := dataMessage.GetGroupV2().GetMasterKey()
		masterKey := masterKeyFromBytes(libsignalgo.GroupMasterKey(groupMasterKeyBytes))
		gidValue, err := StoreMasterKey(ctx, device, masterKey)
		if err != nil {
			zlog.Err(err).Msg("StoreMasterKey error")
			return deliveredTimestamps, err
		}
		gidPointer = &gidValue

		var groupHasChanged = false
		if dataMessage.GetGroupV2().GroupChange != nil {
			// TODO: don't parse the change	for now, just invalidate our cache
			zlog.Debug().Msgf("Invalidating group %v due to change: %v", gidValue, dataMessage.GetGroupV2().GroupChange)
			InvalidateGroupCache(device, gidValue)
			groupHasChanged = true
		} else if dataMessage.GetGroupV2().GetRevision() > 0 {
			// Compare revision, and if it's newer, invalidate our cache
			ourGroup, err := RetrieveGroupByID(ctx, device, gidValue)
			if err != nil {
				zlog.Err(err).Msg("RetrieveGroupByID error")
			} else if dataMessage.GetGroupV2().GetRevision() > ourGroup.Revision {
				zlog.Debug().Msgf("Invalidating group %v due to new revision %v > our revision: %v", gidValue, dataMessage.GetGroupV2().GetRevision(), ourGroup.Revision)
				InvalidateGroupCache(device, gidValue)
				groupHasChanged = true
			}
		}
		if groupHasChanged {
			// Send a group change message to trigger a group update in the portal
			groupChangeMessage := &IncomingSignalMessageGroupChange{
				IncomingSignalMessageBase: IncomingSignalMessageBase{
					SenderUUID:    senderUUID,
					RecipientUUID: recipientUUID,
					GroupID:       gidPointer,
					Timestamp:     dataMessage.GetTimestamp(),
				},
			}
			incomingMessages = append(incomingMessages, groupChangeMessage)
		}
	}

	// Grab quote (reply) info if it exists
	var quoteData *IncomingSignalMessageQuoteData
	if dataMessage.Quote != nil {
		quoteData = &IncomingSignalMessageQuoteData{
			QuotedSender:    dataMessage.GetQuote().GetAuthorAci(),
			QuotedTimestamp: dataMessage.GetQuote().GetId(),
		}
	}

	// If this message is disappearing, set ExpiresIn
	expiresIn := int64(0)
	if dataMessage.ExpireTimer != nil {
		expiresIn = int64(dataMessage.GetExpireTimer())
	}

	partIndex := 0
	// If there's attachements, handle them (one at a time for now)
	if dataMessage.Attachments != nil {
		for index, attachmentPointer := range dataMessage.Attachments {
			bytes, err := fetchAndDecryptAttachment(attachmentPointer)
			if err != nil {
				zlog.Err(err).Msg("fetchAndDecryptAttachment error")
				continue
			}
			// TODO: right now this will be one message per image, each with the same caption
			incomingMessage := IncomingSignalMessageAttachment{
				IncomingSignalMessageBase: IncomingSignalMessageBase{
					SenderUUID:    senderUUID,
					RecipientUUID: recipientUUID,
					GroupID:       gidPointer,
					Timestamp:     dataMessage.GetTimestamp(),
					PartIndex:     partIndex,
					Quote:         quoteData,
					ExpiresIn:     expiresIn,
				},
				Attachment:  bytes,
				Filename:    attachmentPointer.GetFileName(),
				ContentType: attachmentPointer.GetContentType(),
				Size:        uint64(attachmentPointer.GetSize()),
				Width:       attachmentPointer.GetWidth(),
				Height:      attachmentPointer.GetHeight(),
				BlurHash:    attachmentPointer.GetBlurHash(),
			}
			partIndex++
			if HackyCaptionToggle && index == 0 {
				incomingMessage.Caption = dataMessage.GetBody()
				incomingMessage.CaptionRanges = dataMessage.GetBodyRanges()
			}
			incomingMessages = append(incomingMessages, incomingMessage)
		}
	}

	// If there's a body but no attachments, pass along as a text message
	if dataMessage.Body != nil && (dataMessage.Attachments == nil || !HackyCaptionToggle) {
		incomingMessage := IncomingSignalMessageText{
			IncomingSignalMessageBase: IncomingSignalMessageBase{
				SenderUUID:    senderUUID,
				RecipientUUID: recipientUUID,
				GroupID:       gidPointer,
				Timestamp:     dataMessage.GetTimestamp(),
				PartIndex:     partIndex,
				Quote:         quoteData,
				ExpiresIn:     expiresIn,
			},
			Content:       dataMessage.GetBody(),
			ContentRanges: dataMessage.GetBodyRanges(),
		}
		partIndex++
		incomingMessages = append(incomingMessages, incomingMessage)
	}

	// if a sticker and has data, send it
	if dataMessage.Sticker != nil && dataMessage.Sticker.Data != nil {
		bytes, err := fetchAndDecryptAttachment(dataMessage.Sticker.Data)
		if err != nil {
			zlog.Error().Err(err).Msgf("failed to decrypt sticker: %v", dataMessage.Sticker.Data)
		} else {
			incomingMessage := IncomingSignalMessageSticker{
				IncomingSignalMessageBase: IncomingSignalMessageBase{
					SenderUUID:    senderUUID,
					RecipientUUID: recipientUUID,
					GroupID:       gidPointer,
					Timestamp:     dataMessage.GetTimestamp(),
					PartIndex:     partIndex,
					Quote:         quoteData,
					ExpiresIn:     expiresIn,
				},
				Width:       dataMessage.Sticker.Data.GetWidth(),
				Height:      dataMessage.Sticker.Data.GetHeight(),
				ContentType: dataMessage.Sticker.Data.GetContentType(),
				Filename:    dataMessage.Sticker.Data.GetFileName(),
				Sticker:     bytes,
				Emoji:       dataMessage.GetSticker().GetEmoji(),
			}
			incomingMessages = append(incomingMessages, incomingMessage)
			partIndex++
		}
	}

	// Pass along reactions
	if dataMessage.Reaction != nil {
		// make sure target author UUID is lowercase
		targetAuthor := strings.ToLower(dataMessage.GetReaction().GetTargetAuthorAci())
		incomingMessage := IncomingSignalMessageReaction{
			IncomingSignalMessageBase: IncomingSignalMessageBase{
				SenderUUID:    senderUUID,
				RecipientUUID: recipientUUID,
				GroupID:       gidPointer,
				Timestamp:     dataMessage.GetTimestamp(),
				Quote:         quoteData,
				ExpiresIn:     expiresIn,
			},
			Emoji:                  dataMessage.GetReaction().GetEmoji(),
			Remove:                 dataMessage.GetReaction().GetRemove(),
			TargetAuthorUUID:       targetAuthor,
			TargetMessageTimestamp: dataMessage.GetReaction().GetTargetSentTimestamp(),
		}
		incomingMessages = append(incomingMessages, incomingMessage)
	}

	// Pass along deletions
	if dataMessage.Delete != nil {
		incomingMessage := IncomingSignalMessageDelete{
			IncomingSignalMessageBase: IncomingSignalMessageBase{
				SenderUUID:    senderUUID,
				RecipientUUID: recipientUUID,
				GroupID:       gidPointer,
				Timestamp:     dataMessage.GetTimestamp(),
				Quote:         quoteData,
				ExpiresIn:     expiresIn,
			},
			TargetMessageTimestamp: dataMessage.GetDelete().GetTargetSentTimestamp(),
		}
		incomingMessages = append(incomingMessages, incomingMessage)
	}

	// Pass along group calls
	if dataMessage.GroupCallUpdate != nil {
		isRinging := device.UpdateActiveCalls(*gidPointer, *dataMessage.GroupCallUpdate.EraId)
		incomingMessage := IncomingSignalMessageCall{
			IncomingSignalMessageBase: IncomingSignalMessageBase{
				SenderUUID:    senderUUID,
				RecipientUUID: recipientUUID,
				GroupID:       gidPointer,
				Timestamp:     dataMessage.GetTimestamp(),
			},
			IsRinging: isRinging,
		}
		incomingMessages = append(incomingMessages, incomingMessage)
	}

	// If there's a contact card share, pass it along
	if dataMessage.Contact != nil {
		for _, contactCard := range dataMessage.GetContact() {
			incomingMessage := IncomingSignalMessageContactCard{
				IncomingSignalMessageBase: IncomingSignalMessageBase{
					SenderUUID:    senderUUID,
					RecipientUUID: recipientUUID,
					GroupID:       gidPointer,
					Timestamp:     dataMessage.GetTimestamp(),
					PartIndex:     partIndex,
				},
				DisplayName:  contactCard.GetName().GetDisplayName(),
				Organization: contactCard.GetOrganization(),
				PhoneNumbers: make([]string, 0),
				Emails:       make([]string, 0),
				Addresses:    make([]string, 0),
			}
			for _, phone := range contactCard.Number {
				incomingMessage.PhoneNumbers = append(incomingMessage.PhoneNumbers, *phone.Value)
			}
			for _, email := range contactCard.Email {
				incomingMessage.Emails = append(incomingMessage.Emails, *email.Value)
			}
			for _, address := range contactCard.Address {
				addressParts := make([]string, 0)
				if address.Pobox != nil {
					addressParts = append(addressParts, "P.O. Box: "+*address.Pobox)
				}
				if address.Street != nil {
					addressParts = append(addressParts, *address.Street)
				}
				if address.Neighborhood != nil {
					addressParts = append(addressParts, *address.Neighborhood)
				}
				if address.City != nil {
					addressParts = append(addressParts, *address.City)
				}
				if address.Region != nil {
					addressParts = append(addressParts, *address.Region)
				}
				if address.Postcode != nil {
					addressParts = append(addressParts, *address.Postcode)
				}
				if address.Country != nil {
					addressParts = append(addressParts, *address.Country)
				}
				addressString := strings.Join(addressParts, ", ")
				incomingMessage.Addresses = append(incomingMessage.Addresses, addressString)
			}
			partIndex++
			incomingMessages = append(incomingMessages, incomingMessage)
		}
	}

	// If it's a expireTimer change, send that along (DMs only)
	if dataMessage.Flags != nil && dataMessage.GetFlags()&uint32(signalpb.DataMessage_EXPIRATION_TIMER_UPDATE) != 0 {
		newTime := uint32(0)
		if dataMessage.ExpireTimer != nil {
			newTime = dataMessage.GetExpireTimer()
		}
		incomingMessage := IncomingSignalMessageExpireTimerChange{
			IncomingSignalMessageBase: IncomingSignalMessageBase{
				SenderUUID:    senderUUID,
				RecipientUUID: recipientUUID,
				GroupID:       gidPointer,
				Timestamp:     dataMessage.GetTimestamp(),
			},
			NewExpireTimer: newTime,
		}
		incomingMessages = append(incomingMessages, incomingMessage)
	}

	if device.Connection.IncomingSignalMessageHandler != nil {
		for _, incomingMessage := range incomingMessages {
			err := device.Connection.IncomingSignalMessageHandler(incomingMessage)
			if err != nil {
				zlog.Err(err).Msg("IncomingSignalMessageHandler error")
			} else {
				deliveredTimestamps = append(deliveredTimestamps, incomingMessage.Base().Timestamp)
			}
		}
	}
	return deliveredTimestamps, nil
}

func sendDeliveryReceipts(ctx context.Context, device *Device, deliveredTimestamps []uint64, senderUUID string) error {
	// Send delivery receipts
	if len(deliveredTimestamps) > 0 {
		receipt := DeliveredReceiptMessageForTimestamps(deliveredTimestamps)
		result := SendMessage(ctx, device, senderUUID, receipt)
		if !result.WasSuccessful {
			zlog.Error().Msgf("Failed to send delivery receipts: %v", result)
		}
	}
	return nil
}

type DecryptionResult struct {
	SenderAddress libsignalgo.Address
	Content       *signalpb.Content
	SealedSender  bool
}

func serverTrustRootKey() *libsignalgo.PublicKey {
	// TODO: put this server's trust root in the config or DB or something
	serverTrustRoot := "BXu6QIKVz5MA8gstzfOgRQGqyLqOwNKHL6INkv3IHWMF"
	serverTrustRootBytes, err := base64.StdEncoding.DecodeString(serverTrustRoot)
	if err != nil {
		zlog.Err(err).Msg("DecodeString error")
		panic(err)
	}
	serverTrustRootKey, err := libsignalgo.DeserializePublicKey(serverTrustRootBytes)
	if err != nil {
		zlog.Err(err).Msg("DeserializePublicKey error")
		panic(err)
	}
	return serverTrustRootKey
}

func sealedSenderDecrypt(envelope *signalpb.Envelope, device *Device, ctx context.Context) (*DecryptionResult, error) {
	localAddress := libsignalgo.NewSealedSenderAddress(
		device.Data.Number,
		uuid.MustParse(device.Data.AciUuid),
		uint32(device.Data.DeviceId),
	)
	timestamp := time.Unix(0, int64(*envelope.Timestamp))
	result, err := libsignalgo.SealedSenderDecrypt(
		envelope.Content,
		localAddress,
		serverTrustRootKey(),
		timestamp,
		device.SessionStore,
		device.IdentityStore,
		device.PreKeyStore,
		device.SignedPreKeyStore,
		libsignalgo.NewCallbackContext(ctx),
	)

	if err != nil {
		zlog.Err(err).Msg("SealedSenderDecrypt error")
		return nil, err
	}
	msg := result.Message
	err = stripPadding(&msg)
	if err != nil {
		zlog.Err(err).Msg("stripPadding error")
		return nil, err
	}
	address, err := libsignalgo.NewAddress(
		result.Sender.UUID.String(),
		uint(result.Sender.DeviceID),
	)
	if err != nil {
		zlog.Err(err).Msg("NewAddress error")
		return nil, err
	}
	content := &signalpb.Content{}
	err = proto.Unmarshal(msg, content)
	if err != nil {
		zlog.Err(err).Msg("Unmarshal error")
		return nil, err
	}
	DecryptionResult := &DecryptionResult{
		SenderAddress: *address,
		Content:       content,
	}
	return DecryptionResult, nil
}

func prekeyDecrypt(sender libsignalgo.Address, encryptedContent []byte, device *Device, ctx context.Context) (*DecryptionResult, error) {
	preKeyMessage, err := libsignalgo.DeserializePreKeyMessage(encryptedContent)
	if err != nil {
		err = fmt.Errorf("DeserializePreKeyMessage error: %v", err)
		return nil, err
	}
	if preKeyMessage == nil {
		err = fmt.Errorf("preKeyMessage is nil")
		return nil, err
	}

	data, err := libsignalgo.DecryptPreKey(
		preKeyMessage,
		&sender,
		device.SessionStore,
		device.IdentityStore,
		device.PreKeyStore,
		device.SignedPreKeyStore,
		device.KyberPreKeyStore,
		libsignalgo.NewCallbackContext(ctx),
	)
	if err != nil {
		err = fmt.Errorf("DecryptPreKey error: %v", err)
		return nil, err
	}
	err = stripPadding(&data)
	if err != nil {
		err = fmt.Errorf("stripPadding error: %v", err)
		return nil, err
	}
	content := &signalpb.Content{}
	err = proto.Unmarshal(data, content)
	if err != nil {
		err = fmt.Errorf("Unmarshal error: %v", err)
		return nil, err
	}
	DecryptionResult := &DecryptionResult{
		SenderAddress: sender,
		Content:       content,
	}
	return DecryptionResult, nil
}

func stripPadding(contents *[]byte) error {
	for i := len(*contents) - 1; i >= 0; i-- {
		if (*contents)[i] == 0x80 {
			*contents = (*contents)[:i]
			return nil
		} else if (*contents)[i] != 0x00 {
			return fmt.Errorf("Invalid ISO7816 padding")
		}
	}
	return fmt.Errorf("Invalid ISO7816 padding, len(contents): %v", len(*contents))
}
