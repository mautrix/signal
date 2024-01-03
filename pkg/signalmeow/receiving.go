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
	"net/http"
	"strings"
	"time"

	"github.com/google/uuid"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/reflect/protoreflect"

	"go.mau.fi/mautrix-signal/pkg/libsignalgo"
	"go.mau.fi/mautrix-signal/pkg/signalmeow/events"
	signalpb "go.mau.fi/mautrix-signal/pkg/signalmeow/protobuf"
	"go.mau.fi/mautrix-signal/pkg/signalmeow/types"
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

				switch status.Event {
				case web.SignalWebsocketConnectionEventConnecting:
					// do nothing?
				case web.SignalWebsocketConnectionEventConnected:
					zlog.Info().Msg("Authed websocket connected")
				case web.SignalWebsocketConnectionEventDisconnected:
					zlog.Err(status.Err).Msg("Authed websocket disconnected")
				case web.SignalWebsocketConnectionEventLoggedOut:
					zlog.Err(status.Err).Msg("Authed websocket logged out")
					// TODO: Also make sure unauthed websocket is disconnected
					//StopReceiveLoops(d)
				case web.SignalWebsocketConnectionEventError:
					zlog.Err(status.Err).Msg("Authed websocket error")
				case web.SignalWebsocketConnectionEventCleanShutdown:
					zlog.Info().Msg("Authed websocket clean shutdown")
				}
			case status := <-unauthChan:
				lastUnauthStatus = status
				currentStatus = status

				switch status.Event {
				case web.SignalWebsocketConnectionEventConnecting:
					// do nothing?
				case web.SignalWebsocketConnectionEventConnected:
					zlog.Info().Msg("Unauthed websocket connected")
					zlog.Info().Msgf("lastUnauthStatus: %v, lastAuthStatus: %v, currentStatus: %v", lastUnauthStatus, lastAuthStatus, currentStatus)
				case web.SignalWebsocketConnectionEventDisconnected:
					zlog.Err(status.Err).Msg("Unauthed websocket disconnected")
				case web.SignalWebsocketConnectionEventLoggedOut:
					zlog.Err(status.Err).Msg("Unauthed websocket logged out ** THIS SHOULD BE IMPOSSIBLE **")
				case web.SignalWebsocketConnectionEventError:
					zlog.Err(status.Err).Msg("Unauthed websocket error")
				case web.SignalWebsocketConnectionEventCleanShutdown:
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
	if *req.Verb == http.MethodPut && *req.Path == "/api/v1/message" {
		return d.incomingAPIMessageHandler(ctx, req)
	} else if *req.Verb == http.MethodPut && *req.Path == "/api/v1/queue/empty" {
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

		d.UpdateContactE164(senderUUID, senderE164)

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
					SenderAddress: senderAddress,
					Content:       &content,
					SealedSender:  true,
				}
			}

		case libsignalgo.CiphertextMessageTypePreKey:
			zlog.Trace().Msg("SealedSender messageType is CiphertextMessageTypePreKey")
			result, err = prekeyDecrypt(senderAddress, usmcContents, d, ctx)
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
					SenderAddress: senderAddress,
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
		result, err = prekeyDecrypt(sender, envelope.Content, d, ctx)
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
				SenderAddress: senderAddress,
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
		zlog.Trace().Any("raw_data", content).Msg("Raw event data")

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
				result.SenderAddress,
				d.SenderKeyStore,
				libsignalgo.NewCallbackContext(ctx),
			)
			if err != nil {
				zlog.Err(err).Msg("ProcessSenderKeyDistributionMessage error")
				return nil, err
			}
		}

		theirUUID, err := result.SenderAddress.NameUUID()
		if err != nil {
			zlog.Err(err).Msg("Name error")
			return nil, err
		}

		// TODO: handle more sync messages
		if content.SyncMessage != nil {
			syncSent := content.SyncMessage.GetSent()
			if syncSent.GetMessage() != nil || syncSent.GetEditMessage() != nil {
				destination := syncSent.DestinationServiceId
				var ourUUID, destinationUUID uuid.UUID
				ourUUID, _ = uuid.Parse(d.Data.AciUuid)
				if destination != nil {
					destinationUUID, err = uuid.Parse(*destination)
					if err != nil {
						zlog.Err(err).Msg("Sync message destination parse error")
						return nil, err
					}
				}
				if destination == nil && syncSent.GetMessage().GetGroupV2() == nil && syncSent.GetEditMessage().GetDataMessage().GetGroupV2() == nil {
					zlog.Warn().Msg("sync message sent destination is nil")
				} else if content.SyncMessage.Sent.Message != nil {
					// TODO handle expiration start ts, and maybe the sync message ts?
					incomingDataMessage(ctx, d, content.SyncMessage.Sent.Message, ourUUID, destinationUUID)
				} else if content.SyncMessage.Sent.EditMessage != nil {
					incomingEditMessage(ctx, d, content.SyncMessage.Sent.EditMessage, ourUUID, destinationUUID)
				}
			}
			if content.SyncMessage.Contacts != nil {
				zlog.Debug().Msgf("Recieved sync message contacts")
				blob := content.SyncMessage.Contacts.Blob
				if blob != nil {
					contactsBytes, err := DownloadAttachment(blob)
					if err != nil {
						zlog.Err(err).Msg("Contacts Sync DownloadAttachment error")
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
						contact, contactAvatar, err := StoreContactDetailsAsContact(d, signalContact, &avatars[i])
						if err != nil {
							zlog.Err(err).Msg("StoreContactDetailsAsContact error")
							continue
						}
						// Model each contact as an incoming contact change message
						d.Connection.handleEvent(&events.ContactChange{
							Contact: contact,
							Avatar:  contactAvatar,
						})
					}
				}
			}
			if content.SyncMessage.Read != nil {
				d.Connection.handleEvent(&events.ReadSelf{
					Messages: content.SyncMessage.GetRead(),
				})
			}

		}

		var sendDeliveryReceipt bool
		if content.DataMessage != nil {
			sendDeliveryReceipt = incomingDataMessage(ctx, d, content.DataMessage, theirUUID, theirUUID)
		} else if content.EditMessage != nil {
			sendDeliveryReceipt = incomingEditMessage(ctx, d, content.EditMessage, theirUUID, theirUUID)
		}
		if sendDeliveryReceipt {
			// TODO send delivery receipts after actually bridging instead of here
			err = sendDeliveryReceipts(ctx, d, []uint64{content.DataMessage.GetTimestamp()}, theirUUID)
			if err != nil {
				zlog.Err(err).Msg("sendDeliveryReceipts error")
			}
		}

		if content.TypingMessage != nil {
			var groupID types.GroupIdentifier
			if content.TypingMessage.GetGroupId() != nil {
				gidBytes := content.TypingMessage.GetGroupId()
				groupID = types.GroupIdentifier(base64.StdEncoding.EncodeToString(gidBytes))
			}
			d.Connection.handleEvent(&events.ChatEvent{
				Info: events.MessageInfo{
					Sender: theirUUID,
					ChatID: groupOrUserID(groupID, theirUUID),
				},
				Event: content.TypingMessage,
			})
		}

		// DM call message (group call is an opaque callMessage and a groupCallUpdate in a dataMessage)
		if content.CallMessage != nil && (content.CallMessage.Offer != nil || content.CallMessage.Hangup != nil) {
			d.Connection.handleEvent(&events.Call{
				Info: events.MessageInfo{
					Sender: theirUUID,
					ChatID: theirUUID.String(),
				},
				IsRinging: content.CallMessage.Offer != nil,
			})
		}

		// Read and delivery receipts
		if content.ReceiptMessage != nil {
			if content.GetReceiptMessage().GetType() == signalpb.ReceiptMessage_DELIVERY && theirUUID.String() == d.Data.AciUuid {
				// Ignore delivery receipts from other own devices
				return &web.SimpleResponse{
					Status: responseCode,
				}, nil
			}
			d.Connection.handleEvent(&events.Receipt{
				Sender:  theirUUID,
				Content: content.ReceiptMessage,
			})
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

func groupOrUserID(groupID types.GroupIdentifier, userID uuid.UUID) string {
	if groupID == "" {
		return userID.String()
	}
	return string(groupID)
}

func incomingEditMessage(ctx context.Context, device *Device, editMessage *signalpb.EditMessage, messageSender, chatRecipient uuid.UUID) bool {
	// If it's a group message, get the ID and invalidate cache if necessary
	var groupID types.GroupIdentifier
	var groupRevision int
	if editMessage.GetDataMessage().GetGroupV2() != nil {
		// Pull out the master key then store it ASAP - we should pass around GroupIdentifier
		groupMasterKeyBytes := editMessage.GetDataMessage().GetGroupV2().GetMasterKey()
		masterKey := masterKeyFromBytes(libsignalgo.GroupMasterKey(groupMasterKeyBytes))
		var err error
		groupID, err = StoreMasterKey(ctx, device, masterKey)
		if err != nil {
			zlog.Err(err).Msg("StoreMasterKey error")
			return false
		}
		groupRevision = int(editMessage.GetDataMessage().GetGroupV2().GetRevision())
	}
	device.Connection.handleEvent(&events.ChatEvent{
		Info: events.MessageInfo{
			Sender:        messageSender,
			ChatID:        groupOrUserID(groupID, chatRecipient),
			GroupRevision: groupRevision,
		},
		Event: editMessage,
	})
	return true
}

func incomingDataMessage(ctx context.Context, device *Device, dataMessage *signalpb.DataMessage, messageSender, chatRecipient uuid.UUID) bool {
	// If there's a profile key, save it
	if dataMessage.ProfileKey != nil {
		profileKey := libsignalgo.ProfileKey(dataMessage.ProfileKey)
		err := device.ProfileKeyStore.StoreProfileKey(messageSender.String(), profileKey, ctx)
		if err != nil {
			zlog.Err(err).Msg("StoreProfileKey error")
			return false
		}
	}

	// If it's a group message, get the ID and invalidate cache if necessary
	var groupID types.GroupIdentifier
	var groupRevision int
	if dataMessage.GetGroupV2() != nil {
		// Pull out the master key then store it ASAP - we should pass around GroupIdentifier
		groupMasterKeyBytes := dataMessage.GetGroupV2().GetMasterKey()
		masterKey := masterKeyFromBytes(libsignalgo.GroupMasterKey(groupMasterKeyBytes))
		var err error
		groupID, err = StoreMasterKey(ctx, device, masterKey)
		if err != nil {
			zlog.Err(err).Msg("StoreMasterKey error")
			return false
		}
		groupRevision = int(dataMessage.GetGroupV2().GetRevision())

		var groupHasChanged = false
		if dataMessage.GetGroupV2().GroupChange != nil {
			// TODO: don't parse the change	for now, just invalidate our cache
			zlog.Debug().Msgf("Invalidating group %v due to change: %v", groupID, dataMessage.GetGroupV2().GroupChange)
			InvalidateGroupCache(device, groupID)
			groupHasChanged = true
		} else if dataMessage.GetGroupV2().GetRevision() > 0 {
			// Compare revision, and if it's newer, invalidate our cache
			ourGroup, err := RetrieveGroupByID(ctx, device, groupID)
			if err != nil {
				zlog.Err(err).Msg("RetrieveGroupByID error")
			} else if dataMessage.GetGroupV2().GetRevision() > ourGroup.Revision {
				zlog.Debug().Msgf("Invalidating group %v due to new revision %v > our revision: %v", groupID, dataMessage.GetGroupV2().GetRevision(), ourGroup.Revision)
				InvalidateGroupCache(device, groupID)
				groupHasChanged = true
			}
		}
		if groupHasChanged {
			device.Connection.handleEvent(&events.GroupChange{
				SenderID:  messageSender,
				Timestamp: dataMessage.GetTimestamp(),
				GroupID:   groupID,
				Revision:  groupRevision,
			})
		}
	}

	evtInfo := events.MessageInfo{
		Sender:        messageSender,
		ChatID:        groupOrUserID(groupID, chatRecipient),
		GroupRevision: groupRevision,
	}
	// Hacky special case for group calls to cache the state
	if dataMessage.GroupCallUpdate != nil {
		isRinging := device.UpdateActiveCalls(groupID, *dataMessage.GroupCallUpdate.EraId)
		device.Connection.handleEvent(&events.Call{
			Info:      evtInfo,
			Timestamp: dataMessage.GetTimestamp(),
			IsRinging: isRinging,
		})
	} else {
		device.Connection.handleEvent(&events.ChatEvent{
			Info:  evtInfo,
			Event: dataMessage,
		})
	}

	return true
}

func sendDeliveryReceipts(ctx context.Context, device *Device, deliveredTimestamps []uint64, senderUUID uuid.UUID) error {
	// Send delivery receipts
	if len(deliveredTimestamps) > 0 {
		receipt := DeliveredReceiptMessageForTimestamps(deliveredTimestamps)
		result := SendMessage(ctx, device, senderUUID.String(), receipt)
		if !result.WasSuccessful {
			zlog.Error().Msgf("Failed to send delivery receipts: %v", result)
		}
	}
	return nil
}

type DecryptionResult struct {
	SenderAddress *libsignalgo.Address
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
		SenderAddress: address,
		Content:       content,
	}
	return DecryptionResult, nil
}

func prekeyDecrypt(sender *libsignalgo.Address, encryptedContent []byte, device *Device, ctx context.Context) (*DecryptionResult, error) {
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
		sender,
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
