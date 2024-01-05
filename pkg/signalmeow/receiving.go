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

func (cli *Client) StartReceiveLoops(ctx context.Context) (chan SignalConnectionStatus, error) {
	ctx, cancel := context.WithCancel(ctx)
	cli.WSCancel = cancel
	authChan, err := cli.ConnectAuthedWS(ctx, cli.incomingRequestHandler)
	if err != nil {
		cancel()
		return nil, err
	}
	zlog.Info().Msg("Authed websocket connecting")
	unauthChan, err := cli.ConnectUnauthedWS(ctx)
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
				// TODO hacky
				cli.SendContactSyncRequest(ctx)
				return
			}
		}
	}()

	return statusChan, nil
}

func (cli *Client) StopReceiveLoops() error {
	defer func() {
		cli.AuthedWS = nil
		cli.UnauthedWS = nil
	}()
	authErr := cli.AuthedWS.Close()
	unauthErr := cli.UnauthedWS.Close()
	if cli.WSCancel != nil {
		cli.WSCancel()
	}
	if authErr != nil {
		return authErr
	}
	if unauthErr != nil {
		return unauthErr
	}
	return nil
}

func (cli *Client) ClearKeysAndDisconnect(ctx context.Context) error {
	// Essentially logout, clearing sessions and keys, and disconnecting websockets
	// but don't clear ACI UUID or profile keys or contacts, or anything else that
	// we can reuse if we reassociate with the same Signal account.
	// To fully "logout" delete the device from the database.
	clearErr := cli.Store.ClearDeviceKeys(ctx)
	clearErr2 := cli.Store.ClearPassword(ctx)
	stopLoopErr := cli.StopReceiveLoops()

	if clearErr != nil {
		return clearErr
	}
	if clearErr2 != nil {
		return clearErr2
	}
	return stopLoopErr
}

// If a bridge can't decrypt prekeys, it's probably because the prekeys are broken so force re-registration
func (cli *Client) checkDecryptionErrorAndDisconnect(err error) {
	if err != nil {
		if strings.Contains(err.Error(), "30: invalid PreKey message: decryption failed") ||
			strings.Contains(err.Error(), "70: invalid signed prekey identifier") {
			zlog.Warn().Msg("Failed decrypting a PreKey message, probably our prekeys are broken, force re-registration")
			disconnectErr := cli.ClearKeysAndDisconnect(context.TODO())
			if disconnectErr != nil {
				zlog.Err(disconnectErr).Msg("ClearKeysAndDisconnect error")
			}
		}
	}
}

func (cli *Client) incomingRequestHandler(ctx context.Context, req *signalpb.WebSocketRequestMessage) (*web.SimpleResponse, error) {
	if *req.Verb == http.MethodPut && *req.Path == "/api/v1/message" {
		return cli.incomingAPIMessageHandler(ctx, req)
	} else if *req.Verb == http.MethodPut && *req.Path == "/api/v1/queue/empty" {
		zlog.Trace().Msgf("Received queue empty. verb: %v, path: %v", *req.Verb, *req.Path)
	} else {
		zlog.Warn().Msgf("######## Don't know what I received ########## req: %v", req)
	}
	return &web.SimpleResponse{
		Status: 200,
	}, nil
}

func (cli *Client) incomingAPIMessageHandler(ctx context.Context, req *signalpb.WebSocketRequestMessage) (*web.SimpleResponse, error) {
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
		usmc, err := libsignalgo.SealedSenderDecryptToUSMC(
			ctx,
			envelope.GetContent(),
			cli.Store.IdentityStore,
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
		senderAddress, err := libsignalgo.NewUUIDAddress(senderUUID, uint(senderDeviceID))
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

		cli.UpdateContactE164(senderUUID, senderE164)

		switch messageType {
		case libsignalgo.CiphertextMessageTypeSenderKey:
			zlog.Trace().Msg("SealedSender messageType is CiphertextMessageTypeSenderKey ")
			decryptedText, err := libsignalgo.GroupDecrypt(
				ctx,
				usmcContents,
				senderAddress,
				cli.Store.SenderKeyStore,
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
			result, err = cli.prekeyDecrypt(ctx, senderAddress, usmcContents)
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
				ctx,
				message,
				senderAddress,
				cli.Store.SessionStore,
				cli.Store.IdentityStore,
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
			result, err = cli.sealedSenderDecrypt(ctx, envelope)
			if err != nil {
				if strings.Contains(err.Error(), "self send of a sealed sender message") {
					zlog.Debug().Msg("Message sent by us, ignoring")
				} else {
					zlog.Err(err).Msg("sealedSenderDecrypt error")
					cli.checkDecryptionErrorAndDisconnect(err)
				}
			} else {
				zlog.Trace().Msgf("SealedSender decrypt result - address: %v, content: %v", result.SenderAddress, result.Content)
			}
		}

	case signalpb.Envelope_PREKEY_BUNDLE:
		zlog.Debug().Msgf("Received envelope type PREKEY_BUNDLE, verb: %v, path: %v", *req.Verb, *req.Path)
		sender, err := libsignalgo.NewUUIDAddressFromString(
			*envelope.SourceServiceId,
			uint(*envelope.SourceDevice),
		)
		if err != nil {
			return nil, fmt.Errorf("NewAddress error: %v", err)
		}
		result, err = cli.prekeyDecrypt(ctx, sender, envelope.Content)
		if err != nil {
			zlog.Err(err).Msg("prekeyDecrypt error")
			cli.checkDecryptionErrorAndDisconnect(err)
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
		senderAddress, err := libsignalgo.NewUUIDAddressFromString(
			*envelope.SourceServiceId,
			uint(*envelope.SourceDevice),
		)
		if err != nil {
			return nil, fmt.Errorf("NewAddress error: %v", err)
		}
		decryptedText, err := libsignalgo.Decrypt(
			ctx,
			message,
			senderAddress,
			cli.Store.SessionStore,
			cli.Store.IdentityStore,
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
				ctx,
				skdm,
				result.SenderAddress,
				cli.Store.SenderKeyStore,
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
				var destinationUUID uuid.UUID
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
					cli.incomingDataMessage(ctx, content.SyncMessage.Sent.Message, cli.Store.ACI, destinationUUID)
				} else if content.SyncMessage.Sent.EditMessage != nil {
					cli.incomingEditMessage(ctx, content.SyncMessage.Sent.EditMessage, cli.Store.ACI, destinationUUID)
				}
			}
			if content.SyncMessage.Contacts != nil {
				zlog.Debug().Msgf("Recieved sync message contacts")
				blob := content.SyncMessage.Contacts.Blob
				if blob != nil {
					contactsBytes, err := DownloadAttachment(ctx, blob)
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
						contact, contactAvatar, err := cli.StoreContactDetailsAsContact(signalContact, &avatars[i])
						if err != nil {
							zlog.Err(err).Msg("StoreContactDetailsAsContact error")
							continue
						}
						// Model each contact as an incoming contact change message
						cli.handleEvent(&events.ContactChange{
							Contact: contact,
							Avatar:  contactAvatar,
						})
					}
				}
			}
			if content.SyncMessage.Read != nil {
				cli.handleEvent(&events.ReadSelf{
					Messages: content.SyncMessage.GetRead(),
				})
			}

		}

		var sendDeliveryReceipt bool
		if content.DataMessage != nil {
			sendDeliveryReceipt = cli.incomingDataMessage(ctx, content.DataMessage, theirUUID, theirUUID)
		} else if content.EditMessage != nil {
			sendDeliveryReceipt = cli.incomingEditMessage(ctx, content.EditMessage, theirUUID, theirUUID)
		}
		if sendDeliveryReceipt {
			// TODO send delivery receipts after actually bridging instead of here
			err = cli.sendDeliveryReceipts(ctx, []uint64{content.DataMessage.GetTimestamp()}, theirUUID)
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
			cli.handleEvent(&events.ChatEvent{
				Info: events.MessageInfo{
					Sender: theirUUID,
					ChatID: groupOrUserID(groupID, theirUUID),
				},
				Event: content.TypingMessage,
			})
		}

		// DM call message (group call is an opaque callMessage and a groupCallUpdate in a dataMessage)
		if content.CallMessage != nil && (content.CallMessage.Offer != nil || content.CallMessage.Hangup != nil) {
			cli.handleEvent(&events.Call{
				Info: events.MessageInfo{
					Sender: theirUUID,
					ChatID: theirUUID.String(),
				},
				IsRinging: content.CallMessage.Offer != nil,
			})
		}

		// Read and delivery receipts
		if content.ReceiptMessage != nil {
			if content.GetReceiptMessage().GetType() == signalpb.ReceiptMessage_DELIVERY && theirUUID == cli.Store.ACI {
				// Ignore delivery receipts from other own devices
				return &web.SimpleResponse{
					Status: responseCode,
				}, nil
			}
			cli.handleEvent(&events.Receipt{
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

func (cli *Client) incomingEditMessage(ctx context.Context, editMessage *signalpb.EditMessage, messageSender, chatRecipient uuid.UUID) bool {
	// If it's a group message, get the ID and invalidate cache if necessary
	var groupID types.GroupIdentifier
	var groupRevision int
	if editMessage.GetDataMessage().GetGroupV2() != nil {
		// Pull out the master key then store it ASAP - we should pass around GroupIdentifier
		groupMasterKeyBytes := editMessage.GetDataMessage().GetGroupV2().GetMasterKey()
		masterKey := masterKeyFromBytes(libsignalgo.GroupMasterKey(groupMasterKeyBytes))
		var err error
		groupID, err = cli.StoreMasterKey(ctx, masterKey)
		if err != nil {
			zlog.Err(err).Msg("StoreMasterKey error")
			return false
		}
		groupRevision = int(editMessage.GetDataMessage().GetGroupV2().GetRevision())
	}
	cli.handleEvent(&events.ChatEvent{
		Info: events.MessageInfo{
			Sender:        messageSender,
			ChatID:        groupOrUserID(groupID, chatRecipient),
			GroupRevision: groupRevision,
		},
		Event: editMessage,
	})
	return true
}

func (cli *Client) incomingDataMessage(ctx context.Context, dataMessage *signalpb.DataMessage, messageSender, chatRecipient uuid.UUID) bool {
	// If there's a profile key, save it
	if dataMessage.ProfileKey != nil {
		profileKey := libsignalgo.ProfileKey(dataMessage.ProfileKey)
		err := cli.Store.ProfileKeyStore.StoreProfileKey(ctx, messageSender, profileKey)
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
		groupID, err = cli.StoreMasterKey(ctx, masterKey)
		if err != nil {
			zlog.Err(err).Msg("StoreMasterKey error")
			return false
		}
		groupRevision = int(dataMessage.GetGroupV2().GetRevision())

		var groupHasChanged = false
		if dataMessage.GetGroupV2().GroupChange != nil {
			// TODO: don't parse the change	for now, just invalidate our cache
			zlog.Debug().Msgf("Invalidating group %v due to change: %v", groupID, dataMessage.GetGroupV2().GroupChange)
			cli.InvalidateGroupCache(groupID)
			groupHasChanged = true
		} else if dataMessage.GetGroupV2().GetRevision() > 0 {
			// Compare revision, and if it's newer, invalidate our cache
			ourGroup, err := cli.RetrieveGroupByID(ctx, groupID)
			if err != nil {
				zlog.Err(err).Msg("RetrieveGroupByID error")
			} else if dataMessage.GetGroupV2().GetRevision() > ourGroup.Revision {
				zlog.Debug().Msgf("Invalidating group %v due to new revision %v > our revision: %v", groupID, dataMessage.GetGroupV2().GetRevision(), ourGroup.Revision)
				cli.InvalidateGroupCache(groupID)
				groupHasChanged = true
			}
		}
		if groupHasChanged {
			cli.handleEvent(&events.GroupChange{
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
		isRinging := cli.UpdateActiveCalls(groupID, *dataMessage.GroupCallUpdate.EraId)
		cli.handleEvent(&events.Call{
			Info:      evtInfo,
			Timestamp: dataMessage.GetTimestamp(),
			IsRinging: isRinging,
		})
	} else {
		cli.handleEvent(&events.ChatEvent{
			Info:  evtInfo,
			Event: dataMessage,
		})
	}

	return true
}

func (cli *Client) sendDeliveryReceipts(ctx context.Context, deliveredTimestamps []uint64, senderUUID uuid.UUID) error {
	// Send delivery receipts
	if len(deliveredTimestamps) > 0 {
		receipt := DeliveredReceiptMessageForTimestamps(deliveredTimestamps)
		result := cli.SendMessage(ctx, senderUUID, receipt)
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

func (cli *Client) sealedSenderDecrypt(ctx context.Context, envelope *signalpb.Envelope) (*DecryptionResult, error) {
	localAddress := libsignalgo.NewSealedSenderAddress(
		cli.Store.Number,
		cli.Store.ACI,
		uint32(cli.Store.DeviceID),
	)
	timestamp := time.Unix(0, int64(*envelope.Timestamp))
	result, err := libsignalgo.SealedSenderDecrypt(
		ctx,
		envelope.Content,
		localAddress,
		serverTrustRootKey(),
		timestamp,
		cli.Store.SessionStore,
		cli.Store.IdentityStore,
		cli.Store.PreKeyStore,
		cli.Store.SignedPreKeyStore,
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
	address, err := libsignalgo.NewUUIDAddress(
		result.Sender.UUID,
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

func (cli *Client) prekeyDecrypt(ctx context.Context, sender *libsignalgo.Address, encryptedContent []byte) (*DecryptionResult, error) {
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
		ctx,
		preKeyMessage,
		sender,
		cli.Store.SessionStore,
		cli.Store.IdentityStore,
		cli.Store.PreKeyStore,
		cli.Store.SignedPreKeyStore,
		cli.Store.KyberPreKeyStore,
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
