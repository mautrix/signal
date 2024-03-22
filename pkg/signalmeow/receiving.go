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
	"github.com/rs/zerolog"
	"go.mau.fi/util/exerrors"
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
	log := zerolog.Ctx(ctx).With().Str("action", "start receive loops").Logger()
	ctx, cancel := context.WithCancel(log.WithContext(ctx))
	cli.WSCancel = cancel
	authChan, err := cli.ConnectAuthedWS(ctx, cli.incomingRequestHandler)
	if err != nil {
		cancel()
		return nil, err
	}
	log.Info().Msg("Authed websocket connecting")
	unauthChan, err := cli.ConnectUnauthedWS(ctx)
	if err != nil {
		cancel()
		return nil, err
	}
	log.Info().Msg("Unauthed websocket connecting")
	statusChan := make(chan SignalConnectionStatus, 10000)

	initialConnectChan := make(chan struct{})

	// Combine both websocket status channels into a single, more generic "Signal" connection status channel
	go func() {
		defer close(statusChan)
		defer cancel()
		var currentStatus, lastAuthStatus, lastUnauthStatus web.SignalWebsocketConnectionStatus
		for {
			select {
			case <-ctx.Done():
				log.Info().Msg("Context done, exiting websocket status loop")
				return
			case status := <-authChan:
				lastAuthStatus = status
				currentStatus = status

				switch status.Event {
				case web.SignalWebsocketConnectionEventConnecting:
					// do nothing?
				case web.SignalWebsocketConnectionEventConnected:
					log.Info().Msg("Authed websocket connected")
				case web.SignalWebsocketConnectionEventDisconnected:
					log.Err(status.Err).Msg("Authed websocket disconnected")
				case web.SignalWebsocketConnectionEventLoggedOut:
					log.Err(status.Err).Msg("Authed websocket logged out")
					// TODO: Also make sure unauthed websocket is disconnected
					//StopReceiveLoops(d)
				case web.SignalWebsocketConnectionEventError:
					log.Err(status.Err).Msg("Authed websocket error")
				case web.SignalWebsocketConnectionEventCleanShutdown:
					log.Info().Msg("Authed websocket clean shutdown")
				}
			case status := <-unauthChan:
				lastUnauthStatus = status
				currentStatus = status

				switch status.Event {
				case web.SignalWebsocketConnectionEventConnecting:
					// do nothing?
				case web.SignalWebsocketConnectionEventConnected:
					log.Info().
						Any("last_unauth_status", lastUnauthStatus).
						Any("last_auth_status", lastAuthStatus).
						Any("current_status", currentStatus).
						Msg("Unauthed websocket connected")
				case web.SignalWebsocketConnectionEventDisconnected:
					log.Err(status.Err).Msg("Unauthed websocket disconnected")
				case web.SignalWebsocketConnectionEventLoggedOut:
					log.Err(status.Err).Msg("Unauthed websocket logged out ** THIS SHOULD BE IMPOSSIBLE **")
				case web.SignalWebsocketConnectionEventError:
					log.Err(status.Err).Msg("Unauthed websocket error")
				case web.SignalWebsocketConnectionEventCleanShutdown:
					log.Info().Msg("Unauthed websocket clean shutdown")
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
			if statusToSend.Event != 0 && statusToSend.Event != cli.lastConnectionStatus.Event {
				log.Info().Any("status_to_send", statusToSend).Msg("Sending connection status")
				statusChan <- statusToSend
				cli.lastConnectionStatus = statusToSend
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
				log.Info().Msg("Both websockets connected, sending contacts sync request")
				// TODO hacky
				cli.SendContactSyncRequest(ctx)
				if cli.Store.MasterKey == nil {
					cli.SendStorageMasterKeyRequest(ctx)
				}
				return
			}
		}
	}()

	// Start loop to check for and upload more prekeys
	cli.StartKeyCheckLoop(ctx)

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

func (cli *Client) LastConnectionStatus() SignalConnectionStatus {
	return cli.lastConnectionStatus
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
func (cli *Client) checkDecryptionErrorAndDisconnect(ctx context.Context, err error) {
	if err == nil {
		return
	}
	log := zerolog.Ctx(ctx).With().Str("action", "check decryption error and disconnect").Logger()
	if strings.Contains(err.Error(), "70: invalid signed prekey identifier") {
		log.Warn().Msg("Failed decrypting a SignedPreKey message, invalid signed prekey identifier")
	}
	if strings.Contains(err.Error(), "30: invalid PreKey message: decryption failed") {
		log.Warn().Msg("Failed decrypting a PreKey message, probably our prekeys are broken, force re-registration")
		disconnectErr := cli.ClearKeysAndDisconnect(ctx)
		if disconnectErr != nil {
			log.Err(disconnectErr).Msg("ClearKeysAndDisconnect error")
		}
	}
}

func (cli *Client) incomingRequestHandler(ctx context.Context, req *signalpb.WebSocketRequestMessage) (*web.SimpleResponse, error) {
	log := zerolog.Ctx(ctx).With().
		Str("handler", "incoming request handler").
		Str("verb", *req.Verb).
		Str("path", *req.Path).
		Logger()
	ctx = log.WithContext(ctx)
	if *req.Verb == http.MethodPut && *req.Path == "/api/v1/message" {
		return cli.incomingAPIMessageHandler(ctx, req)
	} else if *req.Verb == http.MethodPut && *req.Path == "/api/v1/queue/empty" {
		log.Trace().Msg("Received queue empty")
	} else {
		log.Warn().Any("req", req).Msg("Unknown websocket request message")
	}
	return &web.SimpleResponse{
		Status: 200,
	}, nil
}

// TODO: we should split this up into multiple functions
func (cli *Client) incomingAPIMessageHandler(ctx context.Context, req *signalpb.WebSocketRequestMessage) (*web.SimpleResponse, error) {
	log := *zerolog.Ctx(ctx)
	responseCode := 200
	envelope := &signalpb.Envelope{}
	err := proto.Unmarshal(req.Body, envelope)
	if err != nil {
		log.Err(err).Msg("Unmarshal error")
		return nil, err
	}
	destinationServiceID, err := libsignalgo.ServiceIDFromString(envelope.GetDestinationServiceId())
	if err != nil {
		log.Err(err).Str("destination_service_id", envelope.GetDestinationServiceId()).Msg("Failed to parse destination service ID")
		return nil, err
	}
	var result *DecryptionResult
	log.Trace().
		Uint64("timestamp", envelope.GetTimestamp()).
		Str("destination_service_id", envelope.GetDestinationServiceId()).
		Str("source_service_id", envelope.GetSourceServiceId()).
		Uint32("source_device_id", envelope.GetSourceDevice()).
		Object("parsed_destination_service_id", destinationServiceID).
		Int32("envelope_type_id", int32(envelope.GetType())).
		Str("envelope_type", signalpb.Envelope_Type_name[int32(envelope.GetType())]).
		Msg("Received envelope")

	switch *envelope.Type {
	case signalpb.Envelope_UNIDENTIFIED_SENDER:
		if destinationServiceID != cli.Store.ACIServiceID() {
			log.Warn().Stringer("destination_service_id", destinationServiceID).
				Msg("Received UNIDENTIFIED_SENDER envelope for non-ACI destination")
			break
		}
		usmc, err := libsignalgo.SealedSenderDecryptToUSMC(
			ctx,
			envelope.GetContent(),
			cli.Store.IdentityStore,
		)
		if err != nil || usmc == nil {
			if err == nil {
				err = fmt.Errorf("usmc is nil")
			}
			log.Err(err).Msg("SealedSenderDecryptToUSMC error")
			return nil, err
		}

		messageType, err := usmc.GetMessageType()
		if err != nil {
			log.Err(err).Msg("GetMessageType error")
		}
		senderCertificate, err := usmc.GetSenderCertificate()
		if err != nil {
			log.Err(err).Msg("GetSenderCertificate error")
		}
		senderUUID, err := senderCertificate.GetSenderUUID()
		if err != nil {
			log.Err(err).Msg("GetSenderUUID error")
		}
		senderDeviceID, err := senderCertificate.GetDeviceID()
		if err != nil {
			log.Err(err).Msg("GetDeviceID error")
		}
		senderAddress, err := libsignalgo.NewACIServiceID(senderUUID).Address(uint(senderDeviceID))
		if err != nil {
			log.Err(err).Msg("NewAddress error")
		}
		senderE164, err := senderCertificate.GetSenderE164()
		if err != nil {
			log.Err(err).Msg("GetSenderE164 error")
		}
		usmcContents, err := usmc.GetContents()
		if err != nil {
			log.Err(err).Msg("GetContents error")
		}
		log = log.With().
			Stringer("sender_uuid", senderUUID).
			Uint32("sender_device_id", senderDeviceID).
			Str("sender_e164", senderE164).
			Logger()
		ctx = log.WithContext(ctx)
		log.Trace().Msg("Received SealedSender message")

		cli.Store.RecipientStore.UpdateRecipientE164(ctx, senderUUID, uuid.Nil, senderE164)

		switch messageType {
		case libsignalgo.CiphertextMessageTypeSenderKey:
			log.Trace().Msg("SealedSender messageType is CiphertextMessageTypeSenderKey")
			decryptedText, err := libsignalgo.GroupDecrypt(
				ctx,
				usmcContents,
				senderAddress,
				cli.Store.SenderKeyStore,
			)
			if err != nil {
				if strings.Contains(err.Error(), "message with old counter") {
					log.Warn().Msg("Duplicate message, ignoring")
				} else {
					log.Err(err).Msg("GroupDecrypt error")
				}
			} else {
				err = stripPadding(&decryptedText)
				if err != nil {
					return nil, fmt.Errorf("stripPadding error: %v", err)
				}
				content := signalpb.Content{}
				err = proto.Unmarshal(decryptedText, &content)
				if err != nil {
					log.Err(err).Msg("Unmarshal error")
				}
				result = &DecryptionResult{
					SenderAddress: senderAddress,
					Content:       &content,
					SealedSender:  true,
				}
			}

		case libsignalgo.CiphertextMessageTypePreKey:
			log.Trace().Msg("SealedSender messageType is CiphertextMessageTypePreKey")
			result, err = cli.prekeyDecrypt(ctx, destinationServiceID, senderAddress, usmcContents)
			if err != nil {
				log.Err(err).Msg("prekeyDecrypt error")
			}

		case libsignalgo.CiphertextMessageTypeWhisper:
			log.Trace().Msg("SealedSender messageType is CiphertextMessageTypeWhisper")
			message, err := libsignalgo.DeserializeMessage(usmcContents)
			if err != nil {
				log.Err(err).Msg("DeserializeMessage error")
			}
			decryptedText, err := libsignalgo.Decrypt(
				ctx,
				message,
				senderAddress,
				cli.Store.ACISessionStore,
				cli.Store.IdentityStore,
			)
			if err != nil {
				log.Err(err).Msg("Sealed sender Whisper Decryption error")
			} else {
				err = stripPadding(&decryptedText)
				if err != nil {
					return nil, fmt.Errorf("stripPadding error: %v", err)
				}
				content := signalpb.Content{}
				err = proto.Unmarshal(decryptedText, &content)
				if err != nil {
					log.Err(err).Msg("Unmarshal error")
				}
				result = &DecryptionResult{
					SenderAddress: senderAddress,
					Content:       &content,
					SealedSender:  true,
				}
			}

		case libsignalgo.CiphertextMessageTypePlaintext:
			log.Debug().Msg("SealedSender messageType is CiphertextMessageTypePlaintext")
			// TODO: handle plaintext (usually DecryptionErrorMessage) and retries
			// when implementing SenderKey groups

			//plaintextContent, err := libsignalgo.DeserializePlaintextContent(usmcContents)
			//if err != nil {
			//	log.Err(err).Msg("DeserializePlaintextContent error")
			//}
			//body, err := plaintextContent.GetBody()
			//if err != nil {
			//	log.Err(err).Msg("PlaintextContent GetBody error")
			//}
			//content := signalpb.Content{}
			//err = proto.Unmarshal(body, &content)
			//if err != nil {
			//	log.Err(err).Msg("PlaintextContent Unmarshal error")
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
			log.Warn().Msg("SealedSender messageType is unknown")
		}

		// If we couldn't decrypt with specific decryption methods, try sealedSenderDecrypt
		if result == nil || responseCode != 200 {
			log.Debug().Msg("Didn't decrypt with specific methods, trying sealedSenderDecrypt")
			var err error
			result, err = cli.sealedSenderDecrypt(ctx, envelope)
			if err != nil {
				if strings.Contains(err.Error(), "self send of a sealed sender message") {
					log.Debug().Msg("Message sent by us, ignoring")
				} else {
					log.Err(err).Msg("sealedSenderDecrypt error")
					cli.checkDecryptionErrorAndDisconnect(ctx, err)
				}
			} else {
				log.Trace().
					Any("sender_address", result.SenderAddress).
					Any("content", result.Content).
					Msg("SealedSender decrypt result")
			}
		}

	case signalpb.Envelope_PREKEY_BUNDLE:
		sender, err := libsignalgo.NewUUIDAddressFromString(
			*envelope.SourceServiceId,
			uint(*envelope.SourceDevice),
		)
		if err != nil {
			return nil, fmt.Errorf("NewAddress error: %v", err)
		}
		result, err = cli.prekeyDecrypt(ctx, destinationServiceID, sender, envelope.Content)
		if err != nil {
			log.Err(err).Msg("prekeyDecrypt error")
			cli.checkDecryptionErrorAndDisconnect(ctx, err)
		} else {
			log.Trace().
				Any("sender_address", result.SenderAddress).
				Any("content", result.Content).
				Msg("prekey decrypt result")
		}

	case signalpb.Envelope_PLAINTEXT_CONTENT:

	case signalpb.Envelope_CIPHERTEXT:
		message, err := libsignalgo.DeserializeMessage(envelope.Content)
		if err != nil {
			log.Err(err).Msg("DeserializeMessage error")
		}
		senderAddress, err := libsignalgo.NewUUIDAddressFromString(
			*envelope.SourceServiceId,
			uint(*envelope.SourceDevice),
		)
		if err != nil {
			return nil, fmt.Errorf("NewAddress error: %w", err)
		}
		sessionStore := cli.Store.SessionStore(destinationServiceID)
		if sessionStore == nil {
			return nil, fmt.Errorf("no session store for destination service ID %s", destinationServiceID)
		}
		decryptedText, err := libsignalgo.Decrypt(
			ctx,
			message,
			senderAddress,
			sessionStore,
			cli.Store.IdentityStore,
		)
		if err != nil {
			if strings.Contains(err.Error(), "message with old counter") {
				log.Info().Msg("Duplicate message, ignoring")
			} else {
				log.Err(err).Msg("Whisper Decryption error")
			}
		} else {
			err = stripPadding(&decryptedText)
			if err != nil {
				return nil, fmt.Errorf("stripPadding error: %v", err)
			}
			content := signalpb.Content{}
			err = proto.Unmarshal(decryptedText, &content)
			if err != nil {
				log.Err(err).Msg("Unmarshal error")
			}
			result = &DecryptionResult{
				SenderAddress: senderAddress,
				Content:       &content,
			}
		}

	case signalpb.Envelope_RECEIPT:
		// TODO: handle receipt

	case signalpb.Envelope_KEY_EXCHANGE:
		responseCode = 400

	case signalpb.Envelope_UNKNOWN:
		responseCode = 400

	default:
		log.Warn().Msg("Received actual unknown envelope type")
		responseCode = 400
	}

	// Handle content that is now decrypted
	if result != nil && result.Content != nil {
		content := result.Content
		log.Trace().Any("raw_data", content).Msg("Raw event data")

		name, _ := result.SenderAddress.Name()
		deviceId, _ := result.SenderAddress.DeviceID()
		log = log.With().
			Str("sender_name", name).
			Uint("sender_device_id", deviceId).
			Str("destination_service_id", destinationServiceID.String()).
			Logger()
		ctx = log.WithContext(ctx)
		log.Debug().Msg("Decrypted message")
		printContentFieldString(ctx, content, "Decrypted content fields")

		// If there's a sender key distribution message, process it
		if content.GetSenderKeyDistributionMessage() != nil {
			log.Debug().Msg("content includes sender key distribution message")
			skdm, err := libsignalgo.DeserializeSenderKeyDistributionMessage(content.GetSenderKeyDistributionMessage())
			if err != nil {
				log.Err(err).Msg("DeserializeSenderKeyDistributionMessage error")
				return nil, err
			}
			err = libsignalgo.ProcessSenderKeyDistributionMessage(
				ctx,
				skdm,
				result.SenderAddress,
				cli.Store.SenderKeyStore,
			)
			if err != nil {
				log.Err(err).Msg("ProcessSenderKeyDistributionMessage error")
				return nil, err
			}
		}

		theirServiceID, err := result.SenderAddress.NameServiceID()
		if err != nil {
			log.Err(err).Msg("Name error")
			return nil, err
		} else if theirServiceID.Type != libsignalgo.ServiceIDTypeACI {
			log.Warn().Any("their_service_id", theirServiceID).Msg("Sender ServiceID is not an ACI")
			return &web.SimpleResponse{
				Status: responseCode,
			}, nil
		}

		if content.GetPniSignatureMessage() != nil {
			log.Debug().Msg("Content includes PNI signature message")
			err = cli.handlePNISignatureMessage(ctx, theirServiceID, content.GetPniSignatureMessage())
			if err != nil {
				log.Err(err).
					Hex("pni_raw", content.GetPniSignatureMessage().GetPni()).
					Stringer("aci", theirServiceID.UUID).
					Msg("Failed to verify ACI-PNI mapping")
			}
		}

		// TODO: handle more sync messages
		if content.SyncMessage != nil {
			if content.SyncMessage.Keys != nil {
				cli.Store.MasterKey = content.SyncMessage.Keys.GetMaster()
				err = cli.Store.DeviceStore.PutDevice(ctx, &cli.Store.DeviceData)
				if err != nil {
					log.Err(err).Msg("Failed to save device after receiving master key")
				} else {
					log.Info().Msg("Received master key")
					go cli.SyncStorage(ctx)
				}
			} else if content.SyncMessage.GetFetchLatest().GetType() == signalpb.SyncMessage_FetchLatest_STORAGE_MANIFEST {
				log.Debug().Msg("Received storage manifest fetch latest notice")
				go cli.SyncStorage(ctx)
			}
			syncSent := content.SyncMessage.GetSent()
			if syncSent.GetMessage() != nil || syncSent.GetEditMessage() != nil {
				destination := syncSent.DestinationServiceId
				var syncDestinationServiceID libsignalgo.ServiceID
				if destination != nil {
					syncDestinationServiceID, err = libsignalgo.ServiceIDFromString(*destination)
					if err != nil {
						log.Err(err).Msg("Sync message destination parse error")
						return nil, err
					}
				}
				if destination == nil && syncSent.GetMessage().GetGroupV2() == nil && syncSent.GetEditMessage().GetDataMessage().GetGroupV2() == nil {
					log.Warn().Msg("sync message sent destination is nil")
				} else if content.SyncMessage.Sent.Message != nil {
					// TODO handle expiration start ts, and maybe the sync message ts?
					cli.incomingDataMessage(ctx, content.SyncMessage.Sent.Message, cli.Store.ACI, syncDestinationServiceID)
				} else if content.SyncMessage.Sent.EditMessage != nil {
					cli.incomingEditMessage(ctx, content.SyncMessage.Sent.EditMessage, cli.Store.ACI, syncDestinationServiceID)
				}
			}
			if content.SyncMessage.Contacts != nil {
				log.Debug().Msg("Recieved sync message contacts")
				blob := content.SyncMessage.Contacts.Blob
				if blob != nil {
					contactsBytes, err := DownloadAttachment(ctx, blob)
					if err != nil {
						log.Err(err).Msg("Contacts Sync DownloadAttachment error")
					}
					// unmarshall contacts
					contacts, avatars, err := unmarshalContactDetailsMessages(contactsBytes)
					if err != nil {
						log.Err(err).Msg("Contacts Sync unmarshalContactDetailsMessages error")
					}
					log.Debug().Int("contact_count", len(contacts)).Msg("Contacts Sync received contacts")
					convertedContacts := make([]*types.Recipient, 0, len(contacts))
					for i, signalContact := range contacts {
						if signalContact.Aci == nil || *signalContact.Aci == "" {
							// TODO lookup PNI via CDSI and store that when ACI is missing?
							log.Info().
								Any("contact", signalContact).
								Msg("Signal Contact UUID is nil, skipping")
							continue
						}
						contact, err := cli.StoreContactDetailsAsContact(ctx, signalContact, &avatars[i])
						if err != nil {
							log.Err(err).Msg("StoreContactDetailsAsContact error")
							continue
						}
						convertedContacts = append(convertedContacts, contact)
					}
					cli.handleEvent(&events.ContactList{
						Contacts: convertedContacts,
					})
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
			sendDeliveryReceipt = cli.incomingDataMessage(ctx, content.DataMessage, theirServiceID.UUID, theirServiceID)
		} else if content.EditMessage != nil {
			sendDeliveryReceipt = cli.incomingEditMessage(ctx, content.EditMessage, theirServiceID.UUID, theirServiceID)
		}
		if sendDeliveryReceipt {
			// TODO send delivery receipts after actually bridging instead of here
			err = cli.sendDeliveryReceipts(ctx, []uint64{content.DataMessage.GetTimestamp()}, theirServiceID.UUID)
			if err != nil {
				log.Err(err).Msg("sendDeliveryReceipts error")
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
					Sender: theirServiceID.UUID,
					ChatID: groupOrUserID(groupID, theirServiceID),
				},
				Event: content.TypingMessage,
			})
		}

		// DM call message (group call is an opaque callMessage and a groupCallUpdate in a dataMessage)
		if content.CallMessage != nil && (content.CallMessage.Offer != nil || content.CallMessage.Hangup != nil) {
			cli.handleEvent(&events.Call{
				Info: events.MessageInfo{
					Sender: theirServiceID.UUID,
					ChatID: theirServiceID.String(),
				},
				IsRinging: content.CallMessage.Offer != nil,
			})
		}

		// Read and delivery receipts
		if content.ReceiptMessage != nil {
			if content.GetReceiptMessage().GetType() == signalpb.ReceiptMessage_DELIVERY && theirServiceID == cli.Store.ACIServiceID() {
				// Ignore delivery receipts from other own devices
				return &web.SimpleResponse{
					Status: responseCode,
				}, nil
			}
			cli.handleEvent(&events.Receipt{
				Sender:  theirServiceID.UUID,
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
		fmt.Fprintf(builder, "%s (%s), ", currentField, fd.Kind().String())
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

func printContentFieldString(ctx context.Context, c *signalpb.Content, message string) {
	log := zerolog.Ctx(ctx)
	go func() {
		// catch panic
		defer func() {
			if r := recover(); r != nil {
				log.Warn().Any("recover", r).Msg("Panic in contentFieldsString")
			}
		}()
		log.Debug().Str("content_fields", contentFieldsString(c)).Msg(message)
	}()
}

func contentFieldsString(c *signalpb.Content) string {
	var builder strings.Builder
	printStructFields(c.ProtoReflect(), "", &builder)
	return builder.String()
}

func groupOrUserID(groupID types.GroupIdentifier, userID libsignalgo.ServiceID) string {
	if groupID == "" {
		return userID.String()
	}
	return string(groupID)
}

func (cli *Client) handlePNISignatureMessage(ctx context.Context, sender libsignalgo.ServiceID, msg *signalpb.PniSignatureMessage) error {
	if sender.Type != libsignalgo.ServiceIDTypeACI {
		return fmt.Errorf("PNI signature message sender is not an ACI")
	}
	pniBytes := msg.GetPni()
	if len(pniBytes) != 16 {
		return fmt.Errorf("unexpected PNI length %d (expected 16)", len(pniBytes))
	}
	pni := uuid.UUID(pniBytes)
	pniServiceID := libsignalgo.NewPNIServiceID(pni)
	pniIdentity, err := cli.Store.IdentityStore.GetIdentityKey(ctx, pniServiceID)
	if err != nil {
		return fmt.Errorf("failed to get identity for PNI %s: %w", pni, err)
	} else if pniIdentity == nil {
		return fmt.Errorf("identity not found for PNI %s", pni)
	}
	aciIdentity, err := cli.Store.IdentityStore.GetIdentityKey(ctx, sender)
	if err != nil {
		return fmt.Errorf("failed to get identity for ACI %s: %w", sender, err)
	} else if aciIdentity == nil {
		return fmt.Errorf("identity not found for ACI %s", sender)
	}
	if ok, err := pniIdentity.VerifyAlternateIdentity(aciIdentity, msg.GetSignature()); err != nil {
		return fmt.Errorf("signature validation failed: %w", err)
	} else if !ok {
		return fmt.Errorf("signature is invalid")
	}
	zerolog.Ctx(ctx).Debug().
		Stringer("aci", sender.UUID).
		Stringer("pni", pni).
		Msg("Verified ACI-PNI mapping")
	_, err = cli.Store.RecipientStore.LoadAndUpdateRecipient(ctx, sender.UUID, pni, nil)
	if err != nil {
		zerolog.Ctx(ctx).Err(err).Msg("Failed to update aci/pni mapping in store")
	}
	cli.handleEvent(&events.ACIFound{ACI: sender, PNI: pniServiceID})
	return nil
}

func (cli *Client) incomingEditMessage(ctx context.Context, editMessage *signalpb.EditMessage, messageSenderACI uuid.UUID, chatRecipient libsignalgo.ServiceID) bool {
	// If it's a group message, get the ID and invalidate cache if necessary
	var groupID types.GroupIdentifier
	var groupRevision uint32
	if editMessage.GetDataMessage().GetGroupV2() != nil {
		// Pull out the master key then store it ASAP - we should pass around GroupIdentifier
		groupMasterKeyBytes := editMessage.GetDataMessage().GetGroupV2().GetMasterKey()
		masterKey := masterKeyFromBytes(libsignalgo.GroupMasterKey(groupMasterKeyBytes))
		var err error
		groupID, err = cli.StoreMasterKey(ctx, masterKey)
		if err != nil {
			zerolog.Ctx(ctx).Err(err).Msg("StoreMasterKey error")
			return false
		}
		groupRevision = editMessage.GetDataMessage().GetGroupV2().GetRevision()
	}
	cli.handleEvent(&events.ChatEvent{
		Info: events.MessageInfo{
			Sender:        messageSenderACI,
			ChatID:        groupOrUserID(groupID, chatRecipient),
			GroupRevision: groupRevision,
		},
		Event: editMessage,
	})
	return true
}

func (cli *Client) incomingDataMessage(ctx context.Context, dataMessage *signalpb.DataMessage, messageSenderACI uuid.UUID, chatRecipient libsignalgo.ServiceID) bool {
	// If there's a profile key, save it
	if dataMessage.ProfileKey != nil {
		profileKey := libsignalgo.ProfileKey(dataMessage.ProfileKey)
		err := cli.Store.RecipientStore.StoreProfileKey(ctx, messageSenderACI, profileKey)
		if err != nil {
			zerolog.Ctx(ctx).Err(err).Msg("StoreProfileKey error")
			return false
		}
	}

	// If it's a group message, get the ID and invalidate cache if necessary
	var groupID types.GroupIdentifier
	var groupRevision uint32
	if dataMessage.GetGroupV2() != nil {
		// Pull out the master key then store it ASAP - we should pass around GroupIdentifier
		groupMasterKeyBytes := dataMessage.GetGroupV2().GetMasterKey()
		masterKey := masterKeyFromBytes(libsignalgo.GroupMasterKey(groupMasterKeyBytes))
		var err error
		groupID, err = cli.StoreMasterKey(ctx, masterKey)
		if err != nil {
			zerolog.Ctx(ctx).Err(err).Msg("StoreMasterKey error")
			return false
		}
		groupRevision = dataMessage.GetGroupV2().GetRevision()
	}

	evtInfo := events.MessageInfo{
		Sender:        messageSenderACI,
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
		result := cli.SendMessage(ctx, libsignalgo.NewACIServiceID(senderUUID), receipt)
		if !result.WasSuccessful {
			return fmt.Errorf("failed to send delivery receipts: %v", result)
		}
	}
	return nil
}

type DecryptionResult struct {
	SenderAddress *libsignalgo.Address
	Content       *signalpb.Content
	SealedSender  bool
}

const prodServerTrustRootStr = "BXu6QIKVz5MA8gstzfOgRQGqyLqOwNKHL6INkv3IHWMF"

var prodServerTrustRootBytes = exerrors.Must(base64.StdEncoding.DecodeString(prodServerTrustRootStr))
var prodServerTrustRootKey = exerrors.Must(libsignalgo.DeserializePublicKey(prodServerTrustRootBytes))

func init() {
	// It's never going to be freed anyway
	prodServerTrustRootKey.CancelFinalizer()
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
		prodServerTrustRootKey,
		timestamp,
		cli.Store.ACISessionStore,
		cli.Store.IdentityStore,
		cli.Store.ACIPreKeyStore,
		cli.Store.ACIPreKeyStore,
	)
	if err != nil {
		return nil, fmt.Errorf("SealedSenderDecrypt error: %w", err)
	}

	msg := result.Message
	err = stripPadding(&msg)
	if err != nil {
		return nil, fmt.Errorf("stripPadding error: %w", err)
	}
	address, err := libsignalgo.NewACIServiceID(result.Sender.UUID).Address(uint(result.Sender.DeviceID))
	if err != nil {
		return nil, fmt.Errorf("NewAddress error: %w", err)
	}
	content := &signalpb.Content{}
	err = proto.Unmarshal(msg, content)
	if err != nil {
		return nil, fmt.Errorf("Unmarshal error: %w", err)
	}
	return &DecryptionResult{
		SenderAddress: address,
		Content:       content,
	}, nil
}

func (cli *Client) prekeyDecrypt(ctx context.Context, destination libsignalgo.ServiceID, sender *libsignalgo.Address, encryptedContent []byte) (*DecryptionResult, error) {
	preKeyMessage, err := libsignalgo.DeserializePreKeyMessage(encryptedContent)
	if err != nil {
		return nil, fmt.Errorf("failed to deserialize prekey message: %w", err)
	} else if preKeyMessage == nil {
		return nil, fmt.Errorf("deserializing prekey message returned nil")
	}
	pks := cli.Store.PreKeyStore(destination)
	if pks == nil {
		return nil, fmt.Errorf("no prekey store found for %s", destination)
	}
	ss := cli.Store.SessionStore(destination)
	if ss == nil {
		return nil, fmt.Errorf("no session store found for %s", destination)
	}

	data, err := libsignalgo.DecryptPreKey(
		ctx,
		preKeyMessage,
		sender,
		ss,
		cli.Store.IdentityStore,
		pks,
		pks,
		pks,
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
