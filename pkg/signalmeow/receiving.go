package signalmeow

import (
	"context"
	"encoding/base64"
	"fmt"
	"strings"
	"time"

	"github.com/google/uuid"
	"go.mau.fi/mautrix-signal/pkg/libsignalgo"
	signalpb "go.mau.fi/mautrix-signal/pkg/signalmeow/protobuf"
	"go.mau.fi/mautrix-signal/pkg/signalmeow/web"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/reflect/protoreflect"
)

type SignalConnectionEvent int

const (
	SignalConnectionEventNone SignalConnectionEvent = iota
	SignalConnectionEventConnected
	SignalConnectionEventDisconnected
	SignalConnectionEventLoggedOut
	SignalConnectionEventError
)

type SignalConnectionStatus struct {
	Event SignalConnectionEvent
	Err   error
}

func StartReceiveLoops(ctx context.Context, d *Device) (chan SignalConnectionStatus, error) {
	ctx, cancel := context.WithCancel(ctx)
	handler := incomingRequestHandlerWithDevice(d)
	authChan, err := d.Connection.ConnectAuthedWS(ctx, d.Data, handler)
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
				}
			case status := <-unauthChan:
				lastUnauthStatus = status
				currentStatus = status

				if status.Event == web.SignalWebsocketConnectionEventConnected {
					zlog.Info().Msg("Unauthed websocket connected")
				} else if status.Event == web.SignalWebsocketConnectionEventDisconnected {
					zlog.Err(status.Err).Msg("Unauthed websocket disconnected")
				} else if status.Event == web.SignalWebsocketConnectionEventLoggedOut {
					zlog.Err(status.Err).Msg("Unauthed websocket logged out ** THIS SHOULD BE IMPOSSIBLE **")
				} else if status.Event == web.SignalWebsocketConnectionEventError {
					zlog.Err(status.Err).Msg("Unauthed websocket error")
				}
			}

			var statusToSend SignalConnectionStatus
			if lastAuthStatus.Event == web.SignalWebsocketConnectionEventConnected && lastUnauthStatus.Event == web.SignalWebsocketConnectionEventConnected {
				statusToSend = SignalConnectionStatus{
					Event: SignalConnectionEventConnected,
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
			}
			if statusToSend.Event != 0 && statusToSend != lastSentStatus {
				statusChan <- statusToSend
				lastSentStatus = statusToSend
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
	if authErr != nil {
		return authErr
	}
	if unauthErr != nil {
		return unauthErr
	}
	return nil
}

// Returns a RequestHandlerFunc that can be used to handle incoming requests, with a device injected via closure.
func incomingRequestHandlerWithDevice(device *Device) web.RequestHandlerFunc {
	handler := func(ctx context.Context, req *signalpb.WebSocketRequestMessage) (*web.SimpleResponse, error) {
		responseCode := 400
		if *req.Verb == "PUT" && *req.Path == "/api/v1/message" {
			envelope := &signalpb.Envelope{}
			err := proto.Unmarshal(req.Body, envelope)
			if err != nil {
				zlog.Err(err).Msg("Unmarshal error")
				return nil, err
			}
			var result *DecryptionResult

			if *envelope.Type == signalpb.Envelope_UNIDENTIFIED_SENDER {
				zlog.Trace().Msgf("Received envelope type UNIDENTIFIED_SENDER, verb: %v, path: %v", *req.Verb, *req.Path)
				ctx := context.Background()
				usmc, err := libsignalgo.SealedSenderDecryptToUSMC(
					envelope.GetContent(),
					device.IdentityStore,
					libsignalgo.NewCallbackContext(ctx),
				)
				if err != nil {
					zlog.Err(err).Msg("SealedSenderDecryptToUSMC error")
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
				usmcContents, err := usmc.GetContents()
				if err != nil {
					zlog.Err(err).Msg("GetContents error")
				}
				zlog.Trace().Msgf("SealedSender senderUUID: %v, senderDeviceID: %v", senderUUID, senderDeviceID)

				if messageType == libsignalgo.CiphertextMessageTypeSenderKey {
					zlog.Trace().Msg("SealedSender messageType is CiphertextMessageTypeSenderKey ")
					decryptedText, err := libsignalgo.GroupDecrypt(
						usmcContents,
						senderAddress,
						device.SenderKeyStore,
						libsignalgo.NewCallbackContext(ctx),
					)
					if err != nil {
						if strings.Contains(err.Error(), "message with old counter") {
							// Duplicate message, ignore
							responseCode = 200
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
						responseCode = 200
					}

				} else if messageType == libsignalgo.CiphertextMessageTypePreKey {
					zlog.Trace().Msg("SealedSender messageType is CiphertextMessageTypePreKey")
					result, err = prekeyDecrypt(*senderAddress, usmcContents, device, ctx)
					if err != nil {
						zlog.Err(err).Msg("prekeyDecrypt error")
					} else {
						responseCode = 200
					}

				} else if messageType == libsignalgo.CiphertextMessageTypeWhisper {
					zlog.Trace().Msg("SealedSender messageType is CiphertextMessageTypeWhisper")
					message, err := libsignalgo.DeserializeMessage(usmcContents)
					if err != nil {
						zlog.Err(err).Msg("DeserializeMessage error")
					}
					decryptedText, err := libsignalgo.Decrypt(
						message,
						senderAddress,
						device.SessionStore,
						device.IdentityStore,
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
						responseCode = 200
					}

				} else if messageType == libsignalgo.CiphertextMessageTypePlaintext {
					zlog.Debug().Msg("SealedSender messageType is CiphertextMessageTypePlaintext")

				} else {
					zlog.Warn().Msg("SealedSender messageType is unknown")
				}

				// If we couldn't decrypt with specific decryption methods, try sealedSenderDecrypt
				if result == nil || responseCode != 200 {
					zlog.Debug().Msg("Didn't decrypt with specific methods, trying sealedSenderDecrypt")
					var err error
					result, err = sealedSenderDecrypt(envelope, device, ctx)
					if err != nil {
						if strings.Contains(err.Error(), "self send of a sealed sender message") {
							// Message sent by us, ignore
							responseCode = 200
							zlog.Debug().Msg("Message sent by us, ignoring")
						} else {
							zlog.Err(err).Msg("sealedSenderDecrypt error")
						}
					} else {
						zlog.Trace().Msgf("SealedSender decrypt result - address: %v, content: %v", result.SenderAddress, result.Content)
						responseCode = 200
					}
				}

			} else if *envelope.Type == signalpb.Envelope_PREKEY_BUNDLE {
				zlog.Debug().Msgf("Received envelope type PREKEY_BUNDLE, verb: %v, path: %v", *req.Verb, *req.Path)
				sender, err := libsignalgo.NewAddress(
					*envelope.SourceUuid,
					uint(*envelope.SourceDevice),
				)
				if err != nil {
					return nil, fmt.Errorf("NewAddress error: %v", err)
				}
				result, err = prekeyDecrypt(*sender, envelope.Content, device, ctx)
				if err != nil {
					zlog.Err(err).Msg("prekeyDecrypt error")
				} else {
					zlog.Trace().Msgf("prekey decrypt result -  address: %v, data: %v", result.SenderAddress, result.Content)
					responseCode = 200
				}

			} else if *envelope.Type == signalpb.Envelope_PLAINTEXT_CONTENT {
				zlog.Debug().Msgf("Received envelope type PLAINTEXT_CONTENT, verb: %v, path: %v", *req.Verb, *req.Path)

			} else if *envelope.Type == signalpb.Envelope_CIPHERTEXT {
				zlog.Debug().Msgf("Received envelope type CIPHERTEXT, verb: %v, path: %v", *req.Verb, *req.Path)
				message, err := libsignalgo.DeserializeMessage(envelope.Content)
				if err != nil {
					zlog.Err(err).Msg("DeserializeMessage error")
				}
				senderAddress, err := libsignalgo.NewAddress(
					*envelope.SourceUuid,
					uint(*envelope.SourceDevice),
				)
				decryptedText, err := libsignalgo.Decrypt(
					message,
					senderAddress,
					device.SessionStore,
					device.IdentityStore,
					libsignalgo.NewCallbackContext(ctx),
				)
				if err != nil {
					if strings.Contains(err.Error(), "message with old counter") {
						// Duplicate message, ignore
						responseCode = 200
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
					responseCode = 200
				}

			} else if *envelope.Type == signalpb.Envelope_RECEIPT {
				zlog.Debug().Msgf("Received envelope type RECEIPT, verb: %v, path: %v", *req.Verb, *req.Path)
				// TODO: handle receipt
				responseCode = 200

			} else if *envelope.Type == signalpb.Envelope_KEY_EXCHANGE {
				zlog.Debug().Msgf("Received envelope type KEY_EXCHANGE, verb: %v, path: %v", *req.Verb, *req.Path)

			} else if *envelope.Type == signalpb.Envelope_UNKNOWN {
				zlog.Warn().Msgf("Received envelope type UNKNOWN, verb: %v, path: %v", *req.Verb, *req.Path)

			} else {
				zlog.Warn().Msgf("Received actual unknown envelope type, verb: %v, path: %v", *req.Verb, *req.Path)
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
						device.SenderKeyStore,
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
							destination := content.SyncMessage.Sent.DestinationUuid
							if content.SyncMessage.Sent.Message.GroupV2 != nil {
								zlog.Debug().Msgf("sync message sent group: %v", content.SyncMessage.Sent.Message.GroupV2)
								masterKey := libsignalgo.GroupMasterKey(content.SyncMessage.Sent.Message.GroupV2.MasterKey)
								g := string(groupIDFromMasterKey(masterKey))
								destination = &g
							}
							if destination == nil {
								err := fmt.Errorf("sync message sent destination is nil")
								zlog.Err(err).Msg("")
								return nil, err
							}
							err = incomingDataMessage(ctx, device, content.SyncMessage.Sent.Message, device.Data.AciUuid, *destination)
							if err != nil {
								zlog.Err(err).Msg("incomingDataMessage error")
								return nil, err
							}
						}
					}
				}

				if content.DataMessage != nil {
					err = incomingDataMessage(ctx, device, content.DataMessage, theirUuid, device.Data.AciUuid)
					if err != nil {
						zlog.Err(err).Msg("incomingDataMessage error")
						return nil, err
					}
				}
			}

		} else if *req.Verb == "PUT" && *req.Path == "/api/v1/queue/empty" {
			zlog.Trace().Msgf("Received queue empty. verb: %v, path: %v", *req.Verb, *req.Path)
			responseCode = 200
		} else {
			zlog.Warn().Msgf("######## Don't know what I received ########## req: %v", req)
		}
		return &web.SimpleResponse{
			Status: responseCode,
		}, nil
	}
	return handler
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

func incomingDataMessage(ctx context.Context, device *Device, dataMessage *signalpb.DataMessage, senderUUID string, recipientUUID string) error {
	// If there's a profile key, save it
	if dataMessage.ProfileKey != nil {
		profileKey := libsignalgo.ProfileKey(dataMessage.ProfileKey)
		err := device.ProfileKeyStore.StoreProfileKey(senderUUID, profileKey, ctx)
		if err != nil {
			zlog.Err(err).Msg("StoreProfileKey error")
			return err
		}
	}

	// If it's a group message, get the ID and invalidate cache if necessary
	var groupID *GroupID
	if dataMessage.GetGroupV2() != nil {
		groupMasterKeyBytes := dataMessage.GetGroupV2().GetMasterKey()

		// TODO: should we be using base64 masterkey as an ID????!?
		groupIDValue := groupIDFromMasterKey(libsignalgo.GroupMasterKey(groupMasterKeyBytes))
		groupID = &groupIDValue

		if dataMessage.GetGroupV2().GroupChange != nil {
			// TODO: don't parse the change	for now, just invalidate our cache
			zlog.Debug().Msgf("Invalidating group %v due to change: %v", groupIDValue, dataMessage.GetGroupV2().GroupChange)
			InvalidateGroupCache(device, groupIDValue)
		} else if dataMessage.GetGroupV2().GetRevision() > 0 {
			// Compare revision, and if it's newer, invalidate our cache
			ourGroup, err := RetrieveGroupByID(ctx, device, groupIDValue)
			if err != nil {
				zlog.Err(err).Msg("RetrieveGroupByID error")
			} else if dataMessage.GetGroupV2().GetRevision() > ourGroup.Revision {
				zlog.Debug().Msgf("Invalidating group %v due to new revision %v > our revision: %v", groupIDValue, dataMessage.GetGroupV2().GetRevision(), ourGroup.Revision)
				InvalidateGroupCache(device, groupIDValue)
			}
		}
	}

	var incomingMessages []IncomingSignalMessage

	// Grab quote (reply) info if it exists
	var quoteData *IncomingSignalMessageQuoteData
	if dataMessage.Quote != nil {
		quoteData = &IncomingSignalMessageQuoteData{
			QuotedSender:    dataMessage.GetQuote().GetAuthorUuid(),
			QuotedTimestamp: dataMessage.GetQuote().GetId(),
		}
	}

	// If there's attachements, handle them (one at a time for now)
	if dataMessage.Attachments != nil {
		for _, attachmentPointer := range dataMessage.Attachments {
			bytes, err := fetchAndDecryptAttachment(attachmentPointer)
			if err != nil {
				zlog.Err(err).Msg("fetchAndDecryptAttachment error")
				continue
			}
			// TODO: right now this will be one message per image, each with the same caption
			if strings.HasPrefix(attachmentPointer.GetContentType(), "image") {
				incomingMessage := IncomingSignalMessageImage{
					IncomingSignalMessageBase: IncomingSignalMessageBase{
						SenderUUID:    senderUUID,
						RecipientUUID: recipientUUID,
						GroupID:       groupID,
						Timestamp:     dataMessage.GetTimestamp(),
						Quote:         quoteData,
					},
					Image:       bytes,
					Caption:     dataMessage.GetBody(),
					Filename:    attachmentPointer.GetFileName(),
					ContentType: attachmentPointer.GetContentType(),
					Size:        uint64(attachmentPointer.GetSize()),
					Width:       attachmentPointer.GetWidth(),
					Height:      attachmentPointer.GetHeight(),
					BlurHash:    attachmentPointer.GetBlurHash(),
				}
				incomingMessages = append(incomingMessages, incomingMessage)
			} else {
				// Unhandled attachment
				zlog.Debug().Msgf("Unhandled attachment: %v", attachmentPointer)
				incomingMessage := IncomingSignalMessageUnhandled{
					IncomingSignalMessageBase: IncomingSignalMessageBase{
						SenderUUID:    senderUUID,
						RecipientUUID: recipientUUID,
						GroupID:       groupID,
						Timestamp:     dataMessage.GetTimestamp(),
						Quote:         quoteData,
					},
					Type:   "attachment",
					Notice: fmt.Sprintf("Unhandled attachment of type: %v", attachmentPointer.GetContentType()),
				}
				incomingMessages = append(incomingMessages, incomingMessage)
			}
		}
	}

	// If there's a body but no attachments, pass along as a text message
	if dataMessage.Body != nil && dataMessage.Attachments == nil {
		incomingMessage := IncomingSignalMessageText{
			IncomingSignalMessageBase: IncomingSignalMessageBase{
				SenderUUID:    senderUUID,
				RecipientUUID: recipientUUID,
				GroupID:       groupID,
				Timestamp:     dataMessage.GetTimestamp(),
				Quote:         quoteData,
			},
			Content: dataMessage.GetBody(),
		}
		incomingMessages = append(incomingMessages, incomingMessage)
	}

	// Pass along reactions
	if dataMessage.Reaction != nil {
		incomingMessage := IncomingSignalMessageReaction{
			IncomingSignalMessageBase: IncomingSignalMessageBase{
				SenderUUID:    senderUUID,
				RecipientUUID: recipientUUID,
				GroupID:       groupID,
				Timestamp:     dataMessage.GetTimestamp(),
				Quote:         quoteData,
			},
			Emoji:                  dataMessage.GetReaction().GetEmoji(),
			Remove:                 dataMessage.GetReaction().GetRemove(),
			TargetAuthorUUID:       dataMessage.GetReaction().GetTargetAuthorUuid(),
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
				GroupID:       groupID,
				Timestamp:     dataMessage.GetTimestamp(),
				Quote:         quoteData,
			},
			TargetMessageTimestamp: dataMessage.GetDelete().GetTargetSentTimestamp(),
		}
		incomingMessages = append(incomingMessages, incomingMessage)
	}

	if device.Connection.IncomingSignalMessageHandler != nil {
		for _, incomingMessage := range incomingMessages {
			device.Connection.IncomingSignalMessageHandler(incomingMessage)
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
