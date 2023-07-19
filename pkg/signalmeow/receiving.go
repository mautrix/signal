package signalmeow

import (
	"context"
	"encoding/base64"
	"fmt"
	"log"
	"strings"
	"time"

	"github.com/google/uuid"
	"go.mau.fi/mautrix-signal/pkg/libsignalgo"
	signalpb "go.mau.fi/mautrix-signal/pkg/signalmeow/protobuf"
	"go.mau.fi/mautrix-signal/pkg/signalmeow/web"
	"google.golang.org/protobuf/proto"
)

func StartReceiveLoops(ctx context.Context, d *Device) error {
	handler := incomingRequestHandlerWithDevice(d)
	err := d.Connection.ConnectAuthedWS(ctx, d.Data, handler)
	if err != nil {
		return err
	}
	err = d.Connection.ConnectUnauthedWS(ctx, d.Data)
	if err != nil {
		return err
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
				log.Printf("Unmarshal error: %v", err)
				return nil, err
			}
			var result *DecryptionResult

			if *envelope.Type == signalpb.Envelope_UNIDENTIFIED_SENDER {
				log.Printf("Received envelope type UNIDENTIFIED_SENDER, verb: %v, path: %v", *req.Verb, *req.Path)
				ctx := context.Background()
				usmc, err := libsignalgo.SealedSenderDecryptToUSMC(
					envelope.GetContent(),
					device.IdentityStore,
					libsignalgo.NewCallbackContext(ctx),
				)
				if err != nil {
					log.Printf("SealedSenderDecryptToUSMC error: %v", err)
				}

				messageType, err := usmc.GetMessageType()
				if err != nil {
					log.Printf("GetMessageType error: %v", err)
				}
				senderCertificate, err := usmc.GetSenderCertificate()
				if err != nil {
					log.Printf("GetSenderCertificate error: %v", err)
				}
				senderUUID, err := senderCertificate.GetSenderUUID()
				if err != nil {
					log.Printf("GetSenderUUID error: %v", err)
				}
				senderDeviceID, err := senderCertificate.GetDeviceID()
				if err != nil {
					log.Printf("GetDeviceID error: %v", err)
				}
				senderAddress, err := libsignalgo.NewAddress(senderUUID.String(), uint(senderDeviceID))
				if err != nil {
					log.Printf("NewAddress error: %v", err)
				}
				usmcContents, err := usmc.GetContents()
				if err != nil {
					log.Printf("GetContents error: %v", err)
				}
				log.Printf("SealedSender senderUUID: %v, senderDeviceID: %v", senderUUID, senderDeviceID)

				if messageType == libsignalgo.CiphertextMessageTypeSenderKey {
					log.Printf("SealedSender messageType is CiphertextMessageTypeSenderKey ")
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
							log.Printf("Duplicate message, ignoring")
						} else {
							log.Printf("GroupDecrypt error: %v", err)
						}
					} else {
						err = stripPadding(&decryptedText)
						if err != nil {
							return nil, fmt.Errorf("stripPadding error: %v", err)
						}
						content := signalpb.Content{}
						err = proto.Unmarshal(decryptedText, &content)
						if err != nil {
							log.Printf("Unmarshal error: %v", err)
						}
						result = &DecryptionResult{
							SenderAddress: *senderAddress,
							Content:       &content,
							SealedSender:  true,
						}
						responseCode = 200
					}

				} else if messageType == libsignalgo.CiphertextMessageTypePreKey {
					log.Printf("SealedSender messageType is CiphertextMessageTypePreKey")
					result, err = prekeyDecrypt(*senderAddress, usmcContents, device, ctx)
					if err != nil {
						if strings.Contains(err.Error(), "null pointer") {
							// TODO: actually fix this, but ignoring for now because they just build up without a 200
							responseCode = 200
							log.Printf("sealed sender prekey decrypt null pointer error, ignoring")
						} else {
							log.Printf("prekeyDecrypt error: %v", err)
						}
					} else {
						responseCode = 200
					}

				} else if messageType == libsignalgo.CiphertextMessageTypeWhisper {
					log.Printf("SealedSender messageType is CiphertextMessageTypeWhisper")
					message, err := libsignalgo.DeserializeMessage(usmcContents)
					if err != nil {
						log.Printf("DeserializeMessage error: %v", err)
					}
					decryptedText, err := libsignalgo.Decrypt(
						message,
						senderAddress,
						device.SessionStore,
						device.IdentityStore,
						libsignalgo.NewCallbackContext(ctx),
					)
					if err != nil {
						log.Printf("Sealed sender Whisper Decryption error: %v", err)
					} else {
						err = stripPadding(&decryptedText)
						if err != nil {
							return nil, fmt.Errorf("stripPadding error: %v", err)
						}
						content := signalpb.Content{}
						err = proto.Unmarshal(decryptedText, &content)
						if err != nil {
							log.Printf("Unmarshal error: %v", err)
						}
						result = &DecryptionResult{
							SenderAddress: *senderAddress,
							Content:       &content,
							SealedSender:  true,
						}
						responseCode = 200
					}

				} else if messageType == libsignalgo.CiphertextMessageTypePlaintext {
					log.Printf("SealedSender messageType is CiphertextMessageTypePlaintext")

				} else {
					log.Printf("SealedSender messageType is unknown")
				}

				// If we couldn't decrypt with specific decryption methods, try sealedSenderDecrypt
				if result == nil || responseCode != 200 {
					log.Printf("Trying sealedSenderDecrypt")
					var err error
					result, err = sealedSenderDecrypt(envelope, device, ctx)
					if err != nil {
						if strings.Contains(err.Error(), "self send of a sealed sender message") {
							// Message sent by us, ignore
							responseCode = 200
							log.Printf("Message sent by us, ignoring")
						} else {
							log.Printf("sealedSenderDecrypt error: %v", err)
						}
					} else {
						log.Printf("-----> SealedSender decrypt result - address: %v, content: %v", result.SenderAddress, result.Content)
						responseCode = 200
					}
				}

			} else if *envelope.Type == signalpb.Envelope_PREKEY_BUNDLE {
				log.Printf("Received envelope type PREKEY_BUNDLE, verb: %v, path: %v", *req.Verb, *req.Path)
				sender, err := libsignalgo.NewAddress(
					*envelope.SourceUuid,
					uint(*envelope.SourceDevice),
				)
				if err != nil {
					return nil, fmt.Errorf("NewAddress error: %v", err)
				}
				result, err := prekeyDecrypt(*sender, envelope.Content, device, ctx)
				if err != nil {
					if strings.Contains(err.Error(), "null pointer") {
						// TODO: actually fix this, but ignoring for now because they just build up without a 200
						responseCode = 200
						log.Printf("prekey decrypt null pointer error, ignoring")
					} else {
						log.Printf("prekeyDecrypt error: %v", err)
					}
				} else {
					log.Printf("-----> PreKey decrypt result -  address: %v, data: %v", result.SenderAddress, result.Content)
					responseCode = 200
				}

			} else if *envelope.Type == signalpb.Envelope_PLAINTEXT_CONTENT {
				log.Printf("Received envelope type PLAINTEXT_CONTENT, verb: %v, path: %v", *req.Verb, *req.Path)

			} else if *envelope.Type == signalpb.Envelope_CIPHERTEXT {
				log.Printf("Received envelope type CIPHERTEXT, verb: %v, path: %v", *req.Verb, *req.Path)
				message, err := libsignalgo.DeserializeMessage(envelope.Content)
				if err != nil {
					log.Printf("DeserializeMessage error: %v", err)
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
					log.Printf("Whisper Decryption error: %v", err)
				} else {
					err = stripPadding(&decryptedText)
					if err != nil {
						return nil, fmt.Errorf("stripPadding error: %v", err)
					}
					content := signalpb.Content{}
					err = proto.Unmarshal(decryptedText, &content)
					if err != nil {
						log.Printf("Unmarshal error: %v", err)
					}
					result = &DecryptionResult{
						SenderAddress: *senderAddress,
						Content:       &content,
						SealedSender:  true,
					}
					responseCode = 200
				}

			} else if *envelope.Type == signalpb.Envelope_RECEIPT {
				log.Printf("Received envelope type RECEIPT, verb: %v, path: %v", *req.Verb, *req.Path)
				// TODO: handle receipt
				responseCode = 200

			} else if *envelope.Type == signalpb.Envelope_KEY_EXCHANGE {
				log.Printf("Received envelope type KEY_EXCHANGE, verb: %v, path: %v", *req.Verb, *req.Path)

			} else if *envelope.Type == signalpb.Envelope_UNKNOWN {
				log.Printf("Received envelope type UNKNOWN, verb: %v, path: %v", *req.Verb, *req.Path)

			} else {
				log.Printf("Received actual unknown envelope type, verb: %v, path: %v", *req.Verb, *req.Path)
			}

			// Handle content that is now decrypted
			if result != nil && result.Content != nil {
				content := result.Content
				log.Printf("-----> content: %v", content)

				// If there's a sender key distribution message, process it
				if content.GetSenderKeyDistributionMessage() != nil {
					log.Printf("-----> sender key distribution message: %v", content.GetSenderKeyDistributionMessage())
					skdm, err := libsignalgo.DeserializeSenderKeyDistributionMessage(content.GetSenderKeyDistributionMessage())
					if err != nil {
						log.Printf("DeserializeSenderKeyDistributionMessage error: %v", err)
						return nil, err
					}
					err = libsignalgo.ProcessSenderKeyDistributionMessage(
						skdm,
						&result.SenderAddress,
						device.SenderKeyStore,
						libsignalgo.NewCallbackContext(ctx),
					)
					if err != nil {
						log.Printf("ProcessSenderKeyDistributionMessage error: %v", err)
						return nil, err
					}
				}

				theirUuid, err := result.SenderAddress.Name()
				if err != nil {
					log.Printf("Name error: %v", err)
					return nil, err
				}

				// TODO: handle more sync messages
				if content.SyncMessage != nil {
					if content.SyncMessage.Sent != nil {
						if content.SyncMessage.Sent.Message != nil {
							senderUuid := content.SyncMessage.Sent.DestinationUuid
							err = handleIncomingDataMessage(ctx, device, content.SyncMessage.Sent.Message, theirUuid, *senderUuid)
							if err != nil {
								log.Printf("handleIncomingDataMessage error: %v", err)
								return nil, err
							}
						}
					}
				}

				if content.DataMessage != nil {
					err = handleIncomingDataMessage(ctx, device, content.DataMessage, theirUuid, device.Data.AciUuid)
					if err != nil {
						log.Printf("handleIncomingDataMessage error: %v", err)
						return nil, err
					}
				}
			}

		} else if *req.Verb == "PUT" && *req.Path == "/api/v1/queue/empty" {
			log.Printf("Received queue empty. verb: %v, path: %v", *req.Verb, *req.Path)
			responseCode = 200
		} else {
			log.Printf("######## Don't know what I received ########## req: %v", req)
		}
		return &web.SimpleResponse{
			Status: responseCode,
		}, nil
	}
	return handler
}

func handleIncomingDataMessage(ctx context.Context, device *Device, dataMessage *signalpb.DataMessage, senderUUID string, recipientUUID string) error {
	// If there's a profile key, save it
	if dataMessage.ProfileKey != nil {
		profileKey := libsignalgo.ProfileKey(dataMessage.ProfileKey)
		err := device.ProfileKeyStore.StoreProfileKey(senderUUID, profileKey, ctx)
		if err != nil {
			log.Printf("StoreProfileKey error: %v", err)
			return err
		}
	}

	if device.Connection.IncomingSignalMessageHandler != nil && dataMessage.Body != nil {
		var groupID *GroupID
		if dataMessage.GetGroupV2() != nil {
			groupMasterKeyBytes := dataMessage.GetGroupV2().GetMasterKey()

			// TODO: should we be using base64 masterkey as an ID????!?
			groupIDValue := groupIDFromMasterKey(libsignalgo.GroupMasterKey(groupMasterKeyBytes))
			groupID = &groupIDValue

			log.Printf("********* GROUP FETCH TEST *********")
			// TODO: is this the best place to always fetch the group?
			group, err := RetrieveGroupById(ctx, device, groupIDValue)
			if err != nil {
				log.Printf("RetrieveGroupById error: %v", err)
				return err
			}
			printGroup(group) // TODO: debug log
		}
		incomingMessage := IncomingSignalMessageText{
			IncomingSignalMessageBase: IncomingSignalMessageBase{
				SenderUUID:    senderUUID,
				RecipientUUID: recipientUUID,
				GroupID:       groupID,
			},
			Timestamp: dataMessage.GetTimestamp(),
			Content:   dataMessage.GetBody(),
		}

		device.Connection.IncomingSignalMessageHandler(incomingMessage)
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
		log.Printf("DecodeString error: %v", err)
		panic(err)
	}
	serverTrustRootKey, err := libsignalgo.DeserializePublicKey(serverTrustRootBytes)
	if err != nil {
		log.Printf("DeserializePublicKey error: %v", err)
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
		return nil, fmt.Errorf("SealedSenderDecrypt error: %v", err)
	}
	msg := result.Message
	err = stripPadding(&msg)
	if err != nil {
		return nil, fmt.Errorf("stripPadding error: %v", err)
	}
	address, err := libsignalgo.NewAddress(
		result.Sender.UUID.String(),
		uint(result.Sender.DeviceID),
	)
	if err != nil {
		return nil, fmt.Errorf("NewAddress error: %v", err)
	}
	content := &signalpb.Content{}
	err = proto.Unmarshal(msg, content)
	if err != nil {
		log.Printf("Unmarshal error: %v", err)
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
		return nil, fmt.Errorf("DeserializePreKeyMessage error: %v", err)
	}
	if preKeyMessage == nil {
		return nil, fmt.Errorf("preKeyMessage is nil")
	}

	data, err := libsignalgo.DecryptPreKey(
		preKeyMessage,
		&sender,
		device.SessionStore,
		device.IdentityStore,
		device.PreKeyStore,
		device.SignedPreKeyStore,
		libsignalgo.NewCallbackContext(ctx),
	)
	if err != nil {
		return nil, fmt.Errorf("DecryptPreKey error: %v", err)
	}
	err = stripPadding(&data)
	if err != nil {
		return nil, fmt.Errorf("stripPadding error: %v", err)
	}
	content := &signalpb.Content{}
	err = proto.Unmarshal(data, content)
	if err != nil {
		log.Printf("Unmarshal error: %v", err)
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
