package signalmeow

import (
	"context"
	"encoding/base64"
	"fmt"
	"log"
	"time"

	"github.com/google/uuid"
	"go.mau.fi/mautrix-signal/pkg/libsignalgo"
	signalpb "go.mau.fi/mautrix-signal/pkg/signalmeow/protobuf"
	"go.mau.fi/mautrix-signal/pkg/signalmeow/store"
	"go.mau.fi/mautrix-signal/pkg/signalmeow/web"
	"google.golang.org/protobuf/proto"
)

func StartReceiveLoops(ctx context.Context, d *store.Device) error {
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
func incomingRequestHandlerWithDevice(device *store.Device) web.RequestHandlerFunc {
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
						log.Printf("GroupDecrypt error: %v", err)
					} else {
						responseCode = 200
						log.Printf("===== GROUP decryptedText: %v ===== ", decryptedText)
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
					}

				} else if messageType == libsignalgo.CiphertextMessageTypePreKey {
					log.Printf("SealedSender messageType is CiphertextMessageTypePreKey")
					result, err = prekeyDecrypt(*senderAddress, usmcContents, device, ctx)
					if err != nil {
						log.Printf("prekeyDecrypt error: %v", err)
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
						log.Printf("Whisper Decryption error: %v", err)
					} else {
						responseCode = 200
						log.Printf("===== Whisper decryptedText: %v ===== ", decryptedText)
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
					}

				} else if messageType == libsignalgo.CiphertextMessageTypePlaintext {
					log.Printf("SealedSender messageType is CiphertextMessageTypePlaintext")

				} else {
					log.Printf("SealedSender messageType is unknown")
				}

				// If we couldn't decrypt with specific decryption methods, try sealedSenderDecrypt
				if result == nil {
					log.Printf("Trying sealedSenderDecrypt")
					var err error
					result, err = sealedSenderDecrypt(envelope, device, ctx)
					if err != nil {
						log.Printf("sealedSenderDecrypt error: %v", err)
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
					log.Printf("prekeyDecrypt error: %v", err)
				} else {
					log.Printf("-----> PreKey decrypt result -  address: %v, data: %v", result.SenderAddress, result.Content)
					responseCode = 200
				}

			} else if *envelope.Type == signalpb.Envelope_PLAINTEXT_CONTENT {
				log.Printf("Received envelope type PLAINTEXT_CONTENT, verb: %v, path: %v", *req.Verb, *req.Path)

			} else if *envelope.Type == signalpb.Envelope_CIPHERTEXT {
				log.Printf("Received envelope type CIPHERTEXT, verb: %v, path: %v", *req.Verb, *req.Path)

			} else if *envelope.Type == signalpb.Envelope_RECEIPT {
				log.Printf("Received envelope type RECEIPT, verb: %v, path: %v", *req.Verb, *req.Path)

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

				if content.DataMessage != nil {

					// If there's a profile key, save it
					if content.DataMessage.ProfileKey != nil {
						log.Printf("-----> profile key: %v", content.DataMessage.ProfileKey)
						theirUuid, err := result.SenderAddress.Name()
						if err != nil {
							log.Printf("Name error: %v", err)
							return nil, err
						} else {
							log.Printf("-----> their uuid: %v", theirUuid)
						}
						profileKey := libsignalgo.ProfileKey(content.DataMessage.ProfileKey)
						err = device.ProfileKeyStore.StoreProfileKey(theirUuid, profileKey, ctx)
						if err != nil {
							log.Printf("StoreProfileKey error: %v", err)
							return nil, err
						}
					}

					// Send a friendly reply
					if device.IncomingSignalMessageHandler != nil && content.DataMessage.Body != nil {
						theirUuid, _ := result.SenderAddress.Name()
						device.IncomingSignalMessageHandler(*content.DataMessage.Body, theirUuid)
					} else {
						// TODO: don't echo outside of debug mode
						if content.DataMessage.Body != nil {
							reply := &signalpb.Content{
								DataMessage: &signalpb.DataMessage{
									Body: proto.String("Hello from signalmeow: " + *content.DataMessage.Body),
								},
							}
							theirUuid, _ := result.SenderAddress.Name()
							log.Printf("-----> sending reply to: %v", theirUuid)
							log.Printf("-----> reply: %v", reply)
							err = sendMessage(ctx, device, theirUuid, reply, 0)
						}
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

func sealedSenderDecrypt(envelope *signalpb.Envelope, device *store.Device, ctx context.Context) (*DecryptionResult, error) {
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

func prekeyDecrypt(sender libsignalgo.Address, encryptedContent []byte, device *store.Device, ctx context.Context) (*DecryptionResult, error) {
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
