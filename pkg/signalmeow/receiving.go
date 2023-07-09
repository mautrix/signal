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
		responseCode := 200
		if *req.Verb == "PUT" && *req.Path == "/api/v1/message" {
			envelope := &signalpb.Envelope{}
			err := proto.Unmarshal(req.Body, envelope)
			if err != nil {
				log.Printf("Unmarshal error: %v", err)
				return nil, err
			}
			if *envelope.Type == signalpb.Envelope_UNIDENTIFIED_SENDER {
				log.Printf("&&&&&&& Received envelope type UNIDENTIFIED_SENDER, verb: %v, path: %v &&&&&&&", *req.Verb, *req.Path)
				ctx := context.Background()
				usmc, err := libsignalgo.SealedSenderDecryptToUSMC(
					envelope.Content,
					device.IdentityStore,
					libsignalgo.NewCallbackContext(ctx),
				)
				if err != nil {
					log.Printf("SealedSenderDecryptToUSMC error: %v", err)
					log.Printf("ctx error: %v", ctx.Err())
				}

				messageType, err := usmc.GetMessageType()
				if err != nil {
					log.Printf("GetMessageType error: %v", err)
				}
				if messageType == libsignalgo.CiphertextMessageTypeSenderKey {
					log.Printf("******** messageType is CiphertextMessageTypeSenderKey ********")
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

					decryptedText, err := libsignalgo.GroupDecrypt(
						envelope.Content,
						senderAddress,
						device.SenderKeyStore,
						libsignalgo.NewCallbackContext(ctx),
					)
					if err != nil {
						log.Printf("GroupDecrypt error: %v", err)
					}
					log.Printf("******** ===== GROUP decryptedText: %v ===== ********", decryptedText)

				} else if messageType == libsignalgo.CiphertextMessageTypePreKey {
					log.Printf("******** messageType is CiphertextMessageTypePreKey ********")
				} else if messageType == libsignalgo.CiphertextMessageTypeWhisper {
					log.Printf("******** messageType is CiphertextMessageTypeWhisper ********")
				} else if messageType == libsignalgo.CiphertextMessageTypePlaintext {
					log.Printf("******** messageType is CiphertextMessageTypePlaintext ********")
				} else {
					log.Printf("******** messageType is unknown ********")
				}

				if messageType != libsignalgo.CiphertextMessageTypeSenderKey {
					result, err := sealedSenderDecrypt(envelope, device, ctx)
					if err != nil {
						log.Printf("sealedSenderDecrypt error: %v", err)
						log.Printf("ctx error: %v", ctx.Err())
						responseCode = 400
					} else {
						log.Printf("-----> ss decrypt result - address: %v, data: %v", result.Address, result.Data)
						//extract content from data
						content := &signalpb.Content{}
						err = proto.Unmarshal(result.Data, content)
						if err != nil {
							log.Printf("Unmarshal error: %v", err)
							return nil, err
						}
						log.Printf("-----> content: %v", content)
						if content.DataMessage != nil {
							if content.DataMessage.ProfileKey != nil {
								log.Printf("-----> profile key: %v", content.DataMessage.ProfileKey)
								theirUuid, err := result.Address.Name()
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
								theirUuid, _ := result.Address.Name()
								device.IncomingSignalMessageHandler(*content.DataMessage.Body, theirUuid)
							} else {
								// TODO: don't echo outside of debug mode
								if content.DataMessage.Body != nil {
									reply := &signalpb.Content{
										DataMessage: &signalpb.DataMessage{
											Body: proto.String("Hello from signalmeow: " + *content.DataMessage.Body),
										},
									}
									theirUuid, _ := result.Address.Name()
									log.Printf("-----> sending reply to: %v", theirUuid)
									log.Printf("-----> reply: %v", reply)
									err = sendMessage(ctx, device, theirUuid, reply, 0)
								}
							}
						}
					}
				}
			} else if *envelope.Type == signalpb.Envelope_PREKEY_BUNDLE {
				log.Printf("&&&&&&& Received envelope type PREKEY_BUNDLE, verb: %v, path: %v &&&&&&&", *req.Verb, *req.Path)
				result, err := prekeyDecrypt(envelope, device, ctx)
				if err != nil {
					log.Printf("prekeyDecrypt error: %v", err)
					//return
					responseCode = 400
				} else {
					log.Printf("-----> pk decrypt result -  address: %v, data: %v", result.Address, result.Data)
					//extract content from data
					//	content := &signalpb.Content{}
					//	err = proto.Unmarshal(result.Data, content)
					//	if err != nil {
					//		log.Printf("Unmarshal error: %v", err)
					//		return
					//	}
					//	log.Printf("-----> content: %v", content)
				}
			} else if *envelope.Type == signalpb.Envelope_PLAINTEXT_CONTENT {
				log.Printf("&&&&&&& Received envelope type PLAINTEXT_CONTENT, verb: %v, path: %v &&&&&&&", *req.Verb, *req.Path)
				responseCode = 400
			} else if *envelope.Type == signalpb.Envelope_CIPHERTEXT {
				log.Printf("&&&&&&& Received envelope type CIPHERTEXT, verb: %v, path: %v &&&&&&&", *req.Verb, *req.Path)
				responseCode = 400
			} else if *envelope.Type == signalpb.Envelope_RECEIPT {
				log.Printf("&&&&&&& Received envelope type RECEIPT, verb: %v, path: %v &&&&&&&", *req.Verb, *req.Path)
				responseCode = 400
			} else if *envelope.Type == signalpb.Envelope_KEY_EXCHANGE {
				log.Printf("&&&&&&& Received envelope type KEY_EXCHANGE, verb: %v, path: %v &&&&&&&", *req.Verb, *req.Path)
				responseCode = 400
			} else if *envelope.Type == signalpb.Envelope_UNKNOWN {
				log.Printf("&&&&&&& Received envelope type UNKNOWN, verb: %v, path: %v &&&&&&&", *req.Verb, *req.Path)
				responseCode = 400
			} else {
				log.Printf("&&&&&&& Received actual unknown envelope type, verb: %v, path: %v &&&&&&&", *req.Verb, *req.Path)
				responseCode = 400
			}
		} else if *req.Verb == "PUT" && *req.Path == "/api/v1/queue/empty" {
			log.Printf("Received queue empty. verb: %v, path: %v", *req.Verb, *req.Path)
		} else {
			log.Printf("######## Don't know what I received ########## req: %v", req)
			responseCode = 400
		}
		return &web.SimpleResponse{
			Status: responseCode,
		}, nil
	}
	return handler
}

type DecryptionResult struct {
	Envelope *signalpb.Envelope
	Address  *libsignalgo.Address
	Data     []byte
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
	DecryptionResult := &DecryptionResult{
		Envelope: envelope,
		Address:  address,
		Data:     msg,
	}
	return DecryptionResult, nil
}

func prekeyDecrypt(envelope *signalpb.Envelope, device *store.Device, ctx context.Context) (*DecryptionResult, error) {
	sender, err := libsignalgo.NewAddress(
		*envelope.SourceUuid,
		uint(*envelope.SourceDevice),
	)
	if err != nil {
		return nil, fmt.Errorf("NewAddress error: %v", err)
	}
	preKeyMessage, err := libsignalgo.DeserializePreKeyMessage(envelope.Content)
	if err != nil {
		return nil, fmt.Errorf("DeserializePreKeyMessage error: %v", err)
	}
	if preKeyMessage == nil {
		return nil, fmt.Errorf("preKeyMessage is nil")
	}

	data, err := libsignalgo.DecryptPreKey(
		preKeyMessage,
		sender,
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
	DecryptionResult := &DecryptionResult{
		Envelope: envelope,
		Address:  sender,
		Data:     data,
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
