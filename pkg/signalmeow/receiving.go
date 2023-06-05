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
	return d.Connection.ConnectAuthedWS(ctx, d.Data, handler)
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
			log.Printf("Received an ENVELOPE! verb: %v, path: %v, type: %v", *req.Verb, *req.Path, *envelope.Type)
			if *envelope.Type == signalpb.Envelope_UNIDENTIFIED_SENDER {
				result, err := sealedSenderDecrypt(envelope, device, ctx)
				if err != nil {
					log.Printf("sealedSenderDecrypt error: %v", err)
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
							err = device.ProfileKeyStore.StoreProfileKey(theirUuid, content.DataMessage.ProfileKey, ctx)
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
			} else if *envelope.Type == signalpb.Envelope_PREKEY_BUNDLE {
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
			}
		} else if *req.Verb == "PUT" && *req.Path == "/api/v1/queue/empty" {
			log.Printf("Received queue empty. verb: %v, path: %v", *req.Verb, *req.Path)
		} else {
			log.Printf("Don't know what I received: req: %v", req)
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
	/*
		address, data, err := libsignalgo.SealedSenderDecrypt(
			envelope.Content,
			serverTrustRootKey(),
			*envelope.Timestamp,
			nil, // TODO: add our e164 here?
			device.Data.AciUuid,
			uint32(device.Data.DeviceId),
			device.SessionStore,
			device.IdentityStore,
			device.PreKeyStore,
			device.SignedPreKeyStore,
			libsignalgo.NewCallbackContext(ctx),
		)
	*/

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
	data, err := libsignalgo.DecryptPreKey(
		preKeyMessage,
		sender,
		device.SessionStore,
		device.IdentityStore,
		device.PreKeyStore,
		device.SignedPreKeyStore,
		libsignalgo.NewCallbackContext(ctx),
	)

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
	return fmt.Errorf("Invalid ISO7816 padding")
}
