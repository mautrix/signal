package signalmeow

import (
	"context"
	crand "crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"math/big"
	mrand "math/rand"
	"net/url"
	"time"

	"go.mau.fi/mautrix-signal/pkg/libsignalgo"
	signalpb "go.mau.fi/mautrix-signal/pkg/signalmeow/protobuf"
	"go.mau.fi/mautrix-signal/pkg/signalmeow/store"
	"go.mau.fi/mautrix-signal/pkg/signalmeow/types"
	"go.mau.fi/mautrix-signal/pkg/signalmeow/web"
	"go.mau.fi/mautrix-signal/pkg/signalmeow/wspb"
	"google.golang.org/protobuf/proto"
	"nhooyr.io/websocket"
)

type ConfirmDeviceResponse struct {
	uuid     string
	pni      string
	deviceId int
}

type ProvisioningData struct {
	AciIdentityKeyPair *libsignalgo.IdentityKeyPair
	PniIdentityKeyPair *libsignalgo.IdentityKeyPair
	RegistrationId     int
	PniRegistrationId  int
	AciUuid            string
	PniUuid            string
	DeviceId           int
	Number             string
	Password           string
}

type ProvisioningState int

const (
	StateProvisioningError ProvisioningState = iota
	StateProvisioningURLReceived
	StateProvisioningDataReceived
	StateProvisioningPreKeysRegistered
)

// Enum for the provisioningUrl, ProvisioningMessage, and error
type ProvisioningResponse struct {
	State            ProvisioningState
	ProvisioningUrl  string
	ProvisioningData *types.DeviceData
	Err              error
}

func PerformProvisioning(deviceStore store.DeviceStore) chan ProvisioningResponse {
	c := make(chan ProvisioningResponse)
	go func() {
		defer close(c)

		ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
		defer cancel()
		ws, err := openProvisioningWebsocket(ctx)
		if err != nil {
			log.Printf("openProvisioningWebsocket error: %v", err)
			c <- ProvisioningResponse{State: StateProvisioningError, Err: err}
			return
		}
		defer ws.Close(websocket.StatusInternalError, "Websocket StatusInternalError")
		provisioningCipher := NewProvisioningCipher()

		provisioningUrl, err := startProvisioning(ctx, ws, provisioningCipher)
		c <- ProvisioningResponse{State: StateProvisioningURLReceived, ProvisioningUrl: provisioningUrl, Err: err}

		provisioningMessage, _ := continueProvisioning(ctx, ws, provisioningCipher)
		ws.Close(websocket.StatusNormalClosure, "")

		aciPublicKey, _ := libsignalgo.DeserializePublicKey(provisioningMessage.GetAciIdentityKeyPublic())
		aciPrivateKey, _ := libsignalgo.DeserializePrivateKey(provisioningMessage.GetAciIdentityKeyPrivate())
		aciIdentityKeyPair, _ := libsignalgo.NewIdentityKeyPair(aciPublicKey, aciPrivateKey)
		pniPublicKey, _ := libsignalgo.DeserializePublicKey(provisioningMessage.GetPniIdentityKeyPublic())
		pniPrivateKey, _ := libsignalgo.DeserializePrivateKey(provisioningMessage.GetPniIdentityKeyPrivate())
		pniIdentityKeyPair, _ := libsignalgo.NewIdentityKeyPair(pniPublicKey, pniPrivateKey)

		// log provisioningMessage
		log.Printf("provisioningMessage: %v", provisioningMessage)
		// log aciPrivateKey
		log.Printf("provisioningMessage.GetAciIdentityKeyPrivate(): %v", provisioningMessage.GetAciIdentityKeyPrivate())
		// log aciPublicKey
		log.Printf("provisioningMessage.GetAciIdentityKeyPublic(): %v", provisioningMessage.GetAciIdentityKeyPublic())

		privateKey, _ := libsignalgo.DeserializePrivateKey(provisioningMessage.GetAciIdentityKeyPrivate())
		publicKey, _ := privateKey.GetPublicKey()
		privateBytes, _ := privateKey.Serialize()
		publicBytes, _ := publicKey.Serialize()
		aciBytes, _ := aciIdentityKeyPair.Serialize()
		log.Printf("privateKeyBytes: %v", privateBytes)
		log.Printf("publicKeyBytes: %v", publicBytes)
		log.Printf("aciIdentityKeyPairBytes: %v", aciBytes)

		username := *provisioningMessage.Number
		password, _ := generateRandomPassword(22)
		code := provisioningMessage.ProvisioningCode
		registrationId := mrand.Intn(16383) + 1
		pniRegistrationId := mrand.Intn(16383) + 1
		deviceResponse, err := confirmDevice(username, password, *code, registrationId, pniRegistrationId)
		if err != nil {
			log.Printf("confirmDevice error: %v", err)
			c <- ProvisioningResponse{State: StateProvisioningError, Err: err}
			return
		}

		deviceId := 1
		if deviceResponse.deviceId != 0 {
			deviceId = deviceResponse.deviceId
		}

		data := &types.DeviceData{
			AciIdentityKeyPair: aciIdentityKeyPair,
			PniIdentityKeyPair: pniIdentityKeyPair,
			RegistrationId:     registrationId,
			PniRegistrationId:  pniRegistrationId,
			AciUuid:            deviceResponse.uuid,
			PniUuid:            deviceResponse.pni,
			DeviceId:           deviceId,
			Number:             *provisioningMessage.Number,
			Password:           password,
		}

		// Store the provisioning data
		err = deviceStore.PutDevice(data)
		if err != nil {
			log.Printf("error storing new device: %v", err)
			c <- ProvisioningResponse{State: StateProvisioningError, Err: err}
			return
		}
		newDevice, err := deviceStore.DeviceByAci(data.AciUuid)
		if err != nil {
			log.Printf("error retrieving new device: %v", err)
			c <- ProvisioningResponse{State: StateProvisioningError, Err: err}
			return
		}

		// Store identity keys?
		device, err := deviceStore.DeviceByAci(data.AciUuid)
		if err != nil {
			log.Printf("error retrieving new device: %v", err)
			c <- ProvisioningResponse{State: StateProvisioningError, Err: err}
			return
		}
		address, err := libsignalgo.NewAddress(device.Data.AciUuid, uint(device.Data.DeviceId))
		err = device.IdentityStore.SaveIdentityKey(address, device.Data.AciIdentityKeyPair.GetIdentityKey(), ctx)
		if err != nil {
			log.Printf("error saving identity key: %v", err)
			c <- ProvisioningResponse{State: StateProvisioningError, Err: err}
			return
		}

		// Return the provisioning data
		c <- ProvisioningResponse{State: StateProvisioningDataReceived, ProvisioningData: data}

		// Generate, store, and register prekeys
		err = GenerateAndRegisterPreKeys(newDevice, types.UUID_KIND_ACI)
		err = GenerateAndRegisterPreKeys(newDevice, types.UUID_KIND_PNI)

		if err != nil {
			log.Printf("error generating and registering prekeys: %v", err)
			c <- ProvisioningResponse{State: StateProvisioningError, Err: err}
			return
		}

		c <- ProvisioningResponse{State: StateProvisioningPreKeysRegistered}

		log.Printf("my identity key: %v", newDevice.Data.AciIdentityKeyPair.GetIdentityKey())
	}()
	return c
}

func openProvisioningWebsocket(ctx context.Context) (*websocket.Conn, error) {
	ws, resp, err := web.OpenWebsocket(ctx, web.WebsocketProvisioningPath)
	if err != nil {
		log.Printf("openWebsocket error, resp: %v", resp)
		return nil, err
	}
	return ws, nil
}

// Returns the provisioningUrl and an error
func startProvisioning(ctx context.Context, ws *websocket.Conn, provisioningCipher *ProvisioningCipher) (string, error) {
	pubKey := provisioningCipher.GetPublicKey()

	provisioningUrl := ""

	msg := &signalpb.WebSocketMessage{}
	err := wspb.Read(ctx, ws, msg)
	if err != nil {
		return "", err
	}

	// Ensure the message is a request and has a valid verb and path
	if *msg.Type == signalpb.WebSocketMessage_REQUEST &&
		*msg.Request.Verb == "PUT" &&
		*msg.Request.Path == "/v1/address" {

		// Decode provisioning UUID
		provisioningUuid := &signalpb.ProvisioningUuid{}
		err = proto.Unmarshal(msg.Request.Body, provisioningUuid)

		// Create provisioning URL
		bytesKey, _ := pubKey.Serialize()
		base64Key := base64.StdEncoding.EncodeToString(bytesKey)
		uuid := url.QueryEscape(*provisioningUuid.Uuid)
		pubKey := url.QueryEscape(base64Key)
		provisioningUrl = "sgnl://linkdevice?uuid=" + uuid + "&pub_key=" + pubKey
		log.Printf("provisioningUrl: %s", provisioningUrl)

		// Create and send response
		response := web.CreateWSResponse(*msg.Request.Id, 200)
		err = wspb.Write(ctx, ws, response)
		if err != nil {
			return "", err
		}
	}
	return provisioningUrl, nil
}

func continueProvisioning(ctx context.Context, ws *websocket.Conn, provisioningCipher *ProvisioningCipher) (*signalpb.ProvisionMessage, error) {
	envelope := &signalpb.ProvisionEnvelope{}
	msg := &signalpb.WebSocketMessage{}
	err := wspb.Read(ctx, ws, msg)
	if err != nil {
		return nil, err
	}

	// Wait for provisioning message in a request, then send a response
	if *msg.Type == signalpb.WebSocketMessage_REQUEST &&
		*msg.Request.Verb == "PUT" &&
		*msg.Request.Path == "/v1/message" {

		err = proto.Unmarshal(msg.Request.Body, envelope)
		if err != nil {
			return nil, err
		}

		response := web.CreateWSResponse(*msg.Request.Id, 200)
		err = wspb.Write(ctx, ws, response)
		if err != nil {
			return nil, err
		}
	} else {
		return nil, errors.New("invalid provisioning message")
	}
	provisioningMessage := provisioningCipher.Decrypt(envelope)
	return provisioningMessage, nil
}

func confirmDevice(username string, password string, code string, registrationId int, pniRegistrationId int) (*ConfirmDeviceResponse, error) {
	ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
	defer cancel()
	ws, resp, err := web.OpenWebsocket(ctx, web.WebsocketPath)
	defer ws.Close(websocket.StatusInternalError, "Websocket StatusInternalError")

	data := map[string]interface{}{
		"registrationId":    registrationId,
		"pniRegistrationId": pniRegistrationId,
		"supportsSms":       false,
		"fetchesMessages":   true,
		"capabilities": map[string]interface{}{
			"gv2-3":             true,
			"announcementGroup": true,
			"giftBadges":        true,
			"senderKey":         true,
			"changeNumber":      true,
			"stories":           true,
			"pni":               true,
		},
	}
	// TODO: Set deviceName with "Signal Bridge" or something properly encrypted

	jsonBytes, err := json.Marshal(data)
	if err != nil {
		log.Printf("failed to marshal json: %v", resp)
		return nil, err
	}

	// Create and send request
	requestId := uint64(1)
	request := web.CreateWSRequest("PUT", "/v1/devices/"+code, jsonBytes, &requestId, &username, &password)
	msg_type := signalpb.WebSocketMessage_REQUEST
	message := &signalpb.WebSocketMessage{
		Type:    &msg_type,
		Request: request,
	}
	err = wspb.Write(ctx, ws, message)
	if err != nil {
		log.Printf("failed on write %v", resp)
		return nil, err
	}

	receivedMsg := &signalpb.WebSocketMessage{}
	err = wspb.Read(ctx, ws, receivedMsg)
	if err != nil {
		log.Printf("failed to read after devices call: %v", resp)
		return nil, err
	}

	// Decode body into JSON
	var body map[string]interface{}
	err = json.Unmarshal(receivedMsg.Response.Body, &body)
	if err != nil {
		log.Printf("failed to unmarshal json: %v", resp)
		return nil, err
	}
	status := int(*receivedMsg.Response.Status)
	if status < 200 || status >= 300 {
		log.Printf("problem with devices response - status: %d, message: %s", status, *receivedMsg.Response.Message)
		return nil, fmt.Errorf("problem with devices response - status: %d, message: %s", status, *receivedMsg.Response.Message)
	}

	// Put body into struct
	deviceResp := ConfirmDeviceResponse{}
	uuid, ok := body["uuid"].(string)
	if ok {
		deviceResp.uuid = uuid
	}
	pni, ok := body[types.UUID_KIND_PNI].(string)
	if ok {
		deviceResp.pni = pni
	}
	deviceId, ok := body["deviceId"].(float64)
	if ok {
		deviceResp.deviceId = int(deviceId)
	}

	return &deviceResp, nil
}

func generateRandomPassword(length int) (string, error) {
	if length < 1 {
		return "", fmt.Errorf("password length must be at least 1")
	}

	const charset = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"
	var password []byte
	for i := 0; i < length; i++ {
		index, err := crand.Int(crand.Reader, big.NewInt(int64(len(charset))))
		if err != nil {
			return "", fmt.Errorf("error generating random index: %v", err)
		}
		password = append(password, charset[index.Int64()])
	}

	return string(password), nil
}
