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
	crand "crypto/rand"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"math/big"
	mrand "math/rand"
	"net/http"
	"net/url"
	"time"

	"github.com/google/uuid"
	"google.golang.org/protobuf/proto"
	"nhooyr.io/websocket"

	"go.mau.fi/mautrix-signal/pkg/libsignalgo"
	signalpb "go.mau.fi/mautrix-signal/pkg/signalmeow/protobuf"
	"go.mau.fi/mautrix-signal/pkg/signalmeow/web"
	"go.mau.fi/mautrix-signal/pkg/signalmeow/wspb"
)

type ConfirmDeviceResponse struct {
	ACI      uuid.UUID `json:"uuid"`
	PNI      uuid.UUID `json:"pni,omitempty"`
	DeviceID int       `json:"deviceId"`
}

type ProvisioningState int

const (
	StateProvisioningError ProvisioningState = iota
	StateProvisioningURLReceived
	StateProvisioningDataReceived
	StateProvisioningPreKeysRegistered
)

func (s ProvisioningState) String() string {
	switch s {
	case StateProvisioningError:
		return "StateProvisioningError"
	case StateProvisioningURLReceived:
		return "StateProvisioningURLReceived"
	case StateProvisioningDataReceived:
		return "StateProvisioningDataReceived"
	case StateProvisioningPreKeysRegistered:
		return "StateProvisioningPreKeysRegistered"
	default:
		return fmt.Sprintf("ProvisioningState(%d)", s)
	}
}

// Enum for the provisioningUrl, ProvisioningMessage, and error
type ProvisioningResponse struct {
	State            ProvisioningState
	ProvisioningURL  string
	ProvisioningData *DeviceData
	Err              error
}

func PerformProvisioning(incomingCtx context.Context, deviceStore DeviceStore, deviceName string) chan ProvisioningResponse {
	c := make(chan ProvisioningResponse)
	go func() {
		defer close(c)

		ctx, cancel := context.WithTimeout(incomingCtx, 2*time.Minute)
		defer cancel()
		ws, resp, err := web.OpenWebsocket(ctx, web.WebsocketProvisioningPath)
		if err != nil {
			zlog.Err(err).Any("resp", resp).Msg("error opening provisioning websocket")
			c <- ProvisioningResponse{State: StateProvisioningError, Err: err}
			return
		}
		defer ws.Close(websocket.StatusInternalError, "Websocket StatusInternalError")
		provisioningCipher := NewProvisioningCipher()

		provisioningUrl, err := startProvisioning(ctx, ws, provisioningCipher)
		if err != nil {
			zlog.Err(err).Msg("startProvisioning error")
			c <- ProvisioningResponse{State: StateProvisioningError, Err: err}
			return
		}
		c <- ProvisioningResponse{State: StateProvisioningURLReceived, ProvisioningURL: provisioningUrl, Err: err}

		provisioningMessage, err := continueProvisioning(ctx, ws, provisioningCipher)
		if err != nil {
			zlog.Err(err).Msg("continueProvisioning error")
			c <- ProvisioningResponse{State: StateProvisioningError, Err: err}
			return
		}
		ws.Close(websocket.StatusNormalClosure, "")

		aciPublicKey, _ := libsignalgo.DeserializePublicKey(provisioningMessage.GetAciIdentityKeyPublic())
		aciPrivateKey, _ := libsignalgo.DeserializePrivateKey(provisioningMessage.GetAciIdentityKeyPrivate())
		aciIdentityKeyPair, _ := libsignalgo.NewIdentityKeyPair(aciPublicKey, aciPrivateKey)
		pniPublicKey, _ := libsignalgo.DeserializePublicKey(provisioningMessage.GetPniIdentityKeyPublic())
		pniPrivateKey, _ := libsignalgo.DeserializePrivateKey(provisioningMessage.GetPniIdentityKeyPrivate())
		pniIdentityKeyPair, _ := libsignalgo.NewIdentityKeyPair(pniPublicKey, pniPrivateKey)
		profileKey := libsignalgo.ProfileKey(provisioningMessage.GetProfileKey())

		username := *provisioningMessage.Number
		password, _ := generateRandomPassword(22)
		code := provisioningMessage.ProvisioningCode
		registrationId := mrand.Intn(16383) + 1
		pniRegistrationId := mrand.Intn(16383) + 1
		aciSignedPreKey := GenerateSignedPreKey(1, UUIDKindACI, aciIdentityKeyPair)
		pniSignedPreKey := GenerateSignedPreKey(2, UUIDKindPNI, pniIdentityKeyPair)
		aciPQLastResortPreKeys := GenerateKyberPreKeys(1, 1, UUIDKindACI, aciIdentityKeyPair)
		pniPQLastResortPreKeys := GenerateKyberPreKeys(1, 1, UUIDKindPNI, pniIdentityKeyPair)
		aciPQLastResortPreKey := aciPQLastResortPreKeys[0]
		pniPQLastResortPreKey := pniPQLastResortPreKeys[0]
		deviceResponse, err := confirmDevice(
			ctx,
			username,
			password,
			*code,
			registrationId,
			pniRegistrationId,
			aciSignedPreKey,
			pniSignedPreKey,
			aciPQLastResortPreKey,
			pniPQLastResortPreKey,
			aciIdentityKeyPair,
			deviceName,
		)
		if err != nil {
			zlog.Err(err).Msg("confirmDevice error")
			c <- ProvisioningResponse{State: StateProvisioningError, Err: err}
			return
		}

		deviceId := 1
		if deviceResponse.DeviceID != 0 {
			deviceId = deviceResponse.DeviceID
		}

		data := &DeviceData{
			ACIIdentityKeyPair: aciIdentityKeyPair,
			PNIIdentityKeyPair: pniIdentityKeyPair,
			RegistrationID:     registrationId,
			PNIRegistrationID:  pniRegistrationId,
			ACI:                deviceResponse.ACI,
			PNI:                deviceResponse.PNI,
			DeviceID:           deviceId,
			Number:             *provisioningMessage.Number,
			Password:           password,
		}

		// Store the provisioning data
		err = deviceStore.PutDevice(ctx, data)
		if err != nil {
			zlog.Err(err).Msg("error storing new device")
			c <- ProvisioningResponse{State: StateProvisioningError, Err: err}
			return
		}

		device, err := deviceStore.DeviceByACI(ctx, data.ACI)
		if err != nil {
			zlog.Err(err).Msg("error retrieving new device")
			c <- ProvisioningResponse{State: StateProvisioningError, Err: err}
			return
		}

		// In case this is an existing device, we gotta clear out keys
		device.ClearDeviceKeys(ctx)

		// Store identity keys?
		address, err := libsignalgo.NewUUIDAddress(device.Data.ACI, uint(device.Data.DeviceID))
		_, err = device.IdentityStore.SaveIdentityKey(ctx, address, device.Data.ACIIdentityKeyPair.GetIdentityKey())
		if err != nil {
			zlog.Err(err).Msg("error saving identity key")
			c <- ProvisioningResponse{State: StateProvisioningError, Err: err}
			return
		}

		// Store signed prekeys (now that we have a device)
		StoreSignedPreKey(ctx, device, aciSignedPreKey, UUIDKindACI)
		StoreSignedPreKey(ctx, device, pniSignedPreKey, UUIDKindPNI)
		StoreKyberLastResortPreKey(ctx, device, aciPQLastResortPreKey, UUIDKindACI)
		StoreKyberLastResortPreKey(ctx, device, pniPQLastResortPreKey, UUIDKindPNI)

		// Store our profile key
		err = device.ProfileKeyStore.StoreProfileKey(ctx, data.ACI, profileKey)
		if err != nil {
			zlog.Err(err).Msg("error storing profile key")
			c <- ProvisioningResponse{State: StateProvisioningError, Err: err}
			return
		}

		// Return the provisioning data
		c <- ProvisioningResponse{State: StateProvisioningDataReceived, ProvisioningData: data}

		// Generate, store, and register prekeys
		err = GenerateAndRegisterPreKeys(ctx, device, UUIDKindACI)
		err = GenerateAndRegisterPreKeys(ctx, device, UUIDKindPNI)

		if err != nil {
			zlog.Err(err).Msg("error generating and registering prekeys")
			c <- ProvisioningResponse{State: StateProvisioningError, Err: err}
			return
		}

		c <- ProvisioningResponse{State: StateProvisioningPreKeysRegistered}
	}()
	return c
}

// Returns the provisioningUrl and an error
func startProvisioning(ctx context.Context, ws *websocket.Conn, provisioningCipher *ProvisioningCipher) (string, error) {
	pubKey := provisioningCipher.GetPublicKey()

	provisioningUrl := ""

	msg := &signalpb.WebSocketMessage{}
	err := wspb.Read(ctx, ws, msg)
	if err != nil {
		zlog.Err(err).Msg("error reading websocket message")
		return "", err
	}

	// Ensure the message is a request and has a valid verb and path
	if *msg.Type == signalpb.WebSocketMessage_REQUEST &&
		*msg.Request.Verb == http.MethodPut &&
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

		// Create and send response
		response := web.CreateWSResponse(*msg.Request.Id, 200)
		err = wspb.Write(ctx, ws, response)
		if err != nil {
			zlog.Err(err).Msg("error writing websocket message")
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
		zlog.Err(err).Msg("error reading websocket message")
		return nil, err
	}

	// Wait for provisioning message in a request, then send a response
	if *msg.Type == signalpb.WebSocketMessage_REQUEST &&
		*msg.Request.Verb == http.MethodPut &&
		*msg.Request.Path == "/v1/message" {

		err = proto.Unmarshal(msg.Request.Body, envelope)
		if err != nil {
			return nil, err
		}

		response := web.CreateWSResponse(*msg.Request.Id, 200)
		err = wspb.Write(ctx, ws, response)
		if err != nil {
			zlog.Err(err).Msg("error writing websocket message")
			return nil, err
		}
	} else {
		err = fmt.Errorf("invalid provisioning message, type: %v, verb: %v, path: %v", *msg.Type, *msg.Request.Verb, *msg.Request.Path)
		zlog.Err(err).Msg("problem reading websocket message")
		return nil, err
	}
	provisioningMessage, err := provisioningCipher.Decrypt(envelope)
	return provisioningMessage, err
}

func confirmDevice(
	ctx context.Context,
	username string,
	password string,
	code string,
	registrationId int,
	pniRegistrationId int,
	aciSignedPreKey *libsignalgo.SignedPreKeyRecord,
	pniSignedPreKey *libsignalgo.SignedPreKeyRecord,
	aciPQLastResortPreKey *libsignalgo.KyberPreKeyRecord,
	pniPQLastResortPreKey *libsignalgo.KyberPreKeyRecord,
	aciIdentityKeyPair *libsignalgo.IdentityKeyPair,
	deviceName string,
) (*ConfirmDeviceResponse, error) {
	encryptedDeviceName, err := EncryptDeviceName(deviceName, aciIdentityKeyPair.GetPublicKey())
	if err != nil {
		return nil, fmt.Errorf("failed to encrypt device name: %w", err)
	}

	ws, resp, err := web.OpenWebsocket(ctx, web.WebsocketPath)
	if err != nil {
		zlog.Err(err).Any("resp", resp).Msg("error opening websocket")
		return nil, err
	}
	defer ws.Close(websocket.StatusInternalError, "Websocket StatusInternalError")

	aciSignedPreKeyJson := SignedPreKeyToJSON(aciSignedPreKey)
	pniSignedPreKeyJson := SignedPreKeyToJSON(pniSignedPreKey)

	aciPQLastResortPreKeyJson := KyberPreKeyToJSON(aciPQLastResortPreKey)
	pniPQLastResortPreKeyJson := KyberPreKeyToJSON(pniPQLastResortPreKey)

	data := map[string]interface{}{
		"verificationCode": code,
		"accountAttributes": map[string]interface{}{
			"fetchesMessages":   true,
			"name":              encryptedDeviceName,
			"registrationId":    registrationId,
			"pniRegistrationId": pniRegistrationId,
			"capabilities": map[string]interface{}{
				"pni": true,
			},
		},
		"aciSignedPreKey":       aciSignedPreKeyJson,
		"pniSignedPreKey":       pniSignedPreKeyJson,
		"aciPqLastResortPreKey": aciPQLastResortPreKeyJson,
		"pniPqLastResortPreKey": pniPQLastResortPreKeyJson,
	}

	// TODO: Set deviceName with "Signal Bridge" or something properly encrypted

	jsonBytes, err := json.Marshal(data)
	if err != nil {
		zlog.Err(err).Msg("failed to marshal JSON")
		return nil, err
	}

	// Create and send request TODO: Use SignalWebsocket
	request := web.CreateWSRequest(http.MethodPut, "/v1/devices/link", jsonBytes, &username, &password)
	one := uint64(1)
	request.Id = &one
	msg_type := signalpb.WebSocketMessage_REQUEST
	message := &signalpb.WebSocketMessage{
		Type:    &msg_type,
		Request: request,
	}
	err = wspb.Write(ctx, ws, message)
	if err != nil {
		zlog.Err(err).Msg("failed on write protobuf data to websocket")
		return nil, err
	}

	receivedMsg := &signalpb.WebSocketMessage{}
	err = wspb.Read(ctx, ws, receivedMsg)
	if err != nil {
		zlog.Err(err).Msg("failed to read from websocket after devices call")
		return nil, err
	}

	status := int(*receivedMsg.Response.Status)
	if status < 200 || status >= 300 {
		err := fmt.Errorf("problem with devices response - status: %d, message: %s", status, *receivedMsg.Response.Message)
		zlog.Err(err).Msg("non-200 status code from devices response")
		return nil, err
	}

	// unmarshal JSON response into ConfirmDeviceResponse
	deviceResp := ConfirmDeviceResponse{}
	err = json.Unmarshal(receivedMsg.Response.Body, &deviceResp)
	if err != nil {
		zlog.Err(err).Msg("failed to unmarshal JSON")
		return nil, err
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
