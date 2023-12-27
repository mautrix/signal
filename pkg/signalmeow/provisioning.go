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

	"google.golang.org/protobuf/proto"
	"nhooyr.io/websocket"

	"go.mau.fi/mautrix-signal/pkg/libsignalgo"
	signalpb "go.mau.fi/mautrix-signal/pkg/signalmeow/protobuf"
	"go.mau.fi/mautrix-signal/pkg/signalmeow/web"
	"go.mau.fi/mautrix-signal/pkg/signalmeow/wspb"
)

type ConfirmDeviceResponse struct {
	Uuid     string `json:"uuid"`
	Pni      string `json:"pni,omitempty"`
	DeviceId int    `json:"deviceId"`
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
	ProvisioningData *DeviceData
	Err              error
}

func PerformProvisioning(incomingCtx context.Context, deviceStore DeviceStore, deviceName string) chan ProvisioningResponse {
	c := make(chan ProvisioningResponse)
	go func() {
		defer close(c)

		ctx, cancel := context.WithTimeout(incomingCtx, 2*time.Minute)
		defer cancel()
		ws, err := openProvisioningWebsocket(ctx)
		if err != nil {
			zlog.Err(err).Msg("openProvisioningWebsocket error")
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
		c <- ProvisioningResponse{State: StateProvisioningURLReceived, ProvisioningUrl: provisioningUrl, Err: err}

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
		aciSignedPreKey := GenerateSignedPreKey(1, UUID_KIND_ACI, aciIdentityKeyPair)
		pniSignedPreKey := GenerateSignedPreKey(2, UUID_KIND_PNI, pniIdentityKeyPair)
		aciPQLastResortPreKeys := GenerateKyberPreKeys(1, 1, UUID_KIND_ACI, aciIdentityKeyPair)
		pniPQLastResortPreKeys := GenerateKyberPreKeys(1, 1, UUID_KIND_PNI, pniIdentityKeyPair)
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
		if deviceResponse.DeviceId != 0 {
			deviceId = deviceResponse.DeviceId
		}

		data := &DeviceData{
			AciIdentityKeyPair: aciIdentityKeyPair,
			PniIdentityKeyPair: pniIdentityKeyPair,
			RegistrationId:     registrationId,
			PniRegistrationId:  pniRegistrationId,
			AciUuid:            deviceResponse.Uuid,
			PniUuid:            deviceResponse.Pni,
			DeviceId:           deviceId,
			Number:             *provisioningMessage.Number,
			Password:           password,
		}

		// Store the provisioning data
		err = deviceStore.PutDevice(data)
		if err != nil {
			zlog.Err(err).Msg("error storing new device")
			c <- ProvisioningResponse{State: StateProvisioningError, Err: err}
			return
		}

		device, err := deviceStore.DeviceByAci(data.AciUuid)
		if err != nil {
			zlog.Err(err).Msg("error retrieving new device")
			c <- ProvisioningResponse{State: StateProvisioningError, Err: err}
			return
		}

		// In case this is an existing device, we gotta clear out keys
		device.ClearDeviceKeys()

		// Store identity keys?
		address, err := libsignalgo.NewAddress(device.Data.AciUuid, uint(device.Data.DeviceId))
		_, err = device.IdentityStore.SaveIdentityKey(address, device.Data.AciIdentityKeyPair.GetIdentityKey(), ctx)
		if err != nil {
			zlog.Err(err).Msg("error saving identity key")
			c <- ProvisioningResponse{State: StateProvisioningError, Err: err}
			return
		}

		// Store signed prekeys (now that we have a device)
		StoreSignedPreKey(device, aciSignedPreKey, UUID_KIND_ACI)
		StoreSignedPreKey(device, pniSignedPreKey, UUID_KIND_PNI)
		StoreKyberLastResortPreKey(device, aciPQLastResortPreKey, UUID_KIND_ACI)
		StoreKyberLastResortPreKey(device, pniPQLastResortPreKey, UUID_KIND_PNI)

		// Store our profile key
		err = device.ProfileKeyStore.StoreProfileKey(data.AciUuid, profileKey, ctx)
		if err != nil {
			zlog.Err(err).Msg("error storing profile key")
			c <- ProvisioningResponse{State: StateProvisioningError, Err: err}
			return
		}

		// Return the provisioning data
		c <- ProvisioningResponse{State: StateProvisioningDataReceived, ProvisioningData: data}

		// Generate, store, and register prekeys
		err = GenerateAndRegisterPreKeys(device, UUID_KIND_ACI)
		err = GenerateAndRegisterPreKeys(device, UUID_KIND_PNI)

		if err != nil {
			zlog.Err(err).Msg("error generating and registering prekeys")
			c <- ProvisioningResponse{State: StateProvisioningError, Err: err}
			return
		}

		c <- ProvisioningResponse{State: StateProvisioningPreKeysRegistered}
	}()
	return c
}

func openProvisioningWebsocket(ctx context.Context) (*websocket.Conn, error) {
	ws, resp, err := web.OpenWebsocket(ctx, web.WebsocketProvisioningPath)
	if err != nil {
		zlog.Err(err).Msgf("openWebsocket error, resp : %v", resp)
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
		zlog.Err(err).Msgf("openWebsocket error, resp : %v", resp)
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
		zlog.Err(err).Msgf("failed to marshal json: %v", resp)
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
		zlog.Err(err).Msgf("failed on write %v", resp)
		return nil, err
	}

	receivedMsg := &signalpb.WebSocketMessage{}
	err = wspb.Read(ctx, ws, receivedMsg)
	if err != nil {
		zlog.Err(err).Msgf("failed to read after devices call: %v", resp)
		return nil, err
	}

	status := int(*receivedMsg.Response.Status)
	if status < 200 || status >= 300 {
		err := fmt.Errorf("problem with devices response - status: %d, message: %s", status, *receivedMsg.Response.Message)
		zlog.Err(err).Msg("")
		return nil, err
	}

	// unmarshal JSON response into ConfirmDeviceResponse
	deviceResp := ConfirmDeviceResponse{}
	err = json.Unmarshal(receivedMsg.Response.Body, &deviceResp)
	if err != nil {
		zlog.Err(err).Msgf("failed to unmarshal json: %v", receivedMsg.Response.Body)
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
