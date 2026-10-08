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
	"encoding/json"
	"fmt"
	mrand "math/rand/v2"
	"net/http"
	"net/url"
	"time"

	"github.com/coder/websocket"
	"github.com/google/uuid"
	"github.com/rs/zerolog"
	"go.mau.fi/util/exerrors"
	"go.mau.fi/util/random"
	"google.golang.org/protobuf/proto"

	"go.mau.fi/mautrix-signal/pkg/libsignalgo"
	"go.mau.fi/mautrix-signal/pkg/signalmeow/protobuf/signalpb"
	"go.mau.fi/mautrix-signal/pkg/signalmeow/store"
	"go.mau.fi/mautrix-signal/pkg/signalmeow/types"
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
)

func (s ProvisioningState) String() string {
	switch s {
	case StateProvisioningError:
		return "StateProvisioningError"
	case StateProvisioningURLReceived:
		return "StateProvisioningURLReceived"
	case StateProvisioningDataReceived:
		return "StateProvisioningDataReceived"
	default:
		return fmt.Sprintf("ProvisioningState(%d)", s)
	}
}

// Enum for the provisioningUrl, ProvisioningMessage, and error
type ProvisioningResponse struct {
	State            ProvisioningState
	ProvisioningURL  string
	ProvisioningData *store.DeviceData
	Err              error
}

type DeviceLinkError struct {
	StatusCode int
	Message    string
}

func (dle DeviceLinkError) Error() string {
	return fmt.Sprintf("non-200 status code (%d) from devices response: %s", dle.StatusCode, dle.Message)
}

func PerformProvisioning(ctx context.Context, deviceStore store.DeviceStore, deviceName string, allowBackup bool) chan ProvisioningResponse {
	log := zerolog.Ctx(ctx).With().Str("action", "perform provisioning").Logger()
	c := make(chan ProvisioningResponse, 4)
	go func() {
		defer close(c)

		timeoutCtx, cancel := context.WithTimeout(ctx, 2*time.Minute)
		defer cancel()
		ws, resp, err := web.OpenWebsocket(timeoutCtx, (&url.URL{
			Scheme: "wss",
			Host:   web.APIHostname,
			Path:   web.WebsocketProvisioningPath,
		}).String())
		if err != nil {
			log.Err(err).Any("resp", resp).Msg("error opening provisioning websocket")
			c <- ProvisioningResponse{State: StateProvisioningError, Err: err}
			return
		}
		defer ws.Close(websocket.StatusInternalError, "Websocket StatusInternalError")
		provisioningCipher := NewProvisioningCipher()

		provisioningURL, err := startProvisioning(timeoutCtx, ws, provisioningCipher, allowBackup)
		if err != nil {
			log.Err(err).Msg("startProvisioning error")
			c <- ProvisioningResponse{State: StateProvisioningError, Err: err}
			return
		}
		c <- ProvisioningResponse{State: StateProvisioningURLReceived, ProvisioningURL: provisioningURL, Err: err}

		provisioningMessage, err := continueProvisioning(timeoutCtx, ws, provisioningCipher)
		if err != nil {
			log.Err(err).Msg("continueProvisioning error")
			c <- ProvisioningResponse{State: StateProvisioningError, Err: err}
			return
		}
		ws.Close(websocket.StatusNormalClosure, "")

		aciPublicKey := exerrors.Must(libsignalgo.DeserializePublicKey(provisioningMessage.GetAciIdentityKeyPublic()))
		aciPrivateKey := exerrors.Must(libsignalgo.DeserializePrivateKey(provisioningMessage.GetAciIdentityKeyPrivate()))
		aciIdentityKeyPair := exerrors.Must(libsignalgo.NewIdentityKeyPair(aciPublicKey, aciPrivateKey))
		profileKey := libsignalgo.ProfileKey(provisioningMessage.GetProfileKey())

		password := random.String(22)
		code := provisioningMessage.ProvisioningCode
		aciRegistrationID := mrand.IntN(16383) + 1
		aciSignedPreKey := GenerateSignedPreKey(1, aciIdentityKeyPair)
		aciPQLastResortPreKey := GenerateKyberPreKeys(1, 1, aciIdentityKeyPair)[0]
		var pniIdentityKeyPair *libsignalgo.IdentityKeyPair
		var pniRegistrationID int
		var pniSignedPreKey *libsignalgo.SignedPreKeyRecord
		var pniPQLastResortPreKey *libsignalgo.KyberPreKeyRecord
		var hasE164 bool
		if provisioningMessage.GetPni() != "" {
			hasE164 = true

			pniPublicKey := exerrors.Must(libsignalgo.DeserializePublicKey(provisioningMessage.GetPniIdentityKeyPublic()))
			pniPrivateKey := exerrors.Must(libsignalgo.DeserializePrivateKey(provisioningMessage.GetPniIdentityKeyPrivate()))
			pniIdentityKeyPair = exerrors.Must(libsignalgo.NewIdentityKeyPair(pniPublicKey, pniPrivateKey))

			pniRegistrationID = mrand.IntN(16383) + 1
			pniSignedPreKey = GenerateSignedPreKey(1, pniIdentityKeyPair)
			pniPQLastResortPreKey = GenerateKyberPreKeys(1, 1, pniIdentityKeyPair)[0]
		}
		deviceResponse, err := confirmDevice(
			ctx,
			provisioningMessage.GetAci(),
			password,
			*code,
			hasE164,
			aciRegistrationID,
			pniRegistrationID,
			aciSignedPreKey,
			pniSignedPreKey,
			aciPQLastResortPreKey,
			pniPQLastResortPreKey,
			aciIdentityKeyPair,
			deviceName,
		)
		if err != nil {
			log.Err(err).Msg("confirmDevice error")
			c <- ProvisioningResponse{State: StateProvisioningError, Err: err}
			return
		}

		deviceId := 1
		if deviceResponse.DeviceID != 0 {
			deviceId = deviceResponse.DeviceID
		}

		data := &store.DeviceData{
			ACIIdentityKeyPair: aciIdentityKeyPair,
			PNIIdentityKeyPair: pniIdentityKeyPair,
			ACIRegistrationID:  aciRegistrationID,
			PNIRegistrationID:  pniRegistrationID,
			ACI:                deviceResponse.ACI,
			PNI:                deviceResponse.PNI,
			DeviceID:           deviceId,
			Number:             provisioningMessage.GetNumber(),
			Password:           password,
			AccountEntropyPool: libsignalgo.AccountEntropyPool(provisioningMessage.GetAccountEntropyPool()),
			EphemeralBackupKey: libsignalgo.BytesToBackupKey(provisioningMessage.GetEphemeralBackupKey()),
			MediaRootBackupKey: libsignalgo.BytesToBackupKey(provisioningMessage.GetMediaRootBackupKey()),
			AuthCredentialSalt: provisioningMessage.GetAuthCredentialSalt(),
		}
		if provisioningMessage.GetAccountEntropyPool() != "" {
			data.MasterKey, err = libsignalgo.AccountEntropyPool(provisioningMessage.GetAccountEntropyPool()).DeriveSVRKey()
			if err != nil {
				log.Err(err).Msg("Failed to derive master key from account entropy pool")
			} else {
				log.Debug().Msg("Derived master key from account entropy pool")
			}
		} else {
			log.Warn().Msg("No account entropy pool in provisioning message")
		}

		// Store the provisioning data
		err = deviceStore.PutDevice(ctx, data)
		if err != nil {
			log.Err(err).Msg("error storing new device")
			c <- ProvisioningResponse{State: StateProvisioningError, Err: err}
			return
		}

		device, err := deviceStore.DeviceByACI(ctx, data.ACI)
		if err != nil {
			log.Err(err).Msg("error retrieving new device")
			c <- ProvisioningResponse{State: StateProvisioningError, Err: err}
			return
		}

		device.ClearDeviceKeys(ctx)

		// Store identity keys?
		_, err = device.IdentityKeyStore.SaveIdentityKey(ctx, device.ACIServiceID(), device.ACIIdentityKeyPair.GetIdentityKey())
		if err != nil {
			c <- ProvisioningResponse{
				State: StateProvisioningError,
				Err:   fmt.Errorf("error saving identity key: %w", err),
			}
			return
		}
		device.ACIPreKeyStore.StoreSignedPreKey(ctx, 1, aciSignedPreKey)
		device.ACIPreKeyStore.StoreLastResortKyberPreKey(ctx, 1, aciPQLastResortPreKey)
		if hasE164 {
			_, err = device.IdentityKeyStore.SaveIdentityKey(ctx, device.PNIServiceID(), device.PNIIdentityKeyPair.GetIdentityKey())
			if err != nil {
				c <- ProvisioningResponse{
					State: StateProvisioningError,
					Err:   fmt.Errorf("error saving identity key: %w", err),
				}
				return
			}
			device.PNIPreKeyStore.StoreSignedPreKey(ctx, 1, pniSignedPreKey)
			device.PNIPreKeyStore.StoreLastResortKyberPreKey(ctx, 1, pniPQLastResortPreKey)
		}

		_, err = device.RecipientStore.LoadAndUpdateRecipient(ctx, data.ACI, data.PNI, func(recipient *types.Recipient) (bool, error) {
			recipient.E164 = data.Number
			recipient.Profile.Key = profileKey
			return true, nil
		})
		if err != nil {
			c <- ProvisioningResponse{
				State: StateProvisioningError,
				Err:   fmt.Errorf("error storing profile key: %w", err),
			}
			return
		}

		// Return the provisioning data
		c <- ProvisioningResponse{State: StateProvisioningDataReceived, ProvisioningData: data}
	}()
	return c
}

// Returns the provisioningUrl and an error
func startProvisioning(ctx context.Context, ws *websocket.Conn, provisioningCipher *ProvisioningCipher, allowBackup bool) (string, error) {
	log := zerolog.Ctx(ctx).With().Str("action", "start provisioning").Logger()
	pubKey := provisioningCipher.GetPublicKey()

	msg := &signalpb.WebSocketMessage{}
	err := wspb.Read(ctx, ws, msg)
	if err != nil {
		log.Err(err).Msg("error reading websocket message")
		return "", err
	}

	// Ensure the message is a request and has a valid verb and path
	if msg.GetType() != signalpb.WebSocketMessage_REQUEST || msg.GetRequest().GetVerb() != http.MethodPut || msg.GetRequest().GetPath() != "/v1/address" {
		return "", fmt.Errorf("unexpected websocket message: %v", msg)
	}

	var provisioningBody signalpb.ProvisioningAddress
	err = proto.Unmarshal(msg.GetRequest().GetBody(), &provisioningBody)
	if err != nil {
		return "", fmt.Errorf("failed to unmarshal provisioning UUID: %w", err)
	}

	linkCapabilities := []string{"backup5,nopni2"}
	if !allowBackup {
		linkCapabilities = []string{"nopni2"}
	}
	provisioningURL := (&url.URL{
		Scheme: "sgnl",
		Host:   "linkdevice",
		RawQuery: url.Values{
			"uuid":         []string{provisioningBody.GetAddress()},
			"pub_key":      []string{base64.StdEncoding.EncodeToString(exerrors.Must(pubKey.Serialize()))},
			"capabilities": linkCapabilities,
		}.Encode(),
	}).String()

	// Create and send response
	response := web.CreateWSResponse(ctx, msg.GetRequest().GetId(), 200)
	err = wspb.Write(ctx, ws, response)
	if err != nil {
		log.Err(err).Msg("error writing websocket message")
		return "", err
	}
	return provisioningURL, nil
}

func continueProvisioning(ctx context.Context, ws *websocket.Conn, provisioningCipher *ProvisioningCipher) (*signalpb.ProvisionMessage, error) {
	log := zerolog.Ctx(ctx).With().Str("action", "continue provisioning").Logger()
	envelope := &signalpb.ProvisionEnvelope{}
	msg := &signalpb.WebSocketMessage{}
	err := wspb.Read(ctx, ws, msg)
	if err != nil {
		log.Err(err).Msg("error reading websocket message")
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

		response := web.CreateWSResponse(ctx, *msg.Request.Id, 200)
		err = wspb.Write(ctx, ws, response)
		if err != nil {
			log.Err(err).Msg("error writing websocket message")
			return nil, err
		}
	} else {
		err = fmt.Errorf("invalid provisioning message, type: %v, verb: %v, path: %v", *msg.Type, *msg.Request.Verb, *msg.Request.Path)
		log.Err(err).Msg("problem reading websocket message")
		return nil, err
	}
	provisioningMessage, err := provisioningCipher.Decrypt(envelope)
	return provisioningMessage, err
}

func getSignalCapabilities(phonenumberless bool) map[string]any {
	return map[string]any{
		"attachmentBackfill":        true,
		"spqr":                      true,
		"usernameChangeSyncMessage": true,
		"optionalPhoneNumber":       phonenumberless,
	}
}

func (cli *Client) RegisterCapabilities(ctx context.Context) error {
	body := exerrors.Must(json.Marshal(getSignalCapabilities(cli.Store.PNI == uuid.Nil)))
	resp, err := cli.AuthedWS.SendRequest(ctx, http.MethodPut, "/v1/devices/capabilities", body, nil)
	if err != nil {
		return err
	}
	return web.DecodeWSResponseBody(ctx, nil, resp)
}

func (cli *Client) Unlink(ctx context.Context) error {
	resp, err := cli.AuthedWS.SendRequest(ctx, http.MethodDelete, fmt.Sprintf("/v1/devices/%d", cli.Store.DeviceID), nil, nil)
	if err != nil {
		return err
	}
	return web.DecodeWSResponseBody(ctx, nil, resp)
}

func confirmDevice(
	ctx context.Context,
	username string,
	password string,
	code string,
	hasE164 bool,
	aciRegistrationID int,
	pniRegistrationID int,
	aciSignedPreKey *libsignalgo.SignedPreKeyRecord,
	pniSignedPreKey *libsignalgo.SignedPreKeyRecord,
	aciPQLastResortPreKey *libsignalgo.KyberPreKeyRecord,
	pniPQLastResortPreKey *libsignalgo.KyberPreKeyRecord,
	aciIdentityKeyPair *libsignalgo.IdentityKeyPair,
	deviceName string,
) (*ConfirmDeviceResponse, error) {
	log := zerolog.Ctx(ctx).With().Str("action", "confirm device").Logger()
	ctx = log.WithContext(ctx)
	encryptedDeviceName, err := EncryptDeviceName(deviceName, aciIdentityKeyPair.GetPublicKey())
	if err != nil {
		return nil, fmt.Errorf("failed to encrypt device name: %w", err)
	}

	ws, resp, err := web.OpenWebsocket(ctx, (&url.URL{
		Scheme: "wss",
		Host:   web.APIHostname,
		Path:   web.WebsocketPath,
	}).String())
	if err != nil {
		log.Err(err).Any("resp", resp).Msg("error opening websocket")
		return nil, err
	}
	defer ws.Close(websocket.StatusInternalError, "Websocket StatusInternalError")

	aciSignedPreKeyJson, err := SignedPreKeyToJSON(aciSignedPreKey)
	if err != nil {
		return nil, fmt.Errorf("failed to convert signed ACI prekey to JSON: %w", err)
	}
	aciPQLastResortPreKeyJson, err := KyberPreKeyToJSON(aciPQLastResortPreKey)
	if err != nil {
		return nil, fmt.Errorf("failed to convert ACI kyber last resort prekey to JSON: %w", err)
	}

	accountAttributes := map[string]any{
		"fetchesMessages": true,
		"name":            encryptedDeviceName,
		"registrationId":  aciRegistrationID,
		"capabilities":    getSignalCapabilities(!hasE164),
	}
	data := map[string]any{
		"verificationCode":      code,
		"accountAttributes":     accountAttributes,
		"aciSignedPreKey":       aciSignedPreKeyJson,
		"aciPqLastResortPreKey": aciPQLastResortPreKeyJson,
	}
	if hasE164 {
		accountAttributes["pniRegistrationId"] = pniRegistrationID
		data["pniSignedPreKey"], err = SignedPreKeyToJSON(pniSignedPreKey)
		if err != nil {
			return nil, fmt.Errorf("failed to convert signed PNI prekey to JSON: %w", err)
		}
		data["pniPqLastResortPreKey"], err = KyberPreKeyToJSON(pniPQLastResortPreKey)
		if err != nil {
			return nil, fmt.Errorf("failed to convert PNI kyber last resort prekey to JSON: %w", err)
		}
	}

	jsonBytes, err := json.Marshal(data)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal JSON: %w", err)
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
		return nil, fmt.Errorf("failed on write protobuf data to websocket: %w", err)
	}

	receivedMsg := &signalpb.WebSocketMessage{}
	err = wspb.Read(ctx, ws, receivedMsg)
	if err != nil {
		return nil, fmt.Errorf("failed to read from websocket after devices call: %w", err)
	}
	zerolog.Ctx(ctx).Trace().Any("response", receivedMsg).Msg("Raw confirm device response")

	status := int(receivedMsg.GetResponse().GetStatus())
	if status < 200 || status >= 300 {
		return nil, DeviceLinkError{StatusCode: status, Message: receivedMsg.GetResponse().GetMessage()}
	}

	deviceResp := ConfirmDeviceResponse{}
	err = json.Unmarshal(receivedMsg.Response.Body, &deviceResp)
	if err != nil {
		return nil, fmt.Errorf("failed to unmarshal JSON: %w", err)
	}

	return &deviceResp, nil
}
