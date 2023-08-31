package signalmeow

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"strings"
	"time"

	"go.mau.fi/mautrix-signal/pkg/libsignalgo"
	"go.mau.fi/mautrix-signal/pkg/signalmeow/web"
)

type GeneratedPreKeys struct {
	PreKeys      []libsignalgo.PreKeyRecord
	SignedPreKey libsignalgo.SignedPreKeyRecord
	IdentityKey  []uint8
}

func GenerateAndRegisterPreKeys(device *Device, uuidKind UUIDKind) error {
	// Generate prekeys
	preKeys := GeneratePreKeys(0, 100, uuidKind)

	// Persist prekeys
	for _, preKey := range *preKeys {
		device.PreKeyStoreExtras.SavePreKey(uuidKind, &preKey, false)
	}

	var identityKeyPair *libsignalgo.IdentityKeyPair
	if uuidKind == UUID_KIND_PNI {
		identityKeyPair = device.Data.PniIdentityKeyPair
	} else {
		identityKeyPair = device.Data.AciIdentityKeyPair
	}
	signedPreKey := GenerateSignedPreKey(0, uuidKind, identityKeyPair)
	device.PreKeyStoreExtras.SaveSignedPreKey(uuidKind, signedPreKey, false)

	// Register prekeys
	identityKey, err := identityKeyPair.GetPublicKey().Serialize()
	if err != nil {
		zlog.Err(err).Msg("Error serializing identity key")
		return err
	}
	generatedPreKeys := GeneratedPreKeys{
		PreKeys:      *preKeys,
		SignedPreKey: *signedPreKey,
		IdentityKey:  identityKey,
	}
	preKeyUsername := device.Data.Number
	if device.Data.AciUuid != "" {
		preKeyUsername = device.Data.AciUuid
	}
	preKeyUsername = preKeyUsername + "." + fmt.Sprint(device.Data.DeviceId)
	err = RegisterPreKeys(&generatedPreKeys, uuidKind, preKeyUsername, device.Data.Password)
	if err != nil {
		zlog.Err(err).Msg("RegisterPreKeys error")
		return err
	}

	// Mark prekeys as registered
	lastPreKeyId, err := (*preKeys)[len(*preKeys)-1].GetID()
	err = device.PreKeyStoreExtras.MarkPreKeysAsUploaded(uuidKind, lastPreKeyId)
	signedId, err := signedPreKey.GetID()
	err = device.PreKeyStoreExtras.MarkSignedPreKeysAsUploaded(uuidKind, signedId)

	if err != nil {
		zlog.Err(err).Msg("Error marking prekeys as uploaded")
	}

	return err
}

func GeneratePreKeys(startKeyId uint32, count uint32, uuidKind UUIDKind) *[]libsignalgo.PreKeyRecord {
	generatedPreKeys := []libsignalgo.PreKeyRecord{}
	for i := startKeyId; i < startKeyId+count; i++ {
		privateKey, err := libsignalgo.GeneratePrivateKey()
		if err != nil {
			zlog.Err(err).Msg("Error generating private key")
			panic(err)
		}
		preKey, err := libsignalgo.NewPreKeyRecordFromPrivateKey(i, privateKey)
		if err != nil {
			zlog.Err(err).Msg("Error creating preKey record")
			panic(err)
		}
		generatedPreKeys = append(generatedPreKeys, *preKey)
	}

	return &generatedPreKeys
}

func GenerateSignedPreKey(startSignedKeyId uint32, uuidKind UUIDKind, identityKeyPair *libsignalgo.IdentityKeyPair) *libsignalgo.SignedPreKeyRecord {
	// Generate a signed prekey
	privateKey, err := libsignalgo.GeneratePrivateKey()
	if err != nil {
		zlog.Err(err).Msg("Error generating private key")
		panic(err)
	}
	timestamp := time.Now()
	publicKey, err := privateKey.GetPublicKey()
	if err != nil {
		zlog.Err(err).Msg("Error getting public key")
		panic(err)
	}
	serialized_public_key, err := publicKey.Serialize()
	if err != nil {
		zlog.Err(err).Msg("Error serializing public key")
		panic(err)
	}
	signature, err := identityKeyPair.GetPrivateKey().Sign(serialized_public_key)
	if err != nil {
		zlog.Err(err).Msg("Error signing public key")
		panic(err)
	}
	signedPreKey, err := libsignalgo.NewSignedPreKeyRecordFromPrivateKey(startSignedKeyId, timestamp, privateKey, signature)
	if err != nil {
		zlog.Err(err).Msg("Error creating signed preKey record")
		panic(err)
	}

	return signedPreKey
}

func RegisterPreKeys(generatedPreKeys *GeneratedPreKeys, uuidKind UUIDKind, username string, password string) error {
	// Convert generated prekeys to JSON
	preKeysJson := []map[string]interface{}{}
	for _, preKey := range generatedPreKeys.PreKeys {
		id, _ := preKey.GetID()
		publicKey, _ := preKey.GetPublicKey()
		serializedKey, _ := publicKey.Serialize()
		preKeyJson := map[string]interface{}{
			"keyId":     id,
			"publicKey": base64.StdEncoding.EncodeToString(serializedKey),
		}
		preKeysJson = append(preKeysJson, preKeyJson)
	}

	// Convert signed prekey to JSON
	id, _ := generatedPreKeys.SignedPreKey.GetID()
	publicKey, _ := generatedPreKeys.SignedPreKey.GetPublicKey()
	serializedKey, _ := publicKey.Serialize()
	signature, _ := generatedPreKeys.SignedPreKey.GetSignature()
	signedPreKeyJson := map[string]interface{}{
		"keyId":     id,
		"publicKey": serializedKey,
		"signature": base64.StdEncoding.EncodeToString(signature),
	}
	identityKey := generatedPreKeys.IdentityKey
	register_json := map[string]interface{}{
		"preKeys":      preKeysJson,
		"signedPreKey": signedPreKeyJson,
		"identityKey":  base64.StdEncoding.EncodeToString(identityKey),
	}

	// Send request
	keysPath := "/v2/keys?identity=" + string(uuidKind)
	jsonBytes, err := json.Marshal(register_json)
	if err != nil {
		zlog.Err(err).Msg("Error marshalling register JSON")
		return err
	}
	opts := &web.HTTPReqOpt{Body: jsonBytes, Username: &username, Password: &password}
	resp, err := web.SendHTTPRequest("PUT", keysPath, opts)
	if err != nil {
		zlog.Err(err).Msg("Error sending request")
		return err
	}
	// status code not 2xx
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		err := fmt.Errorf("Error registering prekeys: %v", resp.Status)
		zlog.Err(err).Msg("Error registering prekeys")
		return err
	}
	defer resp.Body.Close()
	return err
}

type prekeyResponse struct {
	IdentityKey string         `json:"identityKey"`
	Devices     []prekeyDevice `json:"devices"`
}

type prekeyDevice struct {
	DeviceID       int           `json:"deviceId"`
	RegistrationID int           `json:"registrationId"`
	SignedPreKey   prekeyDetail  `json:"signedPreKey"`
	PreKey         *prekeyDetail `json:"preKey"`
	PQPreKey       *prekeyDetail `json:"pqPreKey"`
}

type prekeyDetail struct {
	KeyID     int    `json:"keyId"`
	PublicKey string `json:"publicKey"`
	Signature string `json:"signature,omitempty"` // 'omitempty' since this field isn't always present
}

func addBase64PaddingAndDecode(data string) ([]byte, error) {
	padding := len(data) % 4
	if padding > 0 {
		data += strings.Repeat("=", 4-padding)
	}
	return base64.StdEncoding.DecodeString(data)
}

func FetchAndProcessPreKey(ctx context.Context, device *Device, theirUuid string, specificDeviceID int) error {
	// Fetch prekey
	deviceIDPath := "/*"
	if specificDeviceID >= 0 {
		deviceIDPath = "/" + fmt.Sprint(specificDeviceID)
	}
	path := "/v2/keys/" + theirUuid + deviceIDPath
	username, password := device.Data.BasicAuthCreds()
	resp, err := web.SendHTTPRequest("GET", path, &web.HTTPReqOpt{Username: &username, Password: &password})
	if err != nil {
		zlog.Err(err).Msg("Error sending request")
		return err
	}
	var prekeyResponse prekeyResponse
	err = web.DecodeHTTPResponseBody(&prekeyResponse, resp)
	if err != nil {
		zlog.Err(err).Msg("Fetching prekeys, error with response body")
		return err
	}

	rawIdentityKey, err := addBase64PaddingAndDecode(prekeyResponse.IdentityKey)
	identityKey, err := libsignalgo.DeserializeIdentityKey([]byte(rawIdentityKey))
	if err != nil {
		zlog.Err(err).Msg("Error deserializing identity key")
		return err
	}
	if identityKey == nil {
		err := fmt.Errorf("Deserializing identity key returned nil with no error")
		zlog.Err(err).Msg("")
		return err
	}

	// Process each prekey in response (should only be one at the moment)
	for _, d := range prekeyResponse.Devices {
		var publicKey *libsignalgo.PublicKey
		var preKeyId uint32
		if d.PreKey != nil {
			preKeyId = uint32(d.PreKey.KeyID)
			rawPublicKey, err := addBase64PaddingAndDecode(d.PreKey.PublicKey)
			if err != nil {
				zlog.Err(err).Msg("Error decoding public key")
				return err
			}
			publicKey, err = libsignalgo.DeserializePublicKey(rawPublicKey)
			if err != nil {
				zlog.Err(err).Msg("Error deserializing public key")
				return err
			}
		}

		rawSignedPublicKey, err := addBase64PaddingAndDecode(d.SignedPreKey.PublicKey)
		if err != nil {
			zlog.Err(err).Msg("Error decoding signed public key")
			return err
		}
		signedPublicKey, err := libsignalgo.DeserializePublicKey(rawSignedPublicKey)
		if err != nil {
			zlog.Err(err).Msg("Error deserializing signed public key")
			return err
		}

		rawSignature, err := addBase64PaddingAndDecode(d.SignedPreKey.Signature)
		if err != nil {
			zlog.Err(err).Msg("Error decoding signature")
			return err
		}

		var preKeyBundle *libsignalgo.PreKeyBundle
		if publicKey == nil {
			// There is no prekey, use the signed method
			preKeyBundle, err = libsignalgo.NewPreKeyBundleWithoutPrekey(
				uint32(d.RegistrationID),
				uint32(d.DeviceID),
				uint32(d.SignedPreKey.KeyID),
				signedPublicKey,
				rawSignature,
				identityKey,
			)
		} else {
			preKeyBundle, err = libsignalgo.NewPreKeyBundle(
				uint32(d.RegistrationID),
				uint32(d.DeviceID),
				preKeyId,
				publicKey,
				uint32(d.SignedPreKey.KeyID),
				signedPublicKey,
				rawSignature,
				identityKey,
			)
		}
		if err != nil {
			zlog.Err(err).Msg("Error creating prekey bundle")
			return err
		}
		address, err := libsignalgo.NewAddress(theirUuid, uint(d.DeviceID))
		if err != nil {
			zlog.Err(err).Msg("Error creating address")
			return err
		}
		err = libsignalgo.ProcessPreKeyBundle(
			preKeyBundle,
			address,
			device.SessionStore,
			device.IdentityStore,
			libsignalgo.NewCallbackContext(ctx),
		)

		if err != nil {
			zlog.Err(err).Msg("Error processing prekey bundle")
			return err
		}
	}

	return err
}
