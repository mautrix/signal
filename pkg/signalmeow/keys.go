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
	"net/http"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/rs/zerolog"

	"go.mau.fi/mautrix-signal/pkg/libsignalgo"
	"go.mau.fi/mautrix-signal/pkg/signalmeow/types"
	"go.mau.fi/mautrix-signal/pkg/signalmeow/web"
)

type GeneratedPreKeys struct {
	PreKeys      []*libsignalgo.PreKeyRecord
	KyberPreKeys []*libsignalgo.KyberPreKeyRecord
	IdentityKey  []uint8
}

func (cli *Client) GenerateAndRegisterPreKeys(ctx context.Context, uuidKind types.UUIDKind) error {
	var identityKeyPair *libsignalgo.IdentityKeyPair
	if uuidKind == types.UUIDKindPNI {
		identityKeyPair = cli.Store.PNIIdentityKeyPair
	} else {
		identityKeyPair = cli.Store.ACIIdentityKeyPair
	}

	nextPreKeyID, err := cli.Store.PreKeyStoreExtras.GetNextPreKeyID(ctx, uuidKind)
	if err != nil {
		return fmt.Errorf("failed to get next prekey ID: %w", err)
	}
	nextKyberPreKeyID, err := cli.Store.PreKeyStoreExtras.GetNextKyberPreKeyID(ctx, uuidKind)
	if err != nil {
		return fmt.Errorf("failed to get next kyber prekey ID: %w", err)
	}
	preKeys := GeneratePreKeys(nextPreKeyID, 100, uuidKind)
	kyberPreKeys := GenerateKyberPreKeys(nextKyberPreKeyID, 100, uuidKind, identityKeyPair)

	for _, preKey := range preKeys {
		err = cli.Store.PreKeyStoreExtras.SavePreKey(ctx, uuidKind, preKey, false)
		if err != nil {
			return fmt.Errorf("failed to save prekey: %w", err)
		}
	}
	for _, kyberPreKey := range kyberPreKeys {
		err = cli.Store.PreKeyStoreExtras.SaveKyberPreKey(ctx, uuidKind, kyberPreKey, false)
		if err != nil {
			return fmt.Errorf("failed to save kyber prekey: %w", err)
		}
	}

	// Register prekeys
	identityKey, err := identityKeyPair.GetPublicKey().Serialize()
	if err != nil {
		return fmt.Errorf("failed to serialize identity key: %w", err)
	}
	generatedPreKeys := GeneratedPreKeys{
		PreKeys:      preKeys,
		KyberPreKeys: kyberPreKeys,
		IdentityKey:  identityKey,
	}
	preKeyUsername := cli.Store.Number
	if cli.Store.ACI != uuid.Nil {
		preKeyUsername = cli.Store.ACI.String()
	}
	preKeyUsername = fmt.Sprintf("%s.%d", preKeyUsername, cli.Store.DeviceID)
	err = RegisterPreKeys(&generatedPreKeys, uuidKind, preKeyUsername, cli.Store.Password)
	if err != nil {
		zlog.Err(err).Msg("RegisterPreKeys error")
		return err
	}

	// Mark prekeys as registered
	// (kyber prekeys don't have "mark as uploaded" we just assume they always are)
	lastPreKeyID, err := preKeys[len(preKeys)-1].GetID()
	err = cli.Store.PreKeyStoreExtras.MarkPreKeysAsUploaded(ctx, uuidKind, lastPreKeyID)

	if err != nil {
		zerolog.Ctx(ctx).Err(err).Msg("Failed to mark prekeys as uploaded")
	}

	return err
}

func GeneratePreKeys(startKeyId uint, count uint, uuidKind types.UUIDKind) []*libsignalgo.PreKeyRecord {
	generatedPreKeys := []*libsignalgo.PreKeyRecord{}
	for i := startKeyId; i < startKeyId+count; i++ {
		privateKey, err := libsignalgo.GeneratePrivateKey()
		if err != nil {
			zlog.Err(err).Msg("Error generating private key")
			panic(err)
		}
		preKey, err := libsignalgo.NewPreKeyRecordFromPrivateKey(uint32(i), privateKey)
		if err != nil {
			zlog.Err(err).Msg("Error creating preKey record")
			panic(err)
		}
		generatedPreKeys = append(generatedPreKeys, preKey)
	}
	return generatedPreKeys
}

func GenerateKyberPreKeys(startKeyId uint, count uint, uuidKind types.UUIDKind, identityKeyPair *libsignalgo.IdentityKeyPair) []*libsignalgo.KyberPreKeyRecord {
	generatedKyberPreKeys := []*libsignalgo.KyberPreKeyRecord{}
	for i := startKeyId; i < startKeyId+count; i++ {
		kyberPreKeyPair, err := libsignalgo.KyberKeyPairGenerate()
		if err != nil {
			zlog.Err(err).Msg("Error generating kyber key pair")
			panic(err)
		}
		publicKey, err := kyberPreKeyPair.GetPublicKey()
		if err != nil {
			zlog.Err(err).Msg("Error getting kyber public key")
			panic(err)
		}
		serializedPublicKey, err := publicKey.Serialize()
		if err != nil {
			zlog.Err(err).Msg("Error serializing kyber public key")
			panic(err)
		}
		signature, err := identityKeyPair.GetPrivateKey().Sign(serializedPublicKey)
		if err != nil {
			zlog.Err(err).Msg("Error signing kyber public key")
			panic(err)
		}
		preKey, err := libsignalgo.NewKyberPreKeyRecord(uint32(i), time.Now(), kyberPreKeyPair, signature)
		if err != nil {
			zlog.Err(err).Msg("Error creating kyber preKey record")
			panic(err)

		}
		generatedKyberPreKeys = append(generatedKyberPreKeys, preKey)
	}
	return generatedKyberPreKeys
}

func GenerateSignedPreKey(startSignedKeyId uint32, uuidKind types.UUIDKind, identityKeyPair *libsignalgo.IdentityKeyPair) *libsignalgo.SignedPreKeyRecord {
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
	serializedPublicKey, err := publicKey.Serialize()
	if err != nil {
		zlog.Err(err).Msg("Error serializing public key")
		panic(err)
	}
	signature, err := identityKeyPair.GetPrivateKey().Sign(serializedPublicKey)
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

func PreKeyToJSON(preKey *libsignalgo.PreKeyRecord) map[string]interface{} {
	id, _ := preKey.GetID()
	publicKey, _ := preKey.GetPublicKey()
	serializedKey, _ := publicKey.Serialize()
	preKeyJson := map[string]interface{}{
		"keyId":     id,
		"publicKey": base64.StdEncoding.EncodeToString(serializedKey),
	}
	return preKeyJson
}

func SignedPreKeyToJSON(signedPreKey *libsignalgo.SignedPreKeyRecord) map[string]interface{} {
	id, _ := signedPreKey.GetID()
	publicKey, _ := signedPreKey.GetPublicKey()
	serializedKey, _ := publicKey.Serialize()
	signature, _ := signedPreKey.GetSignature()
	signedPreKeyJson := map[string]interface{}{
		"keyId":     id,
		"publicKey": base64.StdEncoding.EncodeToString(serializedKey),
		"signature": base64.StdEncoding.EncodeToString(signature),
	}
	return signedPreKeyJson
}

func KyberPreKeyToJSON(kyberPreKey *libsignalgo.KyberPreKeyRecord) map[string]interface{} {
	id, _ := kyberPreKey.GetID()
	publicKey, _ := kyberPreKey.GetPublicKey()
	serializedKey, _ := publicKey.Serialize()
	signature, _ := kyberPreKey.GetSignature()
	kyberPreKeyJson := map[string]interface{}{
		"keyId":     id,
		"publicKey": base64.StdEncoding.EncodeToString(serializedKey),
		"signature": base64.StdEncoding.EncodeToString(signature),
	}
	return kyberPreKeyJson
}

func RegisterPreKeys(generatedPreKeys *GeneratedPreKeys, uuidKind types.UUIDKind, username string, password string) error {
	// Convert generated prekeys to JSON
	preKeysJson := []map[string]interface{}{}
	kyberPreKeysJson := []map[string]interface{}{}
	for _, preKey := range generatedPreKeys.PreKeys {
		preKeyJson := PreKeyToJSON(preKey)
		preKeysJson = append(preKeysJson, preKeyJson)
	}
	for _, kyberPreKey := range generatedPreKeys.KyberPreKeys {
		kyberPreKeyJson := KyberPreKeyToJSON(kyberPreKey)
		kyberPreKeysJson = append(kyberPreKeysJson, kyberPreKeyJson)
	}

	identityKey := generatedPreKeys.IdentityKey
	register_json := map[string]interface{}{
		"preKeys":     preKeysJson,
		"pqPreKeys":   kyberPreKeysJson,
		"identityKey": base64.StdEncoding.EncodeToString(identityKey),
	}

	// Send request
	keysPath := "/v2/keys?identity=" + string(uuidKind)
	jsonBytes, err := json.Marshal(register_json)
	if err != nil {
		zlog.Err(err).Msg("Error marshalling register JSON")
		return err
	}
	opts := &web.HTTPReqOpt{Body: jsonBytes, Username: &username, Password: &password}
	resp, err := web.SendHTTPRequest(http.MethodPut, keysPath, opts)
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

func (cli *Client) FetchAndProcessPreKey(ctx context.Context, theirUUID uuid.UUID, specificDeviceID int) error {
	// Fetch prekey
	deviceIDPath := "/*"
	if specificDeviceID >= 0 {
		deviceIDPath = "/" + fmt.Sprint(specificDeviceID)
	}
	path := "/v2/keys/" + theirUUID.String() + deviceIDPath + "?pq=true"
	username, password := cli.Store.BasicAuthCreds()
	resp, err := web.SendHTTPRequest(http.MethodGet, path, &web.HTTPReqOpt{Username: &username, Password: &password})
	if err != nil {
		zlog.Err(err).Msg("Error sending request")
		return err
	}
	var prekeyResponse prekeyResponse
	err = web.DecodeHTTPResponseBody(ctx, &prekeyResponse, resp)
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
		var preKeyID uint32
		if d.PreKey != nil {
			preKeyID = uint32(d.PreKey.KeyID)
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

		var kyberPublicKey *libsignalgo.KyberPublicKey
		var kyberPreKeyID uint32
		var kyberPreKeySignature []byte
		if d.PQPreKey != nil {
			kyberPreKeyID = uint32(d.PQPreKey.KeyID)
			rawKyberPublicKey, err := addBase64PaddingAndDecode(d.PQPreKey.PublicKey)
			if err != nil {
				zlog.Err(err).Msg("Error decoding kyber public key")
				return err
			}
			kyberPublicKey, err = libsignalgo.DeserializeKyberPublicKey(rawKyberPublicKey)
			if err != nil {
				zlog.Err(err).Msg("Error deserializing kyber public key")
				return err
			}
			kyberPreKeySignature, err = addBase64PaddingAndDecode(d.PQPreKey.Signature)
		}

		rawSignature, err := addBase64PaddingAndDecode(d.SignedPreKey.Signature)
		if err != nil {
			zlog.Err(err).Msg("Error decoding signature")
			return err
		}

		preKeyBundle, err := libsignalgo.NewPreKeyBundle(
			uint32(d.RegistrationID),
			uint32(d.DeviceID),
			preKeyID,
			publicKey,
			uint32(d.SignedPreKey.KeyID),
			signedPublicKey,
			rawSignature,
			kyberPreKeyID,
			kyberPublicKey,
			kyberPreKeySignature,
			identityKey,
		)
		if err != nil {
			zlog.Err(err).Msg("Error creating prekey bundle")
			return err
		}
		address, err := libsignalgo.NewUUIDAddress(theirUUID, uint(d.DeviceID))
		if err != nil {
			zlog.Err(err).Msg("Error creating address")
			return err
		}
		err = libsignalgo.ProcessPreKeyBundle(
			ctx,
			preKeyBundle,
			address,
			cli.Store.SessionStore,
			cli.Store.IdentityStore,
		)

		if err != nil {
			zlog.Err(err).Msg("Error processing prekey bundle")
			return err
		}
	}

	return err
}
