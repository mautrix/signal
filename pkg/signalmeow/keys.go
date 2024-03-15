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
	"math/rand"
	"net/http"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/rs/zerolog"

	"go.mau.fi/mautrix-signal/pkg/libsignalgo"
	"go.mau.fi/mautrix-signal/pkg/signalmeow/types"
	"go.mau.fi/mautrix-signal/pkg/signalmeow/web"
)

const PREKEY_BATCH_SIZE = 100

type GeneratedPreKeys struct {
	PreKeys      []*libsignalgo.PreKeyRecord
	KyberPreKeys []*libsignalgo.KyberPreKeyRecord
	IdentityKey  []uint8
}

func (cli *Client) GenerateAndRegisterPreKeys(ctx context.Context, uuidKind types.UUIDKind) error {
	_, err := cli.GenerateAndSaveNextPreKeyBatch(ctx, uuidKind)
	if err != nil {
		return fmt.Errorf("failed to generate and save next prekey batch: %w", err)
	}
	_, err = cli.GenerateAndSaveNextKyberPreKeyBatch(ctx, uuidKind)
	if err != nil {
		return fmt.Errorf("failed to generate and save next kyber prekey batch: %w", err)
	}

	// We need to upload all currently valid prekeys, not just the ones we just generated
	err = cli.RegisterAllPreKeys(ctx, uuidKind)
	if err != nil {
		return fmt.Errorf("failed to register prekey batches: %w", err)
	}

	return err
}

func (cli *Client) RegisterAllPreKeys(ctx context.Context, uuidKind types.UUIDKind) error {
	var identityKeyPair *libsignalgo.IdentityKeyPair
	if uuidKind == types.UUIDKindPNI {
		identityKeyPair = cli.Store.PNIIdentityKeyPair
	} else {
		identityKeyPair = cli.Store.ACIIdentityKeyPair
	}

	// Get all prekeys and kyber prekeys from the database
	preKeys, err := cli.Store.PreKeyStoreExtras.AllPreKeys(ctx, uuidKind)
	if err != nil {
		return fmt.Errorf("failed to get all prekeys: %w", err)
	}
	kyberPreKeys, err := cli.Store.PreKeyStoreExtras.AllNormalKyberPreKeys(ctx, uuidKind)
	if err != nil {
		return fmt.Errorf("failed to get all kyber prekeys: %w", err)
	}

	// We need to have some keys to upload
	if len(preKeys) == 0 && len(kyberPreKeys) == 0 {
		return fmt.Errorf("no prekeys to upload")
	}

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
	log := zerolog.Ctx(ctx).With().Str("action", "register prekeys").Logger()
	log.Debug().Int("num_prekeys", len(preKeys)).Int("num_kyber_prekeys", len(kyberPreKeys)).Msg("Registering prekeys")
	err = RegisterPreKeys(ctx, &generatedPreKeys, uuidKind, preKeyUsername, cli.Store.Password)
	if err != nil {
		return fmt.Errorf("failed to register prekeys: %w", err)
	}

	// Mark prekeys as registered
	// (kyber prekeys don't have "mark as uploaded" we just assume they always are)
	// TODO: we don't need to mark prekeys as uploaded, since we just upload all unused prekeys each time.
	// So we can drop this column and remove these methods
	lastPreKeyID, err := preKeys[len(preKeys)-1].GetID()
	if err != nil {
		return fmt.Errorf("failed to get last prekey ID: %w", err)
	}
	err = cli.Store.PreKeyStoreExtras.MarkPreKeysAsUploaded(ctx, uuidKind, lastPreKeyID)
	if err != nil {
		zerolog.Ctx(ctx).Err(err).Msg("Failed to mark prekeys as uploaded")
	}

	return err
}

func (cli *Client) GenerateAndSaveNextPreKeyBatch(ctx context.Context, uuidKind types.UUIDKind) ([]*libsignalgo.PreKeyRecord, error) {
	nextPreKeyID, err := cli.Store.PreKeyStoreExtras.GetNextPreKeyID(ctx, uuidKind)
	if err != nil {
		return nil, fmt.Errorf("failed to get next prekey ID: %w", err)
	}
	preKeys := GeneratePreKeys(nextPreKeyID, PREKEY_BATCH_SIZE, uuidKind)
	for _, preKey := range preKeys {
		err = cli.Store.PreKeyStoreExtras.SavePreKey(ctx, uuidKind, preKey, false)
		if err != nil {
			return nil, fmt.Errorf("failed to save prekey: %w", err)
		}
	}
	return preKeys, nil
}

func (cli *Client) GenerateAndSaveNextKyberPreKeyBatch(ctx context.Context, uuidKind types.UUIDKind) ([]*libsignalgo.KyberPreKeyRecord, error) {
	var identityKeyPair *libsignalgo.IdentityKeyPair
	if uuidKind == types.UUIDKindPNI {
		identityKeyPair = cli.Store.PNIIdentityKeyPair
	} else {
		identityKeyPair = cli.Store.ACIIdentityKeyPair
	}
	nextKyberPreKeyID, err := cli.Store.PreKeyStoreExtras.GetNextKyberPreKeyID(ctx, uuidKind)
	if err != nil {
		return nil, fmt.Errorf("failed to get next kyber prekey ID: %w", err)
	}
	kyberPreKeys := GenerateKyberPreKeys(nextKyberPreKeyID, PREKEY_BATCH_SIZE, uuidKind, identityKeyPair)
	for _, kyberPreKey := range kyberPreKeys {
		err = cli.Store.PreKeyStoreExtras.SaveKyberPreKey(ctx, uuidKind, kyberPreKey, false)
		if err != nil {
			return nil, fmt.Errorf("failed to save kyber prekey: %w", err)
		}
	}
	return kyberPreKeys, nil
}

func GeneratePreKeys(startKeyId uint, count uint, uuidKind types.UUIDKind) []*libsignalgo.PreKeyRecord {
	generatedPreKeys := []*libsignalgo.PreKeyRecord{}
	for i := startKeyId; i < startKeyId+count; i++ {
		privateKey, err := libsignalgo.GeneratePrivateKey()
		if err != nil {
			panic(fmt.Errorf("error generating private key: %w", err))
		}
		preKey, err := libsignalgo.NewPreKeyRecordFromPrivateKey(uint32(i), privateKey)
		if err != nil {
			panic(fmt.Errorf("error creating prekey record: %w", err))
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
			panic(fmt.Errorf("error generating kyber key pair: %w", err))
		}
		publicKey, err := kyberPreKeyPair.GetPublicKey()
		if err != nil {
			panic(fmt.Errorf("error getting kyber public key: %w", err))
		}
		serializedPublicKey, err := publicKey.Serialize()
		if err != nil {
			panic(fmt.Errorf("error serializing kyber public key: %w", err))
		}
		signature, err := identityKeyPair.GetPrivateKey().Sign(serializedPublicKey)
		if err != nil {
			panic(fmt.Errorf("error signing kyber public key: %w", err))
		}
		preKey, err := libsignalgo.NewKyberPreKeyRecord(uint32(i), time.Now(), kyberPreKeyPair, signature)
		if err != nil {
			panic(fmt.Errorf("error creating kyber prekey record: %w", err))

		}
		generatedKyberPreKeys = append(generatedKyberPreKeys, preKey)
	}
	return generatedKyberPreKeys
}

func GenerateSignedPreKey(startSignedKeyId uint32, uuidKind types.UUIDKind, identityKeyPair *libsignalgo.IdentityKeyPair) *libsignalgo.SignedPreKeyRecord {
	// Generate a signed prekey
	privateKey, err := libsignalgo.GeneratePrivateKey()
	if err != nil {
		panic(fmt.Errorf("error generating private key: %w", err))
	}
	timestamp := time.Now()
	publicKey, err := privateKey.GetPublicKey()
	if err != nil {
		panic(fmt.Errorf("error getting public key: %w", err))
	}
	serializedPublicKey, err := publicKey.Serialize()
	if err != nil {
		panic(fmt.Errorf("error serializing public key: %w", err))
	}
	signature, err := identityKeyPair.GetPrivateKey().Sign(serializedPublicKey)
	if err != nil {
		panic(fmt.Errorf("error signing public key: %w", err))
	}
	signedPreKey, err := libsignalgo.NewSignedPreKeyRecordFromPrivateKey(startSignedKeyId, timestamp, privateKey, signature)
	if err != nil {
		panic(fmt.Errorf("error creating signed prekey record: %w", err))
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

func RegisterPreKeys(ctx context.Context, generatedPreKeys *GeneratedPreKeys, uuidKind types.UUIDKind, username string, password string) error {
	log := zerolog.Ctx(ctx).With().Str("action", "register prekeys").Logger()
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
		log.Err(err).Msg("Error marshalling register JSON")
		return err
	}
	opts := &web.HTTPReqOpt{Body: jsonBytes, Username: &username, Password: &password}
	resp, err := web.SendHTTPRequest(ctx, http.MethodPut, keysPath, opts)
	if err != nil {
		log.Err(err).Msg("Error sending request")
		return err
	}
	defer resp.Body.Close()
	// status code not 2xx
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return fmt.Errorf("error registering prekeys: %v", resp.Status)
	}
	return err
}

type prekeyResponse struct {
	IdentityKey string         `json:"identityKey"`
	Devices     []prekeyDevice `json:"devices"`
}

type preKeyCountResponse struct {
	Count   int `json:"count"`
	PQCount int `json:"pqCount"`
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

func (cli *Client) FetchAndProcessPreKey(ctx context.Context, theirServiceID libsignalgo.ServiceID, specificDeviceID int) error {
	// Fetch prekey
	deviceIDPath := "/*"
	if specificDeviceID >= 0 {
		deviceIDPath = "/" + fmt.Sprint(specificDeviceID)
	}
	path := "/v2/keys/" + theirServiceID.String() + deviceIDPath + "?pq=true"
	username, password := cli.Store.BasicAuthCreds()
	resp, err := web.SendHTTPRequest(ctx, http.MethodGet, path, &web.HTTPReqOpt{Username: &username, Password: &password})
	if err != nil {
		return fmt.Errorf("error sending request: %w", err)
	}
	var prekeyResponse prekeyResponse
	err = web.DecodeHTTPResponseBody(ctx, &prekeyResponse, resp)
	if err != nil {
		return fmt.Errorf("error decoding response body: %w", err)
	}

	rawIdentityKey, err := addBase64PaddingAndDecode(prekeyResponse.IdentityKey)
	if err != nil {
		return fmt.Errorf("error decoding identity key: %w", err)
	}
	identityKey, err := libsignalgo.DeserializeIdentityKey([]byte(rawIdentityKey))
	if err != nil {
		return fmt.Errorf("error deserializing identity key: %w", err)
	}
	if identityKey == nil {
		return fmt.Errorf("deserializing identity key returned nil with no error")
	}

	// Process each prekey in response (should only be one at the moment)
	for _, d := range prekeyResponse.Devices {
		var publicKey *libsignalgo.PublicKey
		var preKeyID uint32
		if d.PreKey != nil {
			preKeyID = uint32(d.PreKey.KeyID)
			rawPublicKey, err := addBase64PaddingAndDecode(d.PreKey.PublicKey)
			if err != nil {
				return fmt.Errorf("error decoding public key: %w", err)
			}
			publicKey, err = libsignalgo.DeserializePublicKey(rawPublicKey)
			if err != nil {
				return fmt.Errorf("error deserializing public key: %w", err)
			}
		}

		rawSignedPublicKey, err := addBase64PaddingAndDecode(d.SignedPreKey.PublicKey)
		if err != nil {
			return fmt.Errorf("error decoding signed public key: %w", err)
		}
		signedPublicKey, err := libsignalgo.DeserializePublicKey(rawSignedPublicKey)
		if err != nil {
			return fmt.Errorf("error deserializing signed public key: %w", err)
		}

		var kyberPublicKey *libsignalgo.KyberPublicKey
		var kyberPreKeyID uint32
		var kyberPreKeySignature []byte
		if d.PQPreKey != nil {
			kyberPreKeyID = uint32(d.PQPreKey.KeyID)
			rawKyberPublicKey, err := addBase64PaddingAndDecode(d.PQPreKey.PublicKey)
			if err != nil {
				return fmt.Errorf("error decoding kyber public key: %w", err)
			}
			kyberPublicKey, err = libsignalgo.DeserializeKyberPublicKey(rawKyberPublicKey)
			if err != nil {
				return fmt.Errorf("error deserializing kyber public key: %w", err)
			}
			kyberPreKeySignature, err = addBase64PaddingAndDecode(d.PQPreKey.Signature)
			if err != nil {
				return fmt.Errorf("error decoding kyber prekey signature: %w", err)
			}
		}

		rawSignature, err := addBase64PaddingAndDecode(d.SignedPreKey.Signature)
		if err != nil {
			return fmt.Errorf("error decoding signature: %w", err)
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
			return fmt.Errorf("error creating prekey bundle: %w", err)
		}
		address, err := theirServiceID.Address(uint(d.DeviceID))
		if err != nil {
			return fmt.Errorf("error creating address: %w", err)
		}
		err = libsignalgo.ProcessPreKeyBundle(
			ctx,
			preKeyBundle,
			address,
			cli.Store.SessionStore,
			cli.Store.IdentityStore,
		)
		if err != nil {
			return fmt.Errorf("error processing prekey bundle: %w", err)
		}
	}

	return err
}

func (cli *Client) GetMyKeyCounts(ctx context.Context, uuidKind types.UUIDKind) (int, int, error) {
	log := zerolog.Ctx(ctx).With().Str("action", "get my key counts").Logger()
	username, password := cli.Store.BasicAuthCreds()
	path := "/v2/keys?identity=" + string(uuidKind)
	resp, err := web.SendHTTPRequest(ctx, http.MethodGet, path, &web.HTTPReqOpt{Username: &username, Password: &password})
	if err != nil {
		log.Err(err).Msg("Error sending request")
		return 0, 0, err
	}
	var preKeyCountResponse preKeyCountResponse
	err = web.DecodeHTTPResponseBody(ctx, &preKeyCountResponse, resp)
	if err != nil {
		log.Err(err).Msg("Fetching prekey counts, error with response body")
		return 0, 0, err
	}
	return preKeyCountResponse.Count, preKeyCountResponse.PQCount, err
}

func (cli *Client) CheckAndUploadNewPreKeys(ctx context.Context, uuidKind types.UUIDKind) error {
	log := zerolog.Ctx(ctx).With().Str("action", "check and upload new prekeys").Logger()
	// Check if we need to upload prekeys
	preKeyCount, kyberPreKeyCount, err := cli.GetMyKeyCounts(ctx, uuidKind)
	if err != nil {
		log.Err(err).Msg("Error getting prekey counts")
		return err
	}
	log.Debug().Int("preKeyCount", preKeyCount).Int("kyberPreKeyCount", kyberPreKeyCount).Msg("Checking prekey counts")

	var preKeys []*libsignalgo.PreKeyRecord
	var kyberPreKeys []*libsignalgo.KyberPreKeyRecord
	if preKeyCount < 10 {
		log.Info().Int("preKeyCount", preKeyCount).Msg("Generating and saving new prekeys")
		preKeys, err = cli.GenerateAndSaveNextPreKeyBatch(ctx, uuidKind)
		if err != nil {
			log.Err(err).Msg("Error generating and saving next prekey batch")
			return err
		}
	}
	if kyberPreKeyCount < 10 {
		log.Info().Int("kyberPreKeyCount", kyberPreKeyCount).Msg("Generating and saving new kyber prekeys")
		kyberPreKeys, err = cli.GenerateAndSaveNextKyberPreKeyBatch(ctx, uuidKind)
		if err != nil {
			log.Err(err).Msg("Error generating and saving next kyber prekey batch")
			return err
		}
	}
	if len(preKeys) == 0 && len(kyberPreKeys) == 0 {
		log.Debug().Msg("No new prekeys to upload")
		return nil
	}
	err = cli.RegisterAllPreKeys(ctx, uuidKind)
	if err != nil {
		log.Err(err).Msg("Error registering prekey batches")
		return err
	}
	return nil
}

func (cli *Client) StartKeyCheckLoop(ctx context.Context, uuidKind types.UUIDKind) {
	log := zerolog.Ctx(ctx).With().Str("action", "start key check loop").Logger()
	go func() {
		// Do the initial check within an hour of starting the loop
		window_start := 0
		window_size := 1
		for {
			random_minutes_in_window := rand.Intn(window_size) + window_start
			check_time := time.Duration(random_minutes_in_window) * time.Minute
			log.Debug().Dur("check_time", check_time).Msg("Waiting to check for new prekeys")

			select {
			case <-ctx.Done():
				return
			case <-time.After(check_time):
				err := cli.CheckAndUploadNewPreKeys(ctx, uuidKind)
				if err != nil {
					log.Err(err).Msg("Error checking and uploading new prekeys")
					// Retry within half an hour
					window_start = 5
					window_size = 25
					continue
				}
				// After a successful check, check again in 36 to 60 hours
				window_start = 36 * 60
				window_size = 24 * 60
			}
		}
	}()
}
