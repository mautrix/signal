package signalmeow

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"log"
	"time"

	"go.mau.fi/mautrix-signal/pkg/libsignalgo"
	"go.mau.fi/mautrix-signal/pkg/signalmeow/store"
	"go.mau.fi/mautrix-signal/pkg/signalmeow/types"
	"go.mau.fi/mautrix-signal/pkg/signalmeow/web"
)

type GeneratedPreKeys struct {
	PreKeys      []libsignalgo.PreKeyRecord
	SignedPreKey libsignalgo.SignedPreKeyRecord
	IdentityKey  []uint8
}

func GenerateAndRegisterPreKeys(device *store.Device, uuidKind types.UUIDKind) error {
	// Generate prekeys
	preKeys := GeneratePreKeys(0, 100, uuidKind)

	// Persist prekeys
	for _, preKey := range *preKeys {
		device.PreKeyStore.SavePreKey(uuidKind, &preKey, false)
	}

	var identityKeyPair *libsignalgo.IdentityKeyPair
	if uuidKind == types.UUID_KIND_ACI {
		identityKeyPair = device.Data.AciIdentityKeyPair
	} else {
		identityKeyPair = device.Data.PniIdentityKeyPair
	}
	signedPreKey := GenerateSignedPreKey(0, uuidKind, identityKeyPair)
	device.PreKeyStore.SaveSignedPreKey(uuidKind, signedPreKey, false)

	// Register prekeys
	identityKey, err := identityKeyPair.GetPublicKey().Serialize()
	if err != nil {
		log.Fatalf("Error serializing identity key: %v", err)
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
		log.Printf("RegisterPreKeys error: %v", err)
		return err
	}

	// Mark prekeys as registered
	lastPreKeyId, err := (*preKeys)[len(*preKeys)-1].GetID()
	err = device.PreKeyStore.MarkPreKeysAsUploaded(uuidKind, lastPreKeyId)
	signedId, err := signedPreKey.GetID()
	err = device.PreKeyStore.MarkSignedPreKeysAsUploaded(uuidKind, signedId)

	return err
}

func GeneratePreKeys(startKeyId uint32, count uint32, uuidKind types.UUIDKind) *[]libsignalgo.PreKeyRecord {
	generatedPreKeys := []libsignalgo.PreKeyRecord{}
	for i := startKeyId; i < startKeyId+count; i++ {
		privateKey, err := libsignalgo.GeneratePrivateKey()
		if err != nil {
			log.Fatalf("Error generating private key: %v", err)
		}
		preKey, err := libsignalgo.NewPreKeyRecordFromPrivateKey(i, privateKey)
		if err != nil {
			log.Fatalf("Error creating preKey record: %v", err)
		}
		generatedPreKeys = append(generatedPreKeys, *preKey)
	}

	return &generatedPreKeys
}

func GenerateSignedPreKey(startSignedKeyId uint32, uuidKind types.UUIDKind, identityKeyPair *libsignalgo.IdentityKeyPair) *libsignalgo.SignedPreKeyRecord {
	// Generate a signed prekey
	privateKey, err := libsignalgo.GeneratePrivateKey()
	if err != nil {
		log.Fatalf("Error generating private key: %v", err)
	}
	timestamp := time.Now()
	publicKey, err := privateKey.GetPublicKey()
	if err != nil {
		log.Fatalf("Error getting public key: %v", err)
	}
	serialized_public_key, err := publicKey.Serialize()
	if err != nil {
		log.Fatalf("Error serializing public key: %v", err)
	}
	signature, err := identityKeyPair.GetPrivateKey().Sign(serialized_public_key)
	if err != nil {
		log.Fatalf("Error signing public key: %v", err)
	}
	signedPreKey, err := libsignalgo.NewSignedPreKeyRecordFromPrivateKey(startSignedKeyId, timestamp, privateKey, signature)

	return signedPreKey
}

func RegisterPreKeys(generatedPreKeys *GeneratedPreKeys, uuidKind types.UUIDKind, username string, password string) error {
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
	keysPath := web.HTTPKeysPath + "?identity=" + string(uuidKind)
	jsonBytes, err := json.Marshal(register_json)
	if err != nil {
		log.Printf("Error marshalling register JSON: %v", err)
		return err
	}
	resp, err := web.SendHTTPRequest("PUT", keysPath, jsonBytes, &username, &password)
	if err != nil {
		log.Fatalf("Error sending request: %v", err)
	}
	defer resp.Body.Close()
	return err
}
