package signalmeow

import (
	"encoding/base64"
	"encoding/json"
	"log"
	"time"

	"go.mau.fi/mautrix-signal/pkg/libsignalgo"
)

type GeneratedPreKeys struct {
	PreKeys      []*libsignalgo.PreKeyRecord
	SignedPreKey *libsignalgo.SignedPreKeyRecord
	IdentityKey  []uint8
}

func GenerateAndRegisterPreKeys() error {
	return nil
}

func GeneratePreKeys(startKeyId uint32, startSignedKeyId uint32, count uint32, identityKeyPair *libsignalgo.IdentityKeyPair, uuidKind string) *GeneratedPreKeys {
	// Generate n prekeys
	generatedPreKeys := &GeneratedPreKeys{}
	for i := startKeyId; i < startKeyId+count; i++ {
		privateKey, err := libsignalgo.GeneratePrivateKey()
		if err != nil {
			log.Fatalf("Error generating private key: %v", err)
		}
		preKey, err := libsignalgo.NewPreKeyRecordFromPrivateKey(i, privateKey)
		if err != nil {
			log.Fatalf("Error creating preKey record: %v", err)
		}
		generatedPreKeys.PreKeys = append(generatedPreKeys.PreKeys, preKey)
	}

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
	generatedPreKeys.SignedPreKey = &libsignalgo.SignedPreKeyRecord{}
	generatedPreKeys.SignedPreKey, err = libsignalgo.NewSignedPreKeyRecordFromPrivateKey(startSignedKeyId, timestamp, privateKey, signature)

	// Save identity key
	identityKey, err := identityKeyPair.GetPublicKey().Serialize()
	if err != nil {
		log.Fatalf("Error serializing identity key: %v", err)
	}
	generatedPreKeys.IdentityKey = identityKey

	return generatedPreKeys
}

func RegisterPreKeys(generatedPreKeys *GeneratedPreKeys, uuidKind string, username string, password string) error {
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
	keysUrl := "https://chat.signal.org/v2/keys?identity=" + uuidKind
	jsonBytes, err := json.Marshal(register_json)
	if err != nil {
		log.Printf("Error marshalling register JSON: %v", err)
		return err
	}
	resp, err := sendHTTPRequest("PUT", keysUrl, jsonBytes, &username, &password)
	if err != nil {
		log.Fatalf("Error sending request: %v", err)
	}
	defer resp.Body.Close()
	return err
}
