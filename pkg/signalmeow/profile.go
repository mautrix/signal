package signalmeow

import (
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"log"
	"time"

	"go.mau.fi/mautrix-signal/pkg/libsignalgo"
	"go.mau.fi/mautrix-signal/pkg/signalmeow/web"
)

type ProfileName struct {
	GivenName  string
	FamilyName *string
}
type Profile struct {
	Name       string
	About      string
	AboutEmoji string
}

func ProfileKeyCredentialRequest(ctx context.Context, d *Device, signalId string) ([]byte, error) {
	profileKey, err := ProfileKeyForSignalID(ctx, d, signalId)
	if err != nil {
		log.Printf("ProfileKey error: %v", err)
		return nil, err
	}
	uuid, err := convertUUIDToByteUUID(signalId)
	serverPublicParams := serverPublicParams()

	requestContext, err := libsignalgo.CreateProfileKeyCredentialRequestContext(
		serverPublicParams,
		*uuid,
		*profileKey,
	)
	if err != nil {
		log.Printf("CreateProfileKeyCredentialRequestContext error: %v", err)
		return nil, err
	}

	request, err := requestContext.ProfileKeyCredentialRequestContextGetRequest()
	if err != nil {
		log.Printf("CreateProfileKeyCredentialRequest error: %v", err)
		return nil, err
	}

	// convert request bytes to hexidecimal representation
	hexRequest := hex.EncodeToString(request[:])
	return []byte(hexRequest), nil
}

func ProfileKeyForSignalID(ctx context.Context, d *Device, signalId string) (*libsignalgo.ProfileKey, error) {
	profileKeyStore := d.ProfileKeyStore
	profileKey, err := profileKeyStore.LoadProfileKey(signalId, ctx)
	if err != nil {
		log.Printf("GetProfileKey error: %v", err)
		return nil, err
	}
	return profileKey, nil
}

func RetrieveProfileByID(ctx context.Context, d *Device, signalID string) (*Profile, error) {
	if d.Connection.ProfileCache == nil {
		d.Connection.ProfileCache = &ProfileCache{
			profiles:    make(map[string]*Profile),
			lastFetched: make(map[string]time.Time),
		}
	}

	lastFetched, ok := d.Connection.ProfileCache.lastFetched[string(signalID)]
	if ok && time.Since(lastFetched) < 1*time.Hour {
		group, ok := d.Connection.ProfileCache.profiles[string(signalID)]
		if ok {
			return group, nil
		}
	}
	group, err := fetchProfileByID(ctx, d, signalID)
	if err != nil {
		return nil, err
	}
	d.Connection.ProfileCache.profiles[string(signalID)] = group
	d.Connection.ProfileCache.lastFetched[string(signalID)] = time.Now()
	return group, nil
}

type ProfileCache struct {
	profiles    map[string]*Profile
	lastFetched map[string]time.Time
}

func fetchProfileByID(ctx context.Context, d *Device, signalID string) (*Profile, error) {
	profileKey, err := ProfileKeyForSignalID(ctx, d, signalID)
	if err != nil {
		log.Printf("ProfileKey error: %v", err)
		return nil, err
	}
	if profileKey == nil {
		log.Printf("profileKey is nil")
		return nil, nil
	}
	log.Printf("profileKey: %v", profileKey)
	uuid, err := convertUUIDToByteUUID(signalID)
	if err != nil {
		log.Printf("UUIDFromString error: %v", err)
		return nil, err
	}
	log.Printf("signalID: %v", signalID)

	profileKeyVersion, err := profileKey.GetProfileKeyVersion(*uuid)
	if err != nil {
		log.Printf("profileKey error: %v", err)
		return nil, err
	}

	accessKey, err := profileKey.DeriveAccessKey()
	if err != nil {
		log.Printf("DeriveAccessKey error: %v", err)
		return nil, err
	}
	base64AccessKey := base64.StdEncoding.EncodeToString(accessKey[:])

	credentialRequest, err := ProfileKeyCredentialRequest(ctx, d, signalID)
	if err != nil {
		log.Printf("ProfileKeyCredentialRequest error: %v", err)
		return nil, err
	}

	path := "/v1/profile/" + signalID
	useUnidentified := profileKeyVersion != nil && accessKey != nil
	if useUnidentified {
		log.Printf("Using unidentified profile request with profileKeyVersion: %v, accessKey: %v", profileKeyVersion, accessKey)
		// Assuming we can just make the version bytes into a string
		path += "/" + profileKeyVersion.String()
	}
	if credentialRequest != nil {
		path += "/" + string(credentialRequest)
		path += "?credentialType=expiringProfileKey"
	}
	profileRequest := web.CreateWSRequest(
		"GET",
		path,
		nil,
		nil,
		nil,
	)
	if useUnidentified {
		profileRequest.Headers = append(profileRequest.Headers, "unidentified-access-key:"+base64AccessKey)
		profileRequest.Headers = append(profileRequest.Headers, "accept-language:en-CA")
		log.Printf("headers: %v", profileRequest.Headers)
	}
	log.Printf("Sending profileRequest: %v", profileRequest)
	respChan, err := d.Connection.UnauthedWS.SendRequest(ctx, profileRequest)
	if err != nil {
		log.Printf("SendRequest error: %v", err)
		return nil, err
	}
	log.Printf("Waiting for profile response")
	resp := <-respChan
	log.Printf("Got profile response: %v", resp)
	if *resp.Status != 200 {
		log.Printf("resp.StatusCode: %v", resp.Status)
		return nil, errors.New("bad status code")
	}
	var profile Profile
	err = json.Unmarshal(resp.Body, &profile)
	if err != nil {
		log.Printf("json.Unmarshal error: %v", err)
		return nil, err
	}
	log.Printf("profile: %v", profile)
	if profile.Name != "" {
		base64Name, err := base64.StdEncoding.DecodeString(profile.Name)
		decryptedName, err := decryptString(*profileKey, base64Name)
		if err != nil {
			log.Printf("error decrypting profile name: %v", err)
			profile.Name = ""
		}
		profile.Name = *decryptedName
		log.Printf("decryptedName: %v", *decryptedName)
	}
	if profile.About != "" {
		base64About, err := base64.StdEncoding.DecodeString(profile.About)
		decryptedAbout, err := decryptString(*profileKey, base64About)
		if err != nil {
			log.Printf("error decrypting profile about: %v", err)
			profile.About = ""
		}
		profile.About = *decryptedAbout
		log.Printf("decryptedAbout: %v", *decryptedAbout)
	}
	if profile.AboutEmoji != "" {
		base64AboutEmoji, err := base64.StdEncoding.DecodeString(profile.AboutEmoji)
		decryptedAboutEmoji, err := decryptString(*profileKey, base64AboutEmoji)
		if err != nil {
			log.Printf("error decrypting profile aboutEmoji: %v", err)
			profile.AboutEmoji = ""
		}
		profile.AboutEmoji = *decryptedAboutEmoji
		log.Printf("decryptedAboutEmoji: %v", *decryptedAboutEmoji)
	}

	return &profile, nil
}

func decryptString(key libsignalgo.ProfileKey, encryptedText []byte) (*string, error) {
	if len(encryptedText) < NONCE_LENGTH+16+1 {
		return nil, errors.New("invalid encryptedText length")
	}
	nonce := encryptedText[:NONCE_LENGTH]
	ciphertext := encryptedText[NONCE_LENGTH:]
	keyBytes := key[:]
	padded, err := AesgcmDecrypt(keyBytes, nonce, ciphertext, []byte{})
	if err != nil {
		return nil, err
	}
	paddedLength := len(padded)
	plaintextLength := 0
	for i := paddedLength - 1; i >= 0; i-- {
		if padded[i] != byte(0) {
			plaintextLength = i + 1
			break
		}
	}
	returnString := string(padded[:plaintextLength])
	return &returnString, nil
}

func encryptString(key libsignalgo.ProfileKey, plaintext string, paddedLength int) ([]byte, error) {
	inputLength := len(plaintext)
	if inputLength > paddedLength {
		return nil, errors.New("plaintext longer than paddedLength")
	}
	padded := append([]byte(plaintext), make([]byte, paddedLength-inputLength)...)
	nonce := make([]byte, NONCE_LENGTH)
	rand.Read(nonce)
	keyBytes := key[:]
	ciphertext, err := AesgcmEncrypt(keyBytes, nonce, padded)
	if err != nil {
		return nil, err
	}
	return append(nonce, ciphertext...), nil
}

const NONCE_LENGTH = 12
const TAG_LENGTH_BYTES = 16

func AesgcmDecrypt(key, nonce, data, mac []byte) ([]byte, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}

	aesgcm, err := cipher.NewGCMWithTagSize(block, TAG_LENGTH_BYTES)
	if err != nil {
		return nil, err
	}
	ciphertext := append(data, mac...)

	return aesgcm.Open(nil, nonce, ciphertext, nil)
}

func AesgcmEncrypt(key, nonce, plaintext []byte) ([]byte, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	aesgcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}
	return aesgcm.Seal(nil, nonce, plaintext, nil), nil
}
