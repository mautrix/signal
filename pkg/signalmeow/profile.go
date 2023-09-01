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
	"fmt"
	"io"
	"strings"
	"time"

	"go.mau.fi/mautrix-signal/pkg/libsignalgo"
	"go.mau.fi/mautrix-signal/pkg/signalmeow/web"
)

type ProfileName struct {
	GivenName  string
	FamilyName *string
}
type Profile struct {
	Name        string
	About       string
	AboutEmoji  string
	Avatar      string
	AvatarImage []byte
}

func ProfileKeyCredentialRequest(ctx context.Context, d *Device, signalId string) ([]byte, error) {
	profileKey, err := ProfileKeyForSignalID(ctx, d, signalId)
	if err != nil {
		zlog.Err(err).Msg("ProfileKey error")
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
		zlog.Err(err).Msg("CreateProfileKeyCredentialRequestContext error")
		return nil, err
	}

	request, err := requestContext.ProfileKeyCredentialRequestContextGetRequest()
	if err != nil {
		zlog.Err(err).Msg("CreateProfileKeyCredentialRequest error")
		return nil, err
	}

	// convert request bytes to hexidecimal representation
	hexRequest := hex.EncodeToString(request[:])
	return []byte(hexRequest), nil
}

func ProfileKeyForSignalID(ctx context.Context, d *Device, signalId string) (*libsignalgo.ProfileKey, error) {
	profileKey, err := d.ProfileKeyStore.LoadProfileKey(signalId, ctx)
	if err != nil {
		zlog.Err(err).Msg("GetProfileKey error")
		return nil, err
	}
	return profileKey, nil
}

var errProfileKeyNotFound = errors.New("profile key not found")

func RetrieveProfileByID(ctx context.Context, d *Device, signalID string) (*Profile, error) {
	if d.Connection.ProfileCache == nil {
		d.Connection.ProfileCache = &ProfileCache{
			profiles:    make(map[string]*Profile),
			errors:      make(map[string]*error),
			lastFetched: make(map[string]time.Time),
		}
	}

	lastFetched, ok := d.Connection.ProfileCache.lastFetched[string(signalID)]
	if ok && time.Since(lastFetched) < 1*time.Hour {
		profile, ok := d.Connection.ProfileCache.profiles[string(signalID)]
		if ok {
			return profile, nil
		}
		err, ok := d.Connection.ProfileCache.errors[string(signalID)]
		if ok {
			return nil, *err
		}
	}
	profile, err := fetchProfileByID(ctx, d, signalID)
	if err != nil {
		// If we get a 401 or 5xx error, we should not retry until the cache expires
		if strings.HasPrefix(err.Error(), "401") || strings.HasPrefix(err.Error(), "5") {
			d.Connection.ProfileCache.errors[string(signalID)] = &err
			d.Connection.ProfileCache.lastFetched[string(signalID)] = time.Now()
		}
		return nil, err
	}
	if profile == nil {
		return nil, errProfileKeyNotFound
	}
	d.Connection.ProfileCache.profiles[string(signalID)] = profile
	d.Connection.ProfileCache.lastFetched[string(signalID)] = time.Now()
	return profile, nil
}

type ProfileCache struct {
	profiles    map[string]*Profile
	errors      map[string]*error
	lastFetched map[string]time.Time
}

func fetchProfileByID(ctx context.Context, d *Device, signalID string) (*Profile, error) {
	profileKey, err := ProfileKeyForSignalID(ctx, d, signalID)
	if err != nil {
		zlog.Err(err).Msg("ProfileKey error")
		return nil, err
	}
	if profileKey == nil {
		zlog.Err(err).Msg("profileKey is nil")
		return nil, nil
	}
	uuid, err := convertUUIDToByteUUID(signalID)
	if err != nil {
		zlog.Err(err).Msg("UUIDFromString error")
		return nil, err
	}

	profileKeyVersion, err := profileKey.GetProfileKeyVersion(*uuid)
	if err != nil {
		zlog.Err(err).Msg("profileKey error")
		return nil, err
	}

	accessKey, err := profileKey.DeriveAccessKey()
	if err != nil {
		zlog.Err(err).Msg("DeriveAccessKey error")
		return nil, err
	}
	base64AccessKey := base64.StdEncoding.EncodeToString(accessKey[:])

	credentialRequest, err := ProfileKeyCredentialRequest(ctx, d, signalID)
	if err != nil {
		zlog.Err(err).Msg("ProfileKeyCredentialRequest error")
		return nil, err
	}

	path := "/v1/profile/" + signalID
	useUnidentified := profileKeyVersion != nil && accessKey != nil
	if useUnidentified {
		zlog.Trace().Msgf("Using unidentified profile request with profileKeyVersion: %v", profileKeyVersion)
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
	}
	respChan, err := d.Connection.UnauthedWS.SendRequest(ctx, profileRequest)
	if err != nil {
		zlog.Err(err).Msg("SendRequest error")
		return nil, err
	}
	zlog.Trace().Msg("Waiting for profile response")
	resp := <-respChan
	zlog.Trace().Msg("Got profile response")
	if *resp.Status < 200 || *resp.Status >= 300 {
		err := errors.New(fmt.Sprintf("%v (unsuccessful status code)", *resp.Status))
		zlog.Err(err).Msg("profile response error")
		return nil, err
	}
	var profile Profile
	err = json.Unmarshal(resp.Body, &profile)
	if err != nil {
		zlog.Err(err).Msg("json.Unmarshal error")
		return nil, err
	}
	if profile.Name != "" {
		base64Name, err := base64.StdEncoding.DecodeString(profile.Name)
		decryptedName, err := decryptString(*profileKey, base64Name)
		if err != nil {
			zlog.Err(err).Msg("error decrypting profile name")
			profile.Name = ""
		}
		profile.Name = *decryptedName
		// I've seen profile names come in with a null byte instead of a space
		// between first and last names, so replace any null bytes with spaces
		profile.Name = strings.Replace(profile.Name, "\x00", " ", -1)
	}
	if profile.About != "" {
		base64About, err := base64.StdEncoding.DecodeString(profile.About)
		decryptedAbout, err := decryptString(*profileKey, base64About)
		if err != nil {
			zlog.Err(err).Msg("error decrypting profile about")
			profile.About = ""
		}
		profile.About = *decryptedAbout
	}
	if profile.AboutEmoji != "" {
		base64AboutEmoji, err := base64.StdEncoding.DecodeString(profile.AboutEmoji)
		decryptedAboutEmoji, err := decryptString(*profileKey, base64AboutEmoji)
		if err != nil {
			zlog.Err(err).Msg("error decrypting profile aboutEmoji")
			profile.AboutEmoji = ""
		}
		profile.AboutEmoji = *decryptedAboutEmoji
	}
	if profile.Avatar != "" {
		username, password := d.Data.BasicAuthCreds()
		opts := &web.HTTPReqOpt{
			Host:     web.CDNUrlHost, // I guess don't use CDN2 for profiles?
			Username: &username,
			Password: &password,
		}
		resp, err := web.SendHTTPRequest("GET", profile.Avatar, opts)
		if err != nil {
			zlog.Err(err).Msg("error fetching profile avatar")
			profile.Avatar = ""
		}
		if resp.StatusCode < 200 || resp.StatusCode >= 300 {
			err := errors.New(fmt.Sprintf("%v (unsuccessful status code)", resp.Status))
			zlog.Err(err).Msg("error fetching profile avatar")
			profile.Avatar = ""
		}
		encryptedAvatar, err := io.ReadAll(resp.Body)
		if err != nil {
			zlog.Err(err).Msg("error reading profile avatar")
			profile.Avatar = ""
		}
		avatar, err := decryptBytes(*profileKey, encryptedAvatar)
		if err != nil {
			zlog.Err(err).Msg("error decrypting profile avatar")
			profile.Avatar = ""
		}
		profile.AvatarImage = avatar
	}

	return &profile, nil
}

func decryptBytes(key libsignalgo.ProfileKey, encryptedBytes []byte) ([]byte, error) {
	if len(encryptedBytes) < NONCE_LENGTH+16+1 {
		return nil, errors.New("invalid encryptedBytes length")
	}
	nonce := encryptedBytes[:NONCE_LENGTH]
	ciphertext := encryptedBytes[NONCE_LENGTH:]
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
	returnString := padded[:plaintextLength]
	return returnString, nil
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
