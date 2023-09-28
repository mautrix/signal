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

type ProfileResponse struct {
	Name       string
	About      string
	AboutEmoji string
	Avatar     string
}

type Profile struct {
	Name       string
	About      string
	AboutEmoji string
	AvatarPath string
	Key        libsignalgo.ProfileKey
}

type ProfileCache struct {
	profiles    map[string]*Profile
	errors      map[string]*error
	lastFetched map[string]time.Time
	avatarPaths map[string]string
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
			avatarPaths: make(map[string]string),
		}
	}

	// Check if we have a cached profile that is less than an hour old
	// or if we have a cached error that is less than an hour old
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

	// If we get here, we don't have a cached profile, so fetch it
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

	// If we get here, we have a valid profile, so cache it
	d.Connection.ProfileCache.profiles[string(signalID)] = profile
	d.Connection.ProfileCache.lastFetched[string(signalID)] = time.Now()

	return profile, nil
}

func RetrieveProfileAndAvatarByID(ctx context.Context, d *Device, signalID string) (*Profile, []byte, error) {
	profile, err := RetrieveProfileByID(ctx, d, signalID)
	if err != nil {
		return nil, nil, err
	}

	// If there is an avatarPath, and it's different from the cached one, fetch it
	// (we only return the avatar if it's different from the cached one)
	var avatarImage []byte
	cachedAvatarPath, _ := d.Connection.ProfileCache.avatarPaths[string(signalID)]
	if profile.AvatarPath != "" && cachedAvatarPath != profile.AvatarPath {
		avatarImage, err = fetchAndDecryptAvatarImage(d, profile.AvatarPath, &profile.Key)
		if err != nil {
			zlog.Err(err).Msg("error fetching profile avatarImage")
			return nil, nil, err
		}
	}
	d.Connection.ProfileCache.avatarPaths[string(signalID)] = profile.AvatarPath

	return profile, avatarImage, nil
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
	resp, err := d.Connection.UnauthedWS.SendRequest(ctx, profileRequest)
	if err != nil {
		zlog.Err(err).Msg("SendRequest error")
		return nil, err
	}
	zlog.Trace().Msg("Got profile response")
	if *resp.Status < 200 || *resp.Status >= 300 {
		err := errors.New(fmt.Sprintf("%v (unsuccessful status code)", *resp.Status))
		zlog.Err(err).Msg("profile response error")
		return nil, err
	}
	var profileResponse ProfileResponse
	var profile Profile
	err = json.Unmarshal(resp.Body, &profileResponse)
	if err != nil {
		zlog.Err(err).Msg("json.Unmarshal error")
		return nil, err
	}
	if profileResponse.Name != "" {
		base64Name, err := base64.StdEncoding.DecodeString(profileResponse.Name)
		decryptedName, err := decryptString(*profileKey, base64Name)
		if err != nil {
			zlog.Err(err).Msg("error decrypting profile name")
		}
		profile.Name = *decryptedName
		// I've seen profile names come in with a null byte instead of a space
		// between first and last names, so replace any null bytes with spaces
		profile.Name = strings.Replace(profile.Name, "\x00", " ", -1)
	}
	if profileResponse.About != "" {
		base64About, err := base64.StdEncoding.DecodeString(profileResponse.About)
		decryptedAbout, err := decryptString(*profileKey, base64About)
		if err != nil {
			zlog.Err(err).Msg("error decrypting profile about")
		}
		profile.About = *decryptedAbout
	}
	if profileResponse.AboutEmoji != "" {
		base64AboutEmoji, err := base64.StdEncoding.DecodeString(profileResponse.AboutEmoji)
		decryptedAboutEmoji, err := decryptString(*profileKey, base64AboutEmoji)
		if err != nil {
			zlog.Err(err).Msg("error decrypting profile aboutEmoji")
		}
		profile.AboutEmoji = *decryptedAboutEmoji
	}
	profile.AvatarPath = profileResponse.Avatar
	profile.Key = *profileKey

	return &profile, nil
}

func fetchAndDecryptAvatarImage(d *Device, avatarPath string, profileKey *libsignalgo.ProfileKey) ([]byte, error) {
	username, password := d.Data.BasicAuthCreds()
	opts := &web.HTTPReqOpt{
		Host:     web.CDNUrlHost, // I guess don't use CDN2 for profiles?
		Username: &username,
		Password: &password,
	}
	zlog.Info().Msgf("Fetching profile avatar from %v", avatarPath)
	resp, err := web.SendHTTPRequest("GET", avatarPath, opts)
	if err != nil {
		zlog.Err(err).Msg("error fetching profile avatar")
		return nil, err
	}
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		err := errors.New(fmt.Sprintf("%v (unsuccessful status code)", resp.Status))
		zlog.Err(err).Msg("bad status fetching profile avatar")
		return nil, err
	}
	encryptedAvatar, err := io.ReadAll(resp.Body)
	if err != nil {
		zlog.Err(err).Msg("error reading profile avatar")
		return nil, err
	}
	avatar, err := decryptBytes(*profileKey, encryptedAvatar)
	if err != nil {
		zlog.Err(err).Msg("error decrypting profile avatar")
		return nil, err
	}
	return avatar, nil
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
