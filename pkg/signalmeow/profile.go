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
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"

	"github.com/google/uuid"

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

func (cli *Client) ProfileKeyCredentialRequest(ctx context.Context, signalACI uuid.UUID) ([]byte, error) {
	profileKey, err := cli.ProfileKeyForSignalID(ctx, signalACI)
	if err != nil {
		zlog.Err(err).Msg("ProfileKey error")
		return nil, err
	}
	serverPublicParams := serverPublicParams()

	requestContext, err := libsignalgo.CreateProfileKeyCredentialRequestContext(
		serverPublicParams,
		signalACI,
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

func (cli *Client) ProfileKeyForSignalID(ctx context.Context, signalACI uuid.UUID) (*libsignalgo.ProfileKey, error) {
	profileKey, err := cli.Store.ProfileKeyStore.LoadProfileKey(ctx, signalACI)
	if err != nil {
		zlog.Err(err).Msg("GetProfileKey error")
		return nil, err
	}
	return profileKey, nil
}

var errProfileKeyNotFound = errors.New("profile key not found")

func (cli *Client) RetrieveProfileByID(ctx context.Context, signalID uuid.UUID) (*Profile, error) {
	if cli.ProfileCache == nil {
		cli.ProfileCache = &ProfileCache{
			profiles:    make(map[string]*Profile),
			errors:      make(map[string]*error),
			lastFetched: make(map[string]time.Time),
			avatarPaths: make(map[string]string),
		}
	}

	// Check if we have a cached profile that is less than an hour old
	// or if we have a cached error that is less than an hour old
	lastFetched, ok := cli.ProfileCache.lastFetched[signalID.String()]
	if ok && time.Since(lastFetched) < 1*time.Hour {
		profile, ok := cli.ProfileCache.profiles[signalID.String()]
		if ok {
			return profile, nil
		}
		err, ok := cli.ProfileCache.errors[signalID.String()]
		if ok {
			return nil, *err
		}
	}

	// If we get here, we don't have a cached profile, so fetch it
	profile, err := cli.fetchProfileByID(ctx, signalID)
	if err != nil {
		// If we get a 401 or 5xx error, we should not retry until the cache expires
		if strings.HasPrefix(err.Error(), "401") || strings.HasPrefix(err.Error(), "5") {
			cli.ProfileCache.errors[signalID.String()] = &err
			cli.ProfileCache.lastFetched[signalID.String()] = time.Now()
		}
		return nil, err
	}
	if profile == nil {
		return nil, errProfileKeyNotFound
	}

	// If we get here, we have a valid profile, so cache it
	cli.ProfileCache.profiles[signalID.String()] = profile
	cli.ProfileCache.lastFetched[signalID.String()] = time.Now()

	return profile, nil
}

func (cli *Client) RetrieveProfileAndAvatarByID(ctx context.Context, signalID uuid.UUID) (*Profile, []byte, error) {
	profile, err := cli.RetrieveProfileByID(ctx, signalID)
	if err != nil {
		return nil, nil, err
	}

	// If there is an avatarPath, and it's different from the cached one, fetch it
	// (we only return the avatar if it's different from the cached one)
	var avatarImage []byte
	cachedAvatarPath, _ := cli.ProfileCache.avatarPaths[signalID.String()]
	if profile.AvatarPath != "" && cachedAvatarPath != profile.AvatarPath {
		avatarImage, err = cli.fetchAndDecryptAvatarImage(profile.AvatarPath, &profile.Key)
		if err != nil {
			zlog.Err(err).Msg("error fetching profile avatarImage")
			return nil, nil, err
		}
	}
	cli.ProfileCache.avatarPaths[signalID.String()] = profile.AvatarPath

	return profile, avatarImage, nil
}

func (cli *Client) fetchProfileByID(ctx context.Context, signalID uuid.UUID) (*Profile, error) {
	profileKey, err := cli.ProfileKeyForSignalID(ctx, signalID)
	if err != nil {
		zlog.Err(err).Msg("ProfileKey error")
		return nil, err
	}
	if profileKey == nil {
		zlog.Err(err).Msg("profileKey is nil")
		return nil, nil
	}

	profileKeyVersion, err := profileKey.GetProfileKeyVersion(signalID)
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

	credentialRequest, err := cli.ProfileKeyCredentialRequest(ctx, signalID)
	if err != nil {
		zlog.Err(err).Msg("ProfileKeyCredentialRequest error")
		return nil, err
	}

	path := "/v1/profile/" + signalID.String()
	useUnidentified := profileKeyVersion != nil && accessKey != nil
	if useUnidentified {
		zlog.Trace().
			Hex("profile_key_version", profileKeyVersion[:]).
			Msg("Using unidentified profile request")
		// Assuming we can just make the version bytes into a string
		path += "/" + profileKeyVersion.String()
	}
	if credentialRequest != nil {
		path += "/" + string(credentialRequest)
		path += "?credentialType=expiringProfileKey"
	}
	profileRequest := web.CreateWSRequest(http.MethodGet, path, nil, nil, nil)
	if useUnidentified {
		profileRequest.Headers = append(profileRequest.Headers, "unidentified-access-key:"+base64AccessKey)
		profileRequest.Headers = append(profileRequest.Headers, "accept-language:en-CA")
	}
	resp, err := cli.UnauthedWS.SendRequest(ctx, profileRequest)
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

func (cli *Client) fetchAndDecryptAvatarImage(avatarPath string, profileKey *libsignalgo.ProfileKey) ([]byte, error) {
	username, password := cli.Store.BasicAuthCreds()
	opts := &web.HTTPReqOpt{
		Host:     web.CDN1Hostname, // I guess don't use CDN2 for profiles?
		Username: &username,
		Password: &password,
	}
	zlog.Info().Str("avatar_path", avatarPath).Msg("Fetching profile avatar")
	resp, err := web.SendHTTPRequest(http.MethodGet, avatarPath, opts)
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
