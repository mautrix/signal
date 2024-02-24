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
	"github.com/rs/zerolog"

	"go.mau.fi/mautrix-signal/pkg/libsignalgo"
	"go.mau.fi/mautrix-signal/pkg/signalmeow/types"
	"go.mau.fi/mautrix-signal/pkg/signalmeow/web"
)

type Capabilities struct {
	SenderKey         bool `json:"senderKey"`
	AnnouncementGroup bool `json:"announcementGroup"`
	ChangeNumber      bool `json:"changeNumber"`
	Stories           bool `json:"stories"`
	GiftBadges        bool `json:"giftBadges"`
	PaymentActivation bool `json:"paymentActivation"`
	PNI               bool `json:"pni"`
	Gv1Migration      bool `json:"gv1-migration"`
}

type ProfileResponse struct {
	UUID uuid.UUID `json:"uuid"`

	Name       []byte `json:"name"`
	About      []byte `json:"about"`
	AboutEmoji []byte `json:"aboutEmoji"`
	Avatar     string `json:"avatar"`

	Capabilities Capabilities `json:"capabilities"`

	Credential         []byte `json:"credential"`
	IdentityKey        []byte `json:"identityKey"`
	UnidentifiedAccess []byte `json:"unidentifiedAccess"`

	UnrestrictedUnidentifiedAccess bool `json:"UnrestrictedUnidentifiedAccess"`

	//Badges             []any  `json:"badges"`
	//PhoneNumberSharing []byte `json:"phoneNumberSharing"`
	//PaymentAddress     []byte `json:"paymentAddress"`
}

type ProfileCache struct {
	profiles    map[string]*types.Profile
	errors      map[string]*error
	lastFetched map[string]time.Time
}

func (cli *Client) ProfileKeyCredentialRequest(ctx context.Context, signalACI uuid.UUID) ([]byte, error) {
	profileKey, err := cli.ProfileKeyForSignalID(ctx, signalACI)
	if err != nil {
		return nil, fmt.Errorf("error getting profile key for ACI: %w", err)
	}
	requestContext, err := libsignalgo.CreateProfileKeyCredentialRequestContext(
		prodServerPublicParams,
		signalACI,
		*profileKey,
	)
	if err != nil {
		return nil, fmt.Errorf("error creating profile key credential request context: %w", err)
	}

	request, err := requestContext.ProfileKeyCredentialRequestContextGetRequest()
	if err != nil {
		return nil, fmt.Errorf("error getting profile key credential request: %w", err)
	}

	// convert request bytes to hexidecimal representation
	hexRequest := hex.EncodeToString(request[:])
	return []byte(hexRequest), nil
}

func (cli *Client) ProfileKeyForSignalID(ctx context.Context, signalACI uuid.UUID) (*libsignalgo.ProfileKey, error) {
	profileKey, err := cli.Store.ProfileKeyStore.LoadProfileKey(ctx, signalACI)
	if err != nil {
		return nil, fmt.Errorf("error getting profile key: %w", err)
	}
	return profileKey, nil
}

var errProfileKeyNotFound = errors.New("profile key not found")

func (cli *Client) RetrieveProfileByID(ctx context.Context, signalID uuid.UUID) (*types.Profile, error) {
	if cli.ProfileCache == nil {
		cli.ProfileCache = &ProfileCache{
			profiles:    make(map[string]*types.Profile),
			errors:      make(map[string]*error),
			lastFetched: make(map[string]time.Time),
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
		// TODO this check is wrong and most likely doesn't work, errors shouldn't use string comparisons
		// If we get a 401 or 5xx error, we should not retry until the cache expires
		if strings.HasPrefix(err.Error(), "401") || strings.HasPrefix(err.Error(), "5") {
			cli.ProfileCache.errors[signalID.String()] = &err
			cli.ProfileCache.lastFetched[signalID.String()] = time.Now()
		}
		return nil, err
	}

	// If we get here, we have a valid profile, so cache it
	cli.ProfileCache.profiles[signalID.String()] = profile
	cli.ProfileCache.lastFetched[signalID.String()] = time.Now()

	return profile, nil
}

func (cli *Client) fetchProfileByID(ctx context.Context, signalID uuid.UUID) (*types.Profile, error) {
	log := zerolog.Ctx(ctx)
	profileKey, err := cli.ProfileKeyForSignalID(ctx, signalID)
	if err != nil {
		return nil, fmt.Errorf("error getting profile key: %w", err)
	} else if profileKey == nil {
		return nil, errProfileKeyNotFound
	}

	profileKeyVersion, err := profileKey.GetProfileKeyVersion(signalID)
	if err != nil {
		return nil, fmt.Errorf("error getting profile key version: %w", err)
	}

	accessKey, err := profileKey.DeriveAccessKey()
	if err != nil {
		return nil, fmt.Errorf("error deriving access key: %w", err)
	}
	base64AccessKey := base64.StdEncoding.EncodeToString(accessKey[:])

	credentialRequest, err := cli.ProfileKeyCredentialRequest(ctx, signalID)
	if err != nil {
		return nil, fmt.Errorf("error getting profile key credential request: %w", err)
	}

	path := "/v1/profile/" + signalID.String()
	useUnidentified := profileKeyVersion != nil && accessKey != nil
	if useUnidentified {
		log.Trace().
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
		return nil, fmt.Errorf("error sending request: %w", err)
	}
	var profile types.Profile
	profile.FetchedAt = time.Now()
	logEvt := log.Trace().Uint32("status_code", resp.GetStatus())
	if logEvt.Enabled() {
		if json.Valid(resp.Body) {
			logEvt.RawJSON("response_data", resp.Body)
		} else {
			logEvt.Str("invalid_response_data", base64.StdEncoding.EncodeToString(resp.Body))
		}
	}
	logEvt.Msg("Got profile response")
	if *resp.Status < 200 || *resp.Status >= 300 {
		return nil, fmt.Errorf("error getting profile (unsuccessful status code %d)", *resp.Status)
	}
	var profileResponse ProfileResponse
	err = json.Unmarshal(resp.Body, &profileResponse)
	if err != nil {
		return nil, fmt.Errorf("error unmarshalling profile response: %w", err)
	}
	if len(profileResponse.Name) > 0 {
		profile.Name, err = decryptString(profileKey, profileResponse.Name)
		if err != nil {
			return nil, fmt.Errorf("error decrypting profile name: %w", err)
		}
		// TODO store first and last name separately instead of removing the separator
		profile.Name = strings.ReplaceAll(profile.Name, "\x00", " ")
	}
	if len(profileResponse.About) > 0 {
		profile.About, err = decryptString(profileKey, profileResponse.About)
		if err != nil {
			return nil, fmt.Errorf("error decrypting profile about: %w", err)
		}
	}
	if len(profileResponse.AboutEmoji) > 0 {
		profile.AboutEmoji, err = decryptString(profileKey, profileResponse.AboutEmoji)
		if err != nil {
			return nil, fmt.Errorf("error decrypting profile aboutEmoji: %w", err)
		}
	}
	// TODO store other metadata fields?
	profile.AvatarPath = profileResponse.Avatar
	profile.Key = *profileKey

	return &profile, nil
}

func (cli *Client) DownloadUserAvatar(ctx context.Context, avatarPath string, profileKey libsignalgo.ProfileKey) ([]byte, error) {
	username, password := cli.Store.BasicAuthCreds()
	opts := &web.HTTPReqOpt{
		Host:     web.CDN1Hostname,
		Username: &username,
		Password: &password,
	}
	resp, err := web.SendHTTPRequest(ctx, http.MethodGet, avatarPath, opts)
	if err != nil {
		return nil, fmt.Errorf("failed to send request: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return nil, fmt.Errorf("unexpected response status %d", resp.StatusCode)
	}
	encryptedAvatar, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("failed to read response body: %w", err)
	}
	avatar, err := decryptBytes(profileKey[:], encryptedAvatar)
	if err != nil {
		return nil, fmt.Errorf("failed to decrypt response: %w", err)
	}
	return avatar, nil
}

func decryptBytes(key []byte, encryptedText []byte) ([]byte, error) {
	if len(encryptedText) < NONCE_LENGTH+16+1 {
		return nil, errors.New("invalid encryptedBytes length")
	}
	nonce := encryptedText[:NONCE_LENGTH]
	ciphertext := encryptedText[NONCE_LENGTH:]
	padded, err := AesgcmDecrypt(key, nonce, ciphertext, []byte{})
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

func decryptString(key *libsignalgo.ProfileKey, encryptedText []byte) (string, error) {
	data, err := decryptBytes(key[:], encryptedText)
	return string(data), err
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
