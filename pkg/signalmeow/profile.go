package signalmeow

import (
	"context"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"log"
	"strings"

	"go.mau.fi/mautrix-signal/pkg/libsignalgo"
	"go.mau.fi/mautrix-signal/pkg/signalmeow/store"
	"go.mau.fi/mautrix-signal/pkg/signalmeow/web"
)

type ProfileName struct {
	GivenName  string
	FamilyName *string
}
type Profile struct {
	Name       *ProfileName
	About      *string
	AboutEmoji *string
}

const (
	serverPublicParamsBase64 = "AMhf5ywVwITZMsff/eCyudZx9JDmkkkbV6PInzG4p8x3VqVJSFiMvnvlEKWuRob/1eaIetR31IYeAbm0NdOuHH8Qi+Rexi1wLlpzIo1gstHWBfZzy1+qHRV5A4TqPp15YzBPm0WSggW6PbSn+F4lf57VCnHF7p8SvzAA2ZZJPYJURt8X7bbg+H3i+PEjH9DXItNEqs2sNcug37xZQDLm7X36nOoGPs54XsEGzPdEV+itQNGUFEjY6X9Uv+Acuks7NpyGvCoKxGwgKgE5XyJ+nNKlyHHOLb6N1NuHyBrZrgtY/JYJHRooo5CEqYKBqdFnmbTVGEkCvJKxLnjwKWf+fEPoWeQFj5ObDjcKMZf2Jm2Ae69x+ikU5gBXsRmoF94GXTLfN0/vLt98KDPnxwAQL9j5V1jGOY8jQl6MLxEs56cwXN0dqCnImzVH3TZT1cJ8SW1BRX6qIVxEzjsSGx3yxF3suAilPMqGRp4ffyopjMD1JXiKR2RwLKzizUe5e8XyGOy9fplzhw3jVzTRyUZTRSZKkMLWcQ/gv0E4aONNqs4P"
)

func ProfileKeyCredentialRequest(ctx context.Context, d *store.Device, signalId string) ([]byte, error) {
	serverPublicParams, err := base64.StdEncoding.DecodeString(serverPublicParamsBase64)
	if err != nil {
		log.Printf("DecodeString error: %v", err)
		return nil, err
	}
	profileKey, err := ProfileKeyForSignalID(ctx, d, signalId)
	if err != nil {
		log.Printf("ProfileKey error: %v", err)
		return nil, err
	}
	uuidBytes, err := convertUUIDToBytes(signalId)
	var serverPublicParamsBytes libsignalgo.ServerPublicParams
	copy(serverPublicParamsBytes[:], serverPublicParams)

	requestContext, err := libsignalgo.CreateProfileKeyCredentialRequestContext(
		serverPublicParamsBytes,
		libsignalgo.UUID(uuidBytes),
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

func ProfileKeyForSignalID(ctx context.Context, d *store.Device, signalId string) (*libsignalgo.ProfileKey, error) {
	profileKeyStore := d.ProfileKeyStore
	profileKey, err := profileKeyStore.LoadProfileKey(signalId, ctx)
	if err != nil {
		log.Printf("GetProfileKey error: %v", err)
		return nil, err
	}
	return profileKey, nil
}

func convertUUIDToBytes(uuid string) ([]byte, error) {
	uuid = strings.Replace(uuid, "-", "", -1)
	uuidBytes, err := hex.DecodeString(uuid)
	if err != nil {
		return nil, err
	}
	if len(uuidBytes) != 16 {
		return nil, errors.New("invalid UUID length")
	}
	return uuidBytes, nil
}

func RetrieveProfileById(ctx context.Context, d *store.Device, signalID string) (*Profile, error) {
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
	uuidBytes, err := convertUUIDToBytes(signalID)
	if err != nil {
		log.Printf("UUIDFromString error: %v", err)
		return nil, err
	}
	log.Printf("signalID: %v", signalID)
	log.Printf("uuidBytes: %v", uuidBytes)
	uuid := libsignalgo.UUID(uuidBytes)

	profileKeyVersion, err := profileKey.GetProfileKeyVersion(uuid)
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
	respChan, err := d.Connection.UnauthedWS.SendRequest(ctx, profileRequest, nil, nil)
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
	return &profile, nil
}
