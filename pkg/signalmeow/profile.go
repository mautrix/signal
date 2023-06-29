package signalmeow

import (
	"context"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"log"

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
	var uuidBytes libsignalgo.UUID
	copy(uuidBytes[:], d.Data.AciUuid)
	var serverPublicParamsBytes libsignalgo.ServerPublicParams
	copy(serverPublicParamsBytes[:], serverPublicParams)

	requestContext, err := libsignalgo.CreateProfileKeyCredentialRequestContext(
		serverPublicParamsBytes,
		uuidBytes,
		*profileKey,
	)
	if err != nil {
		log.Printf("CreateProfileKeyCredentialRequestContext error: %v", err)
		return nil, err
	}
	log.Printf("requestContext: %v", requestContext)

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

func RetrieveProfileById(ctx context.Context, d *store.Device, address string) (*Profile, error) {
	profileKey, err := ProfileKeyForSignalID(ctx, d, address)
	if err != nil {
		log.Printf("MyProfileKey error: %v", err)
		return nil, err
	}
	log.Printf("profileKey: %v", profileKey)
	var uuidBytes libsignalgo.UUID
	copy(uuidBytes[:], d.Data.AciUuid)

	profileKeyVersion, err := profileKey.GetProfileKeyVersion(uuidBytes)
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

	credentialRequest, err := ProfileKeyCredentialRequest(ctx, d, address)
	if err != nil {
		log.Printf("ProfileKeyCredentialRequest error: %v", err)
		return nil, err
	}

	path := "/v1/profile/" + address
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
	log.Printf("path: %v", path)
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
