package signalmeow

import (
	"context"
	"encoding/base64"
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
	var uuidBytes [16]byte
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

	path := "/v1/profile/" + address
	useUnidentified := profileKeyVersion != nil && accessKey != nil
	if useUnidentified {
		log.Printf("Using unidentified profile request with profileKeyVersion: %v, accessKey: %v", profileKeyVersion, accessKey)
		// Assuming we can just make the version bytes into a string
		path += "/" + profileKeyVersion.String()
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
		log.Printf("headers: %v", profileRequest.Headers)
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
