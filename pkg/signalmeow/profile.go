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
	"io/ioutil"
	"log"
	"strings"
	"time"

	"go.mau.fi/mautrix-signal/pkg/libsignalgo"
	signalpb "go.mau.fi/mautrix-signal/pkg/signalmeow/protobuf"
	"go.mau.fi/mautrix-signal/pkg/signalmeow/store"
	"go.mau.fi/mautrix-signal/pkg/signalmeow/types"
	"go.mau.fi/mautrix-signal/pkg/signalmeow/web"
	"google.golang.org/protobuf/proto"
)

type ProfileName struct {
	GivenName  string
	FamilyName *string
}
type Profile struct {
	Name       *string
	About      *string
	AboutEmoji *string
}

func serverPublicParams() libsignalgo.ServerPublicParams {
	serverPublicParamsBase64 := "AMhf5ywVwITZMsff/eCyudZx9JDmkkkbV6PInzG4p8x3VqVJSFiMvnvlEKWuRob/1eaIetR31IYeAbm0NdOuHH8Qi+Rexi1wLlpzIo1gstHWBfZzy1+qHRV5A4TqPp15YzBPm0WSggW6PbSn+F4lf57VCnHF7p8SvzAA2ZZJPYJURt8X7bbg+H3i+PEjH9DXItNEqs2sNcug37xZQDLm7X36nOoGPs54XsEGzPdEV+itQNGUFEjY6X9Uv+Acuks7NpyGvCoKxGwgKgE5XyJ+nNKlyHHOLb6N1NuHyBrZrgtY/JYJHRooo5CEqYKBqdFnmbTVGEkCvJKxLnjwKWf+fEPoWeQFj5ObDjcKMZf2Jm2Ae69x+ikU5gBXsRmoF94GXTLfN0/vLt98KDPnxwAQL9j5V1jGOY8jQl6MLxEs56cwXN0dqCnImzVH3TZT1cJ8SW1BRX6qIVxEzjsSGx3yxF3suAilPMqGRp4ffyopjMD1JXiKR2RwLKzizUe5e8XyGOy9fplzhw3jVzTRyUZTRSZKkMLWcQ/gv0E4aONNqs4P"
	serverPublicParamsBytes, err := base64.StdEncoding.DecodeString(serverPublicParamsBase64)
	if err != nil {
		panic(err)
	}
	var serverPublicParams libsignalgo.ServerPublicParams
	copy(serverPublicParams[:], serverPublicParamsBytes)
	return serverPublicParams
}

func ProfileKeyCredentialRequest(ctx context.Context, d *store.Device, signalId string) ([]byte, error) {
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

func ProfileKeyForSignalID(ctx context.Context, d *store.Device, signalId string) (*libsignalgo.ProfileKey, error) {
	profileKeyStore := d.ProfileKeyStore
	profileKey, err := profileKeyStore.LoadProfileKey(signalId, ctx)
	if err != nil {
		log.Printf("GetProfileKey error: %v", err)
		return nil, err
	}
	return profileKey, nil
}

func convertUUIDToByteUUID(uuid string) (*libsignalgo.UUID, error) {
	uuid = strings.Replace(uuid, "-", "", -1)
	uuidBytes, err := hex.DecodeString(uuid)
	if err != nil {
		return nil, err
	}
	if len(uuidBytes) != 16 {
		return nil, errors.New("invalid UUID length")
	}
	byteUUID := libsignalgo.UUID(uuidBytes)
	return &byteUUID, nil
}

// TODO move this to a "group" file or something
type Group struct {
	GroupID string
	Name    string
	Members []string
}

type GroupAuth struct {
	Username string
	Password string
}

func fetchNewGroupCreds(ctx context.Context, d *store.Device, today time.Time) (*types.GroupCredentials, error) {
	sevenDaysOut := today.Add(7 * 24 * time.Hour)
	path := fmt.Sprintf("/v1/certificate/auth/group?redemptionStartSeconds=%d&redemptionEndSeconds=%d", today.Unix(), sevenDaysOut.Unix())
	authRequest := web.CreateWSRequest("GET", path, nil, nil, nil)
	respChan, err := d.Connection.AuthedWS.SendRequest(ctx, authRequest)
	if err != nil {
		log.Printf("SendRequest error: %v", err)
		return nil, err
	}
	log.Printf("Waiting for auth credentials response")
	resp := <-respChan
	if *resp.Status != 200 {
		log.Printf("resp.StatusCode: %v", resp.Status)
		return nil, errors.New("bad status code")
	}

	var creds types.GroupCredentials
	err = json.Unmarshal(resp.Body, &creds)
	if err != nil {
		log.Printf("json.Unmarshal error: %v", err)
		return nil, err
	}
	// make sure pni matches device pni
	if creds.Pni != d.Data.PniUuid {
		log.Printf("creds.Pni != d.PniUuid")
		return nil, errors.New("creds.Pni != d.PniUuid")
	}
	return &creds, nil
}

func getCachedAuthorizationForToday(d *store.Device, today time.Time) *types.GroupCredential {
	if d.Connection.GroupCredentials == nil {
		// No cached credentials
		return nil
	}
	allCreds := d.Connection.GroupCredentials
	// Get the credential for today
	for _, cred := range allCreds.Credentials {
		if cred.RedemptionTime == today.Unix() {
			return &cred
		}
	}
	log.Printf("No credential for today")
	return nil
}

func GetAuthorizationForToday(ctx context.Context, d *store.Device, masterKey libsignalgo.GroupMasterKey) (*GroupAuth, error) {
	// Timestamps for the start of today, and 7 days later
	today := time.Now().Truncate(24 * time.Hour)

	todayCred := getCachedAuthorizationForToday(d, today)
	if todayCred == nil {
		creds, err := fetchNewGroupCreds(ctx, d, today)
		if err != nil {
			log.Printf("fetchNewGroupCreds error: %v", err)
			return nil, err
		}
		d.Connection.GroupCredentials = creds
		todayCred = getCachedAuthorizationForToday(d, today)
	}
	if todayCred == nil {
		return nil, errors.New("Couldn't get credential for today")
	}
	log.Printf("todayCred: %v", todayCred)

	//TODO: cache cred after unmarshalling
	redemptionTime := uint64(todayCred.RedemptionTime)
	credential := todayCred.Credential
	authCredentialResponse, err := libsignalgo.NewAuthCredentialWithPniResponse(credential)
	if err != nil {
		log.Printf("NewAuthCredentialWithPniResponse error: %v", err)
		return nil, err
	}

	// Receive the auth credential
	aciUuidBytes, err := convertUUIDToByteUUID(d.Data.AciUuid)
	if err != nil {
		log.Printf("convertUUIDToBytes error: %v", err)
		return nil, err
	}
	pniUuidBytes, err := convertUUIDToByteUUID(d.Data.PniUuid)
	if err != nil {
		log.Printf("convertUUIDToBytes error: %v", err)
		return nil, err
	}
	authCredential, err := libsignalgo.ReceiveAuthCredentialWithPni(
		serverPublicParams(),
		*aciUuidBytes,
		*pniUuidBytes,
		redemptionTime,
		*authCredentialResponse,
	)
	if err != nil {
		log.Printf("ReceiveAuthCredentialWithPni error: %v", err)
		return nil, err
	}

	// get auth presentation
	groupSecretParams, err := libsignalgo.DeriveGroupSecretParamsFromMasterKey(masterKey)
	if err != nil {
		log.Printf("DeriveGroupSecretParamsFromMasterKey error: %v", err)
		return nil, err
	}
	randomness, err := libsignalgo.GenerateRandomness()
	authCredentialPresentation, err := libsignalgo.CreateAuthCredentialWithPniPresentation(
		serverPublicParams(),
		randomness,
		groupSecretParams,
		*authCredential,
	)
	if err != nil {
		log.Printf("CreateAuthCredentialWithPniPresentation error: %v", err)
		return nil, err
	}
	groupPublicParams, err := groupSecretParams.GetPublicParams()
	if err != nil {
		log.Printf("GetPublicParams error: %v", err)
		return nil, err
	}

	return &GroupAuth{
		Username: hex.EncodeToString(groupPublicParams[:]),
		Password: hex.EncodeToString(*authCredentialPresentation),
	}, nil
}

func masterKeyFromGroupID(groupID string) libsignalgo.GroupMasterKey {
	// We are very tricksy, groupID is just base64 encoded group master key :O
	masterKeyBytes, err := base64.StdEncoding.DecodeString(groupID)
	if err != nil {
		log.Printf("We should always be able to decode groupID into masterKeyBytes")
		panic(err)
	}
	return libsignalgo.GroupMasterKey(masterKeyBytes)
}

func RetrieveGroupById(ctx context.Context, d *store.Device, groupID string) (*signalpb.Group, error) {
	masterKey := masterKeyFromGroupID(groupID)
	groupAuth, err := GetAuthorizationForToday(ctx, d, masterKey)
	if err != nil {
		return nil, err
	}
	opts := &web.HTTPReqOpt{Username: &groupAuth.Username, Password: &groupAuth.Password, RequestPB: true, Host: web.StorageUrlHost}
	response, err := web.SendHTTPRequest("GET", "/v1/groups", opts)
	if err != nil {
		log.Printf("RetrieveGroupById SendHTTPRequest error: %v", err)
		return nil, err
	}
	if response.StatusCode != 200 {
		log.Printf("RetrieveGroupById SendHTTPRequest bad status: %v", response.StatusCode)
		return nil, errors.New(fmt.Sprintf("RetrieveGroupById SendHTTPRequest bad status: %v", response.StatusCode))
	}
	group := &signalpb.Group{}
	groupBytes, err := ioutil.ReadAll(response.Body)
	if err != nil {
		log.Printf("RetrieveGroupById ReadAll error: %v", err)
		return nil, err
	}
	err = proto.Unmarshal(groupBytes, group)
	if err != nil {
		log.Printf("RetrieveGroupById Unmarshal error: %v", err)
		return nil, err
	}
	return group, nil
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
	if profile.Name != nil {
		base64Name, err := base64.StdEncoding.DecodeString(*profile.Name)
		decryptedName, err := decryptString(*profileKey, base64Name)
		if err != nil {
			log.Printf("error decrypting profile name: %v", err)
			profile.Name = nil
		}
		profile.Name = decryptedName
		log.Printf("decryptedName: %v", *decryptedName)
	}
	if profile.About != nil {
		base64About, err := base64.StdEncoding.DecodeString(*profile.About)
		decryptedAbout, err := decryptString(*profileKey, base64About)
		if err != nil {
			log.Printf("error decrypting profile about: %v", err)
			profile.About = nil
		}
		profile.About = decryptedAbout
		log.Printf("decryptedAbout: %v", *decryptedAbout)
	}
	if profile.AboutEmoji != nil {
		base64AboutEmoji, err := base64.StdEncoding.DecodeString(*profile.AboutEmoji)
		decryptedAboutEmoji, err := decryptString(*profileKey, base64AboutEmoji)
		if err != nil {
			log.Printf("error decrypting profile aboutEmoji: %v", err)
			profile.AboutEmoji = nil
		}
		profile.AboutEmoji = decryptedAboutEmoji
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
