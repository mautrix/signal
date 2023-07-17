package signalmeow

import (
	"context"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io/ioutil"
	"log"
	"time"

	"go.mau.fi/mautrix-signal/pkg/libsignalgo"
	signalpb "go.mau.fi/mautrix-signal/pkg/signalmeow/protobuf"
	"go.mau.fi/mautrix-signal/pkg/signalmeow/web"
	"google.golang.org/protobuf/proto"
)

type GroupMemberRole int32

const (
	GroupMember_UNKNOWN       GroupMemberRole = 0
	GroupMember_DEFAULT       GroupMemberRole = 1
	GroupMember_ADMINISTRATOR GroupMemberRole = 2
)

type GroupMember struct {
	UserId     string
	Role       GroupMemberRole
	ProfileKey libsignalgo.ProfileKey
	//Presentation     []byte
	//JoinedAtRevision uint32
}
type Group struct {
	GroupID GroupID

	Title             string
	Avatar            string
	Members           []*GroupMember
	Description       string
	AnnouncementsOnly bool
	//PublicKey                 *libsignalgo.PublicKey
	//Revision			        uint32
	//DisappearingMessagesTimer []byte
	//AccessControl             *AccessControl
	//PendingMembers            []*PendingMember
	//RequestingMembers         []*RequestingMember
	//InviteLinkPassword        []byte
	//BannedMembers             []*BannedMember
}

type GroupAuth struct {
	Username string
	Password string
}

// Shhhh this is just base64 encoded group master key
type GroupID string

func fetchNewGroupCreds(ctx context.Context, d *Device, today time.Time) (*GroupCredentials, error) {
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

	var creds GroupCredentials
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

func getCachedAuthorizationForToday(d *Device, today time.Time) *GroupCredential {
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

func GetAuthorizationForToday(ctx context.Context, d *Device, masterKey libsignalgo.GroupMasterKey) (*GroupAuth, error) {
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

func masterKeyFromGroupID(groupID GroupID) libsignalgo.GroupMasterKey {
	// We are very tricksy, groupID is just base64 encoded group master key :O
	masterKeyBytes, err := base64.StdEncoding.DecodeString(string(groupID))
	if err != nil {
		log.Printf("We should always be able to decode groupID into masterKeyBytes")
		panic(err)
	}
	return libsignalgo.GroupMasterKey(masterKeyBytes)
}

func groupIDFromMasterKey(masterKey libsignalgo.GroupMasterKey) GroupID {
	return GroupID(base64.StdEncoding.EncodeToString(masterKey[:]))
}

func decryptGroup(encryptedGroup *signalpb.Group, groupID GroupID) (*Group, error) {
	decryptedGroup := &Group{
		GroupID: groupID,
	}

	groupSecretParams, err := libsignalgo.DeriveGroupSecretParamsFromMasterKey(masterKeyFromGroupID(groupID))
	if err != nil {
		log.Printf("DeriveGroupSecretParamsFromMasterKey error: %v", err)
		return nil, err
	}
	title, err := groupSecretParams.DecryptBlobWithPadding(encryptedGroup.Title)
	if err != nil {
		log.Printf("DecryptBlobWithPadding Title error: %v", err)
		return nil, err
	}
	decryptedGroup.Title = string(title)

	return decryptedGroup, nil
}

func RetrieveGroupById(ctx context.Context, d *Device, groupID GroupID) (*Group, error) {
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
	encryptedGroup := &signalpb.Group{}
	groupBytes, err := ioutil.ReadAll(response.Body)
	if err != nil {
		log.Printf("RetrieveGroupById ReadAll error: %v", err)
		return nil, err
	}
	err = proto.Unmarshal(groupBytes, encryptedGroup)
	if err != nil {
		log.Printf("RetrieveGroupById Unmarshal error: %v", err)
		return nil, err
	}

	group, err := decryptGroup(encryptedGroup, groupID)
	if err != nil {
		log.Printf("RetrieveGroupById decryptGroup error: %v", err)
		return nil, err
	}
	return group, nil
}
