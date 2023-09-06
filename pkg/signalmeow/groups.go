package signalmeow

import (
	"context"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"strings"
	"time"
	"unicode"

	"go.mau.fi/mautrix-signal/pkg/libsignalgo"
	signalpb "go.mau.fi/mautrix-signal/pkg/signalmeow/protobuf"
	"go.mau.fi/mautrix-signal/pkg/signalmeow/web"
	"google.golang.org/protobuf/proto"
)

type GroupMemberRole int32

const (
	// Note: right now we assume these match the equivalent values in the protobuf (signalpb.Member_Role)
	GroupMember_UNKNOWN       GroupMemberRole = 0
	GroupMember_DEFAULT       GroupMemberRole = 1
	GroupMember_ADMINISTRATOR GroupMemberRole = 2
)

type GroupMember struct {
	UserId           string
	Role             GroupMemberRole
	ProfileKey       libsignalgo.ProfileKey
	JoinedAtRevision uint32
	//Presentation     []byte
}
type Group struct {
	GroupID GroupID

	Title             string
	Avatar            string
	Members           []*GroupMember
	Description       string
	AnnouncementsOnly bool
	Revision          uint32
	//PublicKey                 *libsignalgo.PublicKey
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
	resp, err := d.Connection.AuthedWS.SendRequest(ctx, authRequest)
	if err != nil {
		zlog.Err(err).Msg("SendRequest error")
		return nil, err
	}
	if *resp.Status != 200 {
		err := fmt.Errorf("bad status code: %d", *resp.Status)
		zlog.Err(err).Msg("bad status code fetching group creds")
		return nil, err
	}

	var creds GroupCredentials
	err = json.Unmarshal(resp.Body, &creds)
	if err != nil {
		zlog.Err(err).Msg("json.Unmarshal error")
		return nil, err
	}
	// make sure pni matches device pni
	if creds.Pni != d.Data.PniUuid {
		err := fmt.Errorf("creds.Pni != d.PniUuid")
		zlog.Err(err).Msg("creds.Pni != d.PniUuid")
		return nil, err
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
	zlog.Info().Msg("No cached credential found for today")
	return nil
}

func GetAuthorizationForToday(ctx context.Context, d *Device, masterKey libsignalgo.GroupMasterKey) (*GroupAuth, error) {
	// Timestamps for the start of today, and 7 days later
	today := time.Now().Truncate(24 * time.Hour)

	todayCred := getCachedAuthorizationForToday(d, today)
	if todayCred == nil {
		creds, err := fetchNewGroupCreds(ctx, d, today)
		if err != nil {
			zlog.Err(err).Msg("fetchNewGroupCreds error")
			return nil, err
		}
		d.Connection.GroupCredentials = creds
		todayCred = getCachedAuthorizationForToday(d, today)
	}
	if todayCred == nil {
		err := errors.New("Couldn't get credential for today")
		zlog.Err(err).Msg("GetAuthorizationForToday error")
		return nil, err
	}

	//TODO: cache cred after unmarshalling
	redemptionTime := uint64(todayCred.RedemptionTime)
	credential := todayCred.Credential
	authCredentialResponse, err := libsignalgo.NewAuthCredentialWithPniResponse(credential)
	if err != nil {
		zlog.Err(err).Msg("NewAuthCredentialWithPniResponse error")
		return nil, err
	}

	// Receive the auth credential
	aciUuidBytes, err := convertUUIDToByteUUID(d.Data.AciUuid)
	if err != nil {
		zlog.Err(err).Msg("aci convertUUIDToBytes error")
		return nil, err
	}
	pniUuidBytes, err := convertUUIDToByteUUID(d.Data.PniUuid)
	if err != nil {
		zlog.Err(err).Msg("pni convertUUIDToBytes error")
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
		zlog.Err(err).Msg("ReceiveAuthCredentialWithPni error")
		return nil, err
	}

	// get auth presentation
	groupSecretParams, err := libsignalgo.DeriveGroupSecretParamsFromMasterKey(masterKey)
	if err != nil {
		zlog.Err(err).Msg("DeriveGroupSecretParamsFromMasterKey error")
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
		zlog.Err(err).Msg("CreateAuthCredentialWithPniPresentation error")
		return nil, err
	}
	groupPublicParams, err := groupSecretParams.GetPublicParams()
	if err != nil {
		zlog.Err(err).Msg("GetPublicParams error")
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
		zlog.Err(err).Msg("")
		zlog.Fatal().Msg("We should always be able to decode groupID into masterKeyBytes")
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
		zlog.Err(err).Msg("DeriveGroupSecretParamsFromMasterKey error")
		return nil, err
	}

	title, err := groupSecretParams.DecryptBlobWithPadding(encryptedGroup.Title)
	if err != nil {
		zlog.Err(err).Msg("DecryptBlobWithPadding Title error")
		return nil, err
	}
	titleString := string(title)
	// strip non-printable characters from the title
	titleString = strings.Map(func(r rune) rune {
		if unicode.IsGraphic(r) {
			return r
		}
		return -1
	}, titleString)
	// strip \n and \t from start and end of title if it exists
	titleString = strings.TrimSpace(titleString)
	decryptedGroup.Title = titleString

	// TODO: Not sure how to decrypt avatar yet
	//avatarBytes, err := base64.StdEncoding.DecodeString(encryptedGroup.Avatar)
	//zlog.Err(err).Msg("avatarBytes")
	//decryptedAvatar, err := groupSecretParams.DecryptBlobWithPadding(avatarBytes)
	//if err != nil {
	//	zlog.Err(err).Msg("DecryptBlobWithPadding Avatar error")
	//	//return nil, err
	//}
	//decryptedGroup.Avatar = string(decryptedAvatar)

	// Decrypt members
	decryptedGroup.Members = make([]*GroupMember, 0)
	for _, member := range encryptedGroup.Members {
		if member == nil {
			continue
		}
		encryptedUserID := libsignalgo.UUIDCiphertext(member.UserId)
		userID, err := groupSecretParams.DecryptUUID(encryptedUserID)
		if err != nil {
			zlog.Err(err).Msg("DecryptUUID UserId error")
			return nil, err
		}
		encryptedProfileKey := libsignalgo.ProfileKeyCiphertext(member.ProfileKey)
		profileKey, err := groupSecretParams.DecryptProfileKey(encryptedProfileKey, *userID)
		if err != nil {
			zlog.Err(err).Msg("DecryptProfileKey ProfileKey error")
			return nil, err
		}
		decryptedGroup.Members = append(decryptedGroup.Members, &GroupMember{
			UserId:           convertByteUUIDToUUID(*userID),
			ProfileKey:       *profileKey,
			Role:             GroupMemberRole(member.Role),
			JoinedAtRevision: member.JoinedAtRevision,
		})
	}

	return decryptedGroup, nil
}

func printGroupMember(member *GroupMember) {
	if member == nil {
		zlog.Debug().Msg("GroupMember is nil")
		return
	}
	zlog.Debug().Msgf("UserID: %v", member.UserId)
	zlog.Debug().Msgf("ProfileKey: %v", member.ProfileKey)
	zlog.Debug().Msgf("Role: %v", member.Role)
	zlog.Debug().Msgf("JoinedAtRevision: %v", member.JoinedAtRevision)
}
func printGroup(group *Group) {
	zlog.Debug().Msgf("GroupID: %v", group.GroupID)
	zlog.Debug().Msgf("Title: %v", group.Title)
	zlog.Debug().Msgf("Avatar: %v", group.Avatar)
	zlog.Debug().Msgf("Members len: %v", len(group.Members))
	for _, member := range group.Members {
		printGroupMember(member)
	}
}

func groupMetadataForDataMessage(group Group) *signalpb.GroupContextV2 {
	masterKey := masterKeyFromGroupID(group.GroupID)
	masterKeyBytes := masterKey[:]
	return &signalpb.GroupContextV2{
		MasterKey: masterKeyBytes,
		Revision:  &group.Revision,
	}
}

func fetchGroupByID(ctx context.Context, d *Device, groupID GroupID) (*Group, error) {
	masterKey := masterKeyFromGroupID(groupID)
	groupAuth, err := GetAuthorizationForToday(ctx, d, masterKey)
	if err != nil {
		return nil, err
	}
	opts := &web.HTTPReqOpt{
		Username:    &groupAuth.Username,
		Password:    &groupAuth.Password,
		ContentType: web.ContentTypeProtobuf,
		Host:        web.StorageUrlHost,
	}
	response, err := web.SendHTTPRequest("GET", "/v1/groups", opts)
	if err != nil {
		zlog.Err(err).Msg("RetrieveGroupById SendHTTPRequest error")
		return nil, err
	}
	if response.StatusCode != 200 {
		err := fmt.Errorf("RetrieveGroupById SendHTTPRequest bad status: %v", response.StatusCode)
		zlog.Err(err).Msg("")
		return nil, err
	}
	encryptedGroup := &signalpb.Group{}
	groupBytes, err := io.ReadAll(response.Body)
	if err != nil {
		zlog.Err(err).Msg("RetrieveGroupById ReadAll error")
		return nil, err
	}
	err = proto.Unmarshal(groupBytes, encryptedGroup)
	if err != nil {
		zlog.Err(err).Msg("RetrieveGroupById Unmarshal error")
		return nil, err
	}

	group, err := decryptGroup(encryptedGroup, groupID)
	if err != nil {
		zlog.Err(err).Msg("RetrieveGroupById decryptGroup error")
		return nil, err
	}

	// Store the profile keys in case they're new
	for _, member := range group.Members {
		err = d.ProfileKeyStore.StoreProfileKey(member.UserId, member.ProfileKey, ctx)
		if err != nil {
			zlog.Err(err).Msg("DecryptGroup StoreProfileKey error")
			//return nil, err
		}
	}
	return group, nil
}

func RetrieveGroupByID(ctx context.Context, d *Device, groupID GroupID) (*Group, error) {
	if d.Connection.GroupCache == nil {
		d.Connection.GroupCache = &GroupCache{
			groups:      make(map[string]*Group),
			lastFetched: make(map[string]time.Time),
		}
	}

	lastFetched, ok := d.Connection.GroupCache.lastFetched[string(groupID)]
	if ok && time.Since(lastFetched) < 1*time.Hour {
		group, ok := d.Connection.GroupCache.groups[string(groupID)]
		if ok {
			return group, nil
		}
	}
	group, err := fetchGroupByID(ctx, d, groupID)
	if err != nil {
		return nil, err
	}
	d.Connection.GroupCache.groups[string(groupID)] = group
	d.Connection.GroupCache.lastFetched[string(groupID)] = time.Now()
	return group, nil
}

func InvalidateGroupCache(d *Device, groupID GroupID) {
	if d.Connection.GroupCache == nil {
		return
	}
	delete(d.Connection.GroupCache.groups, string(groupID))
	delete(d.Connection.GroupCache.lastFetched, string(groupID))
}

type GroupCache struct {
	groups      map[string]*Group
	lastFetched map[string]time.Time
}
