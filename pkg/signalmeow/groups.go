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
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"
	"unicode"

	"github.com/google/uuid"
	"google.golang.org/protobuf/proto"

	"go.mau.fi/mautrix-signal/pkg/libsignalgo"
	signalpb "go.mau.fi/mautrix-signal/pkg/signalmeow/protobuf"
	"go.mau.fi/mautrix-signal/pkg/signalmeow/types"
	"go.mau.fi/mautrix-signal/pkg/signalmeow/web"
)

type GroupMemberRole int32

const (
	// Note: right now we assume these match the equivalent values in the protobuf (signalpb.Member_Role)
	GroupMember_UNKNOWN       GroupMemberRole = 0
	GroupMember_DEFAULT       GroupMemberRole = 1
	GroupMember_ADMINISTRATOR GroupMemberRole = 2
)

type GroupMember struct {
	UserID           uuid.UUID
	Role             GroupMemberRole
	ProfileKey       libsignalgo.ProfileKey
	JoinedAtRevision uint32
	//Presentation     []byte
}

type Group struct {
	groupMasterKey  types.SerializedGroupMasterKey // We should keep this relatively private
	GroupIdentifier types.GroupIdentifier          // This is what we should use to identify a group outside this file

	Title                        string
	AvatarPath                   string
	Members                      []*GroupMember
	Description                  string
	AnnouncementsOnly            bool
	Revision                     uint32
	DisappearingMessagesDuration uint32
	//PublicKey                  *libsignalgo.PublicKey
	//AccessControl              *AccessControl
	//PendingMembers             []*PendingMember
	//RequestingMembers          []*RequestingMember
	//InviteLinkPassword         []byte
	//BannedMembers              []*BannedMember
}

type GroupAuth struct {
	Username string
	Password string
}

func (cli *Client) fetchNewGroupCreds(ctx context.Context, today time.Time) (*GroupCredentials, error) {
	sevenDaysOut := today.Add(7 * 24 * time.Hour)
	path := fmt.Sprintf("/v1/certificate/auth/group?redemptionStartSeconds=%d&redemptionEndSeconds=%d", today.Unix(), sevenDaysOut.Unix())
	authRequest := web.CreateWSRequest(http.MethodGet, path, nil, nil, nil)
	resp, err := cli.AuthedWS.SendRequest(ctx, authRequest)
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
	if creds.PNI != cli.Store.PNI {
		err := fmt.Errorf("creds.PNI != d.PNI")
		zlog.Err(err).Msg("creds.PNI != d.PNI")
		return nil, err
	}
	return &creds, nil
}

func (cli *Client) getCachedAuthorizationForToday(today time.Time) *GroupCredential {
	if cli.GroupCredentials == nil {
		// No cached credentials
		return nil
	}
	allCreds := cli.GroupCredentials
	// Get the credential for today
	for _, cred := range allCreds.Credentials {
		if cred.RedemptionTime == today.Unix() {
			return &cred
		}
	}
	zlog.Info().Msg("No cached credential found for today")
	return nil
}

func (cli *Client) GetAuthorizationForToday(ctx context.Context, masterKey libsignalgo.GroupMasterKey) (*GroupAuth, error) {
	// Timestamps for the start of today, and 7 days later
	today := time.Now().Truncate(24 * time.Hour)

	todayCred := cli.getCachedAuthorizationForToday(today)
	if todayCred == nil {
		creds, err := cli.fetchNewGroupCreds(ctx, today)
		if err != nil {
			zlog.Err(err).Msg("fetchNewGroupCreds error")
			return nil, err
		}
		cli.GroupCredentials = creds
		todayCred = cli.getCachedAuthorizationForToday(today)
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
	authCredential, err := libsignalgo.ReceiveAuthCredentialWithPni(
		serverPublicParams(),
		cli.Store.ACI,
		cli.Store.PNI,
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

func masterKeyToBytes(groupMasterKey types.SerializedGroupMasterKey) libsignalgo.GroupMasterKey {
	// We are very tricksy, groupMasterKey is just base64 encoded group master key :O
	masterKeyBytes, err := base64.StdEncoding.DecodeString(string(groupMasterKey))
	if err != nil {
		//zlog.Err(err).Msg("")
		zlog.Fatal().Err(err).Msg("We should always be able to decode groupMasterKey into masterKeyBytes")
	}
	return libsignalgo.GroupMasterKey(masterKeyBytes)
}

func masterKeyFromBytes(masterKey libsignalgo.GroupMasterKey) types.SerializedGroupMasterKey {
	return types.SerializedGroupMasterKey(base64.StdEncoding.EncodeToString(masterKey[:]))
}

func groupIdentifierFromMasterKey(masterKey types.SerializedGroupMasterKey) (types.GroupIdentifier, error) {
	groupSecretParams, err := libsignalgo.DeriveGroupSecretParamsFromMasterKey(masterKeyToBytes(masterKey))
	if err != nil {
		zlog.Err(err).Msg("DeriveGroupSecretParamsFromMasterKey error")
		return "", err
	}
	// Get the "group identifier" that isn't just the master key
	groupPublicParams, err := groupSecretParams.GetPublicParams()
	if err != nil {
		zlog.Err(err).Msg("GetPublicParams error")
		return "", err
	}
	groupIdentifier, err := libsignalgo.GetGroupIdentifier(*groupPublicParams)
	if err != nil {
		zlog.Err(err).Msg("GetGroupIdentifier error")
		return "", err
	}
	base64GroupIdentifier := base64.StdEncoding.EncodeToString(groupIdentifier[:])
	gid := types.GroupIdentifier(base64GroupIdentifier)
	return gid, nil
}

func decryptGroup(encryptedGroup *signalpb.Group, groupMasterKey types.SerializedGroupMasterKey) (*Group, error) {
	decryptedGroup := &Group{
		groupMasterKey: groupMasterKey,
	}

	groupSecretParams, err := libsignalgo.DeriveGroupSecretParamsFromMasterKey(masterKeyToBytes(groupMasterKey))
	if err != nil {
		zlog.Err(err).Msg("DeriveGroupSecretParamsFromMasterKey error")
		return nil, err
	}

	gid, err := groupIdentifierFromMasterKey(groupMasterKey)
	if err != nil {
		zlog.Err(err).Msg("groupIdentifierFromMasterKey error")
		return nil, err
	}
	decryptedGroup.GroupIdentifier = gid

	titleBlob, err := decryptGroupPropertyIntoBlob(groupSecretParams, encryptedGroup.Title)
	if err != nil {
		return nil, err
	}
	// The actual title is in the blob
	decryptedGroup.Title = cleanupStringProperty(titleBlob.GetTitle())

	descriptionBlob, err := decryptGroupPropertyIntoBlob(groupSecretParams, encryptedGroup.Description)
	if err == nil {
		// treat a failure in obtaining the description as non-fatal
		decryptedGroup.Description = cleanupStringProperty(descriptionBlob.GetDescription())
	}

	if encryptedGroup.DisappearingMessagesTimer != nil && len(encryptedGroup.DisappearingMessagesTimer) > 0 {
		timerBlob, err := decryptGroupPropertyIntoBlob(groupSecretParams, encryptedGroup.DisappearingMessagesTimer)
		if err != nil {
			return nil, err
		}
		decryptedGroup.DisappearingMessagesDuration = timerBlob.GetDisappearingMessagesDuration()
	}

	// These aren't encrypted
	decryptedGroup.AvatarPath = encryptedGroup.Avatar
	decryptedGroup.Revision = encryptedGroup.Revision

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
		profileKey, err := groupSecretParams.DecryptProfileKey(encryptedProfileKey, userID)
		if err != nil {
			zlog.Err(err).Msg("DecryptProfileKey ProfileKey error")
			return nil, err
		}
		decryptedGroup.Members = append(decryptedGroup.Members, &GroupMember{
			UserID:           userID,
			ProfileKey:       *profileKey,
			Role:             GroupMemberRole(member.Role),
			JoinedAtRevision: member.JoinedAtRevision,
		})
	}

	return decryptedGroup, nil
}

func decryptGroupPropertyIntoBlob(groupSecretParams libsignalgo.GroupSecretParams, encryptedProperty []byte) (*signalpb.GroupAttributeBlob, error) {
	decryptedProperty, err := groupSecretParams.DecryptBlobWithPadding(encryptedProperty)
	if err != nil {
		zlog.Err(err).Msg("DecryptBlobWithPadding error")
		return nil, err
	}
	propertyBlob := &signalpb.GroupAttributeBlob{}
	err = proto.Unmarshal(decryptedProperty, propertyBlob)
	if err != nil {
		zlog.Err(err).Msg("Unmarshal error")
		return nil, err
	}
	return propertyBlob, nil
}

func cleanupStringProperty(property string) string {
	// strip non-printable characters from the string
	property = strings.Map(cleanupStringMapping, property)
	// strip \n and \t from start and end of the property if it exists
	return strings.TrimSpace(property)
}

func cleanupStringMapping(r rune) rune {
	if unicode.IsGraphic(r) {
		return r
	}
	return -1
}

func decryptGroupAvatar(encryptedAvatar []byte, groupMasterKey types.SerializedGroupMasterKey) ([]byte, error) {
	groupSecretParams, err := libsignalgo.DeriveGroupSecretParamsFromMasterKey(masterKeyToBytes(groupMasterKey))
	if err != nil {
		zlog.Err(err).Msg("DeriveGroupSecretParamsFromMasterKey error")
		return nil, err
	}
	avatarBlob, err := decryptGroupPropertyIntoBlob(groupSecretParams, encryptedAvatar)
	if err != nil {
		return nil, err
	}
	// The actual avatar is in the blob
	decryptedImage := avatarBlob.GetAvatar()

	return decryptedImage, nil
}

func groupMetadataForDataMessage(group Group) *signalpb.GroupContextV2 {
	masterKey := masterKeyToBytes(group.groupMasterKey)
	masterKeyBytes := masterKey[:]
	return &signalpb.GroupContextV2{
		MasterKey: masterKeyBytes,
		Revision:  &group.Revision,
	}
}

func (cli *Client) fetchGroupByID(ctx context.Context, gid types.GroupIdentifier) (*Group, error) {
	groupMasterKey, err := cli.Store.GroupStore.MasterKeyFromGroupIdentifier(ctx, gid)
	if err != nil {
		zlog.Err(err).Msg("Failed to get group master key")
		return nil, err
	}
	if groupMasterKey == "" {
		err := fmt.Errorf("No group master key found for group identifier")
		zlog.Err(err).Str("gid", string(gid)).Msg("")
		return nil, err
	}
	masterKeyBytes := masterKeyToBytes(groupMasterKey)
	groupAuth, err := cli.GetAuthorizationForToday(ctx, masterKeyBytes)
	if err != nil {
		return nil, err
	}
	opts := &web.HTTPReqOpt{
		Username:    &groupAuth.Username,
		Password:    &groupAuth.Password,
		ContentType: web.ContentTypeProtobuf,
		Host:        web.StorageHostname,
	}
	response, err := web.SendHTTPRequest(http.MethodGet, "/v1/groups", opts)
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

	group, err := decryptGroup(encryptedGroup, groupMasterKey)
	if err != nil {
		zlog.Err(err).Msg("RetrieveGroupById decryptGroup error")
		return nil, err
	}

	// Store the profile keys in case they're new
	for _, member := range group.Members {
		err = cli.Store.ProfileKeyStore.StoreProfileKey(ctx, member.UserID, member.ProfileKey)
		if err != nil {
			zlog.Err(err).Msg("DecryptGroup StoreProfileKey error")
			//return nil, err
		}
	}
	return group, nil
}

func (cli *Client) fetchAndDecryptGroupAvatarImage(path string, masterKey types.SerializedGroupMasterKey) ([]byte, error) {
	// Fetch avatar
	username, password := cli.Store.BasicAuthCreds()
	opts := &web.HTTPReqOpt{
		Host:     web.CDN1Hostname,
		Username: &username,
		Password: &password,
	}
	zlog.Info().Str("avatar_path", path).Msg("Fetching group avatar")
	resp, err := web.SendHTTPRequest(http.MethodGet, path, opts)
	if err != nil {
		zlog.Err(err).Msg("error fetching group avatar")
		return nil, err
	}
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		err := errors.New(fmt.Sprintf("%v (unsuccessful status code)", resp.Status))
		zlog.Err(err).Msg("bad status fetching group avatar")
		return nil, err
	}
	encryptedAvatar, err := io.ReadAll(resp.Body)
	if err != nil {
		zlog.Err(err).Msg("error reading group avatar")
		return nil, err
	}

	encryptedBytes := encryptedAvatar

	// Decrypt avatar
	decryptedBytes, err := decryptGroupAvatar(encryptedBytes, masterKey)
	return decryptedBytes, nil
}

func (cli *Client) RetrieveGroupByID(ctx context.Context, gid types.GroupIdentifier) (*Group, error) {
	cli.initGroupCache()

	lastFetched, ok := cli.GroupCache.lastFetched[gid]
	if ok && time.Since(lastFetched) < 1*time.Hour {
		group, ok := cli.GroupCache.groups[gid]
		if ok {
			return group, nil
		}
	}
	group, err := cli.fetchGroupByID(ctx, gid)
	if err != nil {
		return nil, err
	}
	cli.GroupCache.groups[gid] = group
	cli.GroupCache.lastFetched[gid] = time.Now()
	return group, nil
}

func (cli *Client) RetrieveGroupAndAvatarByID(ctx context.Context, gid types.GroupIdentifier) (*Group, []byte, error) {
	group, err := cli.RetrieveGroupByID(ctx, gid)
	if err != nil {
		return nil, nil, err
	}
	gid = group.GroupIdentifier

	// If there is an avatarPath, and it's different from the cached one, fetch it
	// (we only return the avatar if it's different from the cached one)
	var avatarImage []byte
	cachedAvatarPath, _ := cli.GroupCache.avatarPaths[gid]
	if group.AvatarPath != "" && cachedAvatarPath != group.AvatarPath {
		avatarImage, err = cli.fetchAndDecryptGroupAvatarImage(group.AvatarPath, group.groupMasterKey)
		if err != nil {
			zlog.Err(err).Msg("error fetching group avatarImage")
			return nil, nil, err
		}
	}
	cli.GroupCache.avatarPaths[gid] = group.AvatarPath

	return group, avatarImage, nil
}

func (cli *Client) InvalidateGroupCache(gid types.GroupIdentifier) {
	if cli.GroupCache == nil {
		return
	}
	delete(cli.GroupCache.groups, gid)
	delete(cli.GroupCache.lastFetched, gid)
	// Don't delete avatarPaths, they can stay cached
}

// We should store the group master key in the group store as soon as we see it,
// then use the group identifier to refer to groups. As a convenience, we return
// the group identifier, which is derived from the group master key.
func (cli *Client) StoreMasterKey(ctx context.Context, groupMasterKey types.SerializedGroupMasterKey) (types.GroupIdentifier, error) {
	groupIdentifier, err := groupIdentifierFromMasterKey(groupMasterKey)
	if err != nil {
		zlog.Err(err).Msg("groupIdentifierFromMasterKey error")
		return "", err
	}
	err = cli.Store.GroupStore.StoreMasterKey(ctx, groupIdentifier, groupMasterKey)
	if err != nil {
		zlog.Err(err).Msg("StoreMasterKey error")
		return "", err
	}
	return groupIdentifier, nil
}

// We need to track active calls so we don't send too many IncomingSignalMessageCalls
// Of course for group calls Signal doesn't tell us *anything* so we're mostly just inferring
// So we just jam a new call ID in, and return true if we *think* this is a new incoming call
func (cli *Client) UpdateActiveCalls(gid types.GroupIdentifier, callID string) (isActive bool) {
	cli.initGroupCache()
	// Check to see if we currently have an active call for this group
	currentCallID, ok := cli.GroupCache.activeCalls[gid]
	if ok {
		// If we do, then this must be ending the call
		if currentCallID == callID {
			delete(cli.GroupCache.activeCalls, gid)
			return false
		}
	}
	cli.GroupCache.activeCalls[gid] = callID
	return true
}

func (cli *Client) initGroupCache() {
	if cli.GroupCache == nil {
		cli.GroupCache = &GroupCache{
			groups:      make(map[types.GroupIdentifier]*Group),
			lastFetched: make(map[types.GroupIdentifier]time.Time),
			avatarPaths: make(map[types.GroupIdentifier]string),
			activeCalls: make(map[types.GroupIdentifier]string),
		}
	}
}

type GroupCache struct {
	groups      map[types.GroupIdentifier]*Group
	lastFetched map[types.GroupIdentifier]time.Time
	avatarPaths map[types.GroupIdentifier]string
	activeCalls map[types.GroupIdentifier]string
}
