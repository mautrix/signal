// mautrix-signal - A Matrix-signal puppeting bridge.
// Copyright (C) 2023 Scott Weber, Malte Eggers
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
	"unicode"

	"github.com/google/uuid"
	"github.com/rs/zerolog"
	"google.golang.org/protobuf/proto"

	"go.mau.fi/mautrix-signal/pkg/libsignalgo"
	signalpb "go.mau.fi/mautrix-signal/pkg/signalmeow/protobuf"
	"go.mau.fi/mautrix-signal/pkg/signalmeow/types"
	"go.mau.fi/mautrix-signal/pkg/signalmeow/web"
)

type GroupMemberRole int32

type GroupAvatarMeta interface {
	getGroupMasterKey() types.SerializedGroupMasterKey
	GetAvatarPath() *string
}

const (
	// Note: right now we assume these match the equivalent values in the protobuf (signalpb.Member_Role)
	GroupMember_UNKNOWN       GroupMemberRole = 0
	GroupMember_DEFAULT       GroupMemberRole = 1
	GroupMember_ADMINISTRATOR GroupMemberRole = 2
)

type AccessControl int32

const (
	AccessControl_UNKNOWN       AccessControl = 0
	AccessControl_ANY           AccessControl = 1
	AccessControl_MEMBER        AccessControl = 2
	AccessControl_ADMINISTRATOR AccessControl = 3
	AccessControl_UNSATISFIABLE AccessControl = 4
)

type GroupMember struct {
	UserID           uuid.UUID
	Role             GroupMemberRole
	ProfileKey       libsignalgo.ProfileKey
	JoinedAtRevision uint32
	//Presentation     []byte
}

func (gm *GroupMember) UserServiceID() libsignalgo.ServiceID {
	return libsignalgo.NewACIServiceID(gm.UserID)
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
	AccessControl                *GroupAccessControl
	PendingMembers               []*PendingMember
	RequestingMembers            []*RequestingMember
	BannedMembers                []*BannedMember
	InviteLinkPassword           *types.SerializedInviteLinkPassword
	//PublicKey                  *libsignalgo.PublicKey
}

func (group *Group) GetInviteLink() (string, error) {
	if group.InviteLinkPassword == nil {
		return "", fmt.Errorf("no invite link password set")
	}
	masterKeyBytes := masterKeyToBytes(group.groupMasterKey)
	inviteLinkPasswordBytes, err := inviteLinkPasswordToBytes(*group.InviteLinkPassword)
	if err != nil {
		return "", fmt.Errorf("couldn't decode invite link password")
	}
	inviteLinkContents := signalpb.GroupInviteLink_V1Contents{
		V1Contents: &signalpb.GroupInviteLink_GroupInviteLinkContentsV1{
			GroupMasterKey:     masterKeyBytes[:],
			InviteLinkPassword: inviteLinkPasswordBytes,
		},
	}
	inviteLink := signalpb.GroupInviteLink{Contents: &inviteLinkContents}
	inviteLinkEncoded, err := proto.Marshal(&inviteLink)
	if err != nil {
		return "", fmt.Errorf("failed to marshal invite link")
	}
	inviteLinkPath := base64.URLEncoding.EncodeToString(inviteLinkEncoded)
	return "https://signal.group/#" + inviteLinkPath, nil
}

type GroupAccessControl struct {
	Members           AccessControl
	AddFromInviteLink AccessControl
	Attributes        AccessControl
}

func (group *Group) getGroupMasterKey() types.SerializedGroupMasterKey {
	return group.groupMasterKey
}
func (group *Group) GetAvatarPath() *string {
	return &group.AvatarPath
}

type AddMember struct {
	GroupMember
	JoinFromInviteLink bool
}

type PendingMember struct {
	GroupMember
	AddedByUserID uuid.UUID
	Timestamp     uint64
}

type ProfileKeyMember struct {
	UserID     uuid.UUID
	ProfileKey libsignalgo.ProfileKey
	//Presentation []byte
}

type RequestingMember struct {
	UserID     uuid.UUID
	ProfileKey libsignalgo.ProfileKey
	Timestamp  uint64
	//Presentation []byte
}

// type PromotePniAciMember struct {
// 	UserID     uuid.UUID
// 	ProfileKey libsignalgo.ProfileKey
// 	PNI        uuid.UUID
// 	Presentation []byte
// }

type RoleMember struct {
	UserID uuid.UUID
	Role   GroupMemberRole
}

type BannedMember struct {
	UserID    uuid.UUID
	Timestamp uint64
}

type GroupChange struct {
	groupMasterKey types.SerializedGroupMasterKey

	Revision                           uint32
	AddMembers                         []*AddMember
	DeleteMembers                      []*uuid.UUID
	ModifyMemberRoles                  []*RoleMember
	ModifyMemberProfileKeys            []*ProfileKeyMember
	AddPendingMembers                  []*PendingMember
	DeletePendingMembers               []*uuid.UUID
	PromotePendingMembers              []*ProfileKeyMember
	ModifyTitle                        *string
	ModifyAvatar                       *string
	ModifyDisappearingMessagesDuration *uint32
	ModifyAttributesAccess             *AccessControl
	ModifyMemberAccess                 *AccessControl
	ModifyAddFromInviteLinkAccess      *AccessControl
	AddRequestingMembers               []*RequestingMember
	DeleteRequestingMembers            []*uuid.UUID
	PromoteRequestingMembers           []*RoleMember
	ModifyDescription                  *string
	ModifyAnnouncementsOnly            *bool
	AddBannedMembers                   []*BannedMember
	DeleteBannedMembers                []*uuid.UUID
	PromotePendingPniAciMembers        []*ProfileKeyMember
	ModifyInviteLinkPassword           *types.SerializedInviteLinkPassword
}

func (groupChange *GroupChange) isEmptpy() bool {
	return len(groupChange.AddMembers) == 0 &&
		len(groupChange.DeleteMembers) == 0 &&
		len(groupChange.ModifyMemberRoles) == 0 &&
		len(groupChange.ModifyMemberProfileKeys) == 0 &&
		len(groupChange.AddPendingMembers) == 0 &&
		len(groupChange.PromotePendingMembers) == 0 &&
		groupChange.ModifyTitle == nil &&
		groupChange.ModifyAvatar == nil &&
		groupChange.ModifyDisappearingMessagesDuration == nil &&
		groupChange.ModifyAttributesAccess == nil &&
		groupChange.ModifyMemberAccess == nil &&
		groupChange.ModifyAddFromInviteLinkAccess == nil &&
		len(groupChange.AddRequestingMembers) == 0 &&
		len(groupChange.DeleteRequestingMembers) == 0 &&
		len(groupChange.PromoteRequestingMembers) == 0 &&
		groupChange.ModifyDescription == nil &&
		groupChange.ModifyAnnouncementsOnly == nil &&
		len(groupChange.AddBannedMembers) == 0 &&
		len(groupChange.DeleteMembers) == 0
}

func (groupChange *GroupChange) resolveConflict(group *Group) {
	if *groupChange.ModifyTitle == group.Title {
		groupChange.ModifyTitle = nil
	}
	if *groupChange.ModifyDescription == group.Description {
		groupChange.ModifyDescription = nil
	}
	if *groupChange.ModifyAvatar == group.AvatarPath {
		groupChange.ModifyAvatar = nil
	}
	if *groupChange.ModifyDisappearingMessagesDuration == group.DisappearingMessagesDuration {
		groupChange.ModifyDisappearingMessagesDuration = nil
	}
	if *groupChange.ModifyAttributesAccess == group.AccessControl.Attributes {
		groupChange.ModifyAttributesAccess = nil
	}
	if *groupChange.ModifyMemberAccess == group.AccessControl.Members {
		groupChange.ModifyAttributesAccess = nil
	}
	if *groupChange.ModifyAddFromInviteLinkAccess == group.AccessControl.AddFromInviteLink {
		groupChange.ModifyAddFromInviteLinkAccess = nil
	}
	if *groupChange.ModifyAnnouncementsOnly == group.AnnouncementsOnly {
		groupChange.ModifyAnnouncementsOnly = nil
	}
	members := make(map[uuid.UUID]GroupMemberRole)
	for _, member := range group.Members {
		members[member.UserID] = member.Role
	}
	pendingMembers := make(map[uuid.UUID]bool)
	for _, pendingMember := range group.PendingMembers {
		pendingMembers[pendingMember.UserID] = true
	}
	requestingMembers := make(map[uuid.UUID]bool)
	for _, requestingMember := range group.RequestingMembers {
		requestingMembers[requestingMember.UserID] = true
	}
	for i, member := range groupChange.AddMembers {
		if _, ok := members[member.GroupMember.UserID]; ok {
			groupChange.AddMembers = append(groupChange.AddMembers[:i], groupChange.AddMembers[i+1:]...)
		}
	}
	for i, promotePendingMember := range groupChange.PromotePendingMembers {
		if _, ok := members[promotePendingMember.UserID]; ok {
			groupChange.PromotePendingMembers = append(groupChange.PromotePendingMembers[:i], groupChange.PromotePendingMembers[i+1:]...)
		}
	}
	for i, promoteRequestingMember := range groupChange.PromotePendingMembers {
		if _, ok := members[promoteRequestingMember.UserID]; ok {
			groupChange.PromoteRequestingMembers = append(groupChange.PromoteRequestingMembers[:i], groupChange.PromoteRequestingMembers[i+1:]...)
		}
	}
	for i, pendingMember := range groupChange.AddPendingMembers {
		if pendingMembers[pendingMember.GroupMember.UserID] {
			groupChange.AddPendingMembers = append(groupChange.AddPendingMembers[:i], groupChange.AddPendingMembers[i+1:]...)
		}
	}
	for i, requestingMember := range groupChange.AddRequestingMembers {
		if pendingMembers[requestingMember.UserID] {
			groupChange.AddRequestingMembers = append(groupChange.AddRequestingMembers[:i], groupChange.AddRequestingMembers[i+1:]...)
		}
	}
	for i, deletePendingMember := range groupChange.DeletePendingMembers {
		if !pendingMembers[*deletePendingMember] {
			groupChange.DeletePendingMembers = append(groupChange.DeletePendingMembers[:i], groupChange.DeletePendingMembers[i+1:]...)
		}
	}
	for i, deleteRequestingMember := range groupChange.DeleteRequestingMembers {
		if !pendingMembers[*deleteRequestingMember] {
			groupChange.DeleteRequestingMembers = append(groupChange.DeleteRequestingMembers[:i], groupChange.DeleteRequestingMembers[i+1:]...)
		}
	}
	for i, deleteMember := range groupChange.DeleteMembers {
		if _, ok := members[*deleteMember]; !ok {
			groupChange.DeleteMembers = append(groupChange.DeleteMembers[:i], groupChange.DeleteMembers[i+1:]...)
		}
	}
	for i, modifyMemberRole := range groupChange.ModifyMemberRoles {
		if members[modifyMemberRole.UserID] == modifyMemberRole.Role {
			groupChange.ModifyMemberRoles = append(groupChange.ModifyMemberRoles[:i], groupChange.ModifyMemberRoles[i+1:]...)
		}
	}
}

func (groupChange *GroupChange) getGroupMasterKey() types.SerializedGroupMasterKey {
	return groupChange.groupMasterKey
}

func (groupChange *GroupChange) GetAvatarPath() *string {
	return groupChange.ModifyAvatar
}

type GroupAuth struct {
	Username string
	Password string
}

func (cli *Client) fetchNewGroupCreds(ctx context.Context, today time.Time) (*GroupCredentials, error) {
	log := zerolog.Ctx(ctx).With().
		Str("action", "fetch new group creds").
		Logger()
	sevenDaysOut := today.Add(7 * 24 * time.Hour)
	path := fmt.Sprintf("/v1/certificate/auth/group?redemptionStartSeconds=%d&redemptionEndSeconds=%d&pniAsServiceId=true", today.Unix(), sevenDaysOut.Unix())
	authRequest := web.CreateWSRequest(http.MethodGet, path, nil, nil, nil)
	resp, err := cli.AuthedWS.SendRequest(ctx, authRequest)
	if err != nil {
		return nil, fmt.Errorf("SendRequest error: %w", err)
	}
	if *resp.Status != 200 {
		return nil, fmt.Errorf("bad status code fetching group creds: %d", *resp.Status)
	}

	var creds GroupCredentials
	err = json.Unmarshal(resp.Body, &creds)
	if err != nil {
		log.Err(err).Msg("json.Unmarshal error")
		return nil, err
	}
	// make sure pni matches device pni
	if creds.PNI != cli.Store.PNI {
		err := fmt.Errorf("creds.PNI != d.PNI")
		log.Err(err).Msg("creds.PNI != d.PNI")
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
	return nil
}

func (cli *Client) GetAuthorizationForToday(ctx context.Context, masterKey libsignalgo.GroupMasterKey) (*GroupAuth, error) {
	log := zerolog.Ctx(ctx).With().
		Str("action", "get authorization for today").
		Logger()
	// Timestamps for the start of today, and 7 days later
	today := time.Now().Truncate(24 * time.Hour)

	todayCred := cli.getCachedAuthorizationForToday(today)
	if todayCred == nil {
		creds, err := cli.fetchNewGroupCreds(ctx, today)
		if err != nil {
			return nil, fmt.Errorf("fetchNewGroupCreds error: %w", err)
		}
		cli.GroupCredentials = creds
		todayCred = cli.getCachedAuthorizationForToday(today)
	}
	if todayCred == nil {
		return nil, fmt.Errorf("couldn't get credential for today")
	}

	//TODO: cache cred after unmarshalling
	redemptionTime := uint64(todayCred.RedemptionTime)
	credential := todayCred.Credential
	authCredentialResponse, err := libsignalgo.NewAuthCredentialWithPniResponse(credential)
	if err != nil {
		log.Err(err).Msg("NewAuthCredentialWithPniResponse error")
		return nil, err
	}

	// Receive the auth credential
	authCredential, err := libsignalgo.ReceiveAuthCredentialWithPni(
		prodServerPublicParams,
		cli.Store.ACI,
		cli.Store.PNI,
		redemptionTime,
		*authCredentialResponse,
	)
	if err != nil {
		log.Err(err).Msg("ReceiveAuthCredentialWithPni error")
		return nil, err
	}

	// get auth presentation
	groupSecretParams, err := libsignalgo.DeriveGroupSecretParamsFromMasterKey(masterKey)
	if err != nil {
		log.Err(err).Msg("DeriveGroupSecretParamsFromMasterKey error")
		return nil, err
	}
	authCredentialPresentation, err := libsignalgo.CreateAuthCredentialWithPniPresentation(
		prodServerPublicParams,
		libsignalgo.GenerateRandomness(),
		groupSecretParams,
		*authCredential,
	)
	if err != nil {
		log.Err(err).Msg("CreateAuthCredentialWithPniPresentation error")
		return nil, err
	}
	groupPublicParams, err := groupSecretParams.GetPublicParams()
	if err != nil {
		log.Err(err).Msg("GetPublicParams error")
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
		panic(fmt.Errorf("we should always be able to decode groupMasterKey into masterKeyBytes: %w", err))
	}
	return libsignalgo.GroupMasterKey(masterKeyBytes)
}

func masterKeyFromBytes(masterKey libsignalgo.GroupMasterKey) types.SerializedGroupMasterKey {
	return types.SerializedGroupMasterKey(base64.StdEncoding.EncodeToString(masterKey[:]))
}

func inviteLinkPasswordToBytes(inviteLinkPassword types.SerializedInviteLinkPassword) ([]byte, error) {
	inviteLinkPasswordBytes, err := base64.StdEncoding.DecodeString((string(inviteLinkPassword)))
	if err != nil {
		return nil, err
	}
	return inviteLinkPasswordBytes, nil
}

func InviteLinkPasswordFromBytes(inviteLinkPassword []byte) types.SerializedInviteLinkPassword {
	return types.SerializedInviteLinkPassword(base64.StdEncoding.EncodeToString(inviteLinkPassword))
}

func groupIdentifierFromMasterKey(masterKey types.SerializedGroupMasterKey) (types.GroupIdentifier, error) {
	groupSecretParams, err := libsignalgo.DeriveGroupSecretParamsFromMasterKey(masterKeyToBytes(masterKey))
	if err != nil {
		return "", fmt.Errorf("DeriveGroupSecretParamsFromMasterKey error: %w", err)
	}
	// Get the "group identifier" that isn't just the master key
	groupPublicParams, err := groupSecretParams.GetPublicParams()
	if err != nil {
		return "", fmt.Errorf("GetPublicParams error: %w", err)
	}
	groupIdentifier, err := libsignalgo.GetGroupIdentifier(*groupPublicParams)
	if err != nil {
		return "", fmt.Errorf("GetGroupIdentifier error: %w", err)
	}
	base64GroupIdentifier := base64.StdEncoding.EncodeToString(groupIdentifier[:])
	gid := types.GroupIdentifier(base64GroupIdentifier)
	return gid, nil
}

func decryptGroup(ctx context.Context, encryptedGroup *signalpb.Group, groupMasterKey types.SerializedGroupMasterKey) (*Group, error) {
	log := zerolog.Ctx(ctx).With().Str("action", "decrypt group").Logger()
	decryptedGroup := &Group{
		groupMasterKey: groupMasterKey,
	}

	groupSecretParams, err := libsignalgo.DeriveGroupSecretParamsFromMasterKey(masterKeyToBytes(groupMasterKey))
	if err != nil {
		log.Err(err).Msg("DeriveGroupSecretParamsFromMasterKey error")
		return nil, err
	}

	gid, err := groupIdentifierFromMasterKey(groupMasterKey)
	if err != nil {
		log.Err(err).Msg("groupIdentifierFromMasterKey error")
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
	for _, member := range encryptedGroup.Members {
		if member == nil {
			continue
		}
		decryptedMember, err := decryptMember(ctx, member, groupSecretParams)
		if err != nil {
			return nil, err
		}
		decryptedGroup.Members = append(decryptedGroup.Members, decryptedMember)
	}

	for _, pendingMember := range encryptedGroup.PendingMembers {
		if pendingMember == nil {
			continue
		}
		decryptedPendingMember, err := decryptPendingMember(ctx, pendingMember, groupSecretParams)
		if err != nil {
			continue
			// decryptPendingMember returns an error if the userID is a PNI, keep decrypting
		}
		decryptedGroup.PendingMembers = append(decryptedGroup.PendingMembers, decryptedPendingMember)
	}

	for _, requestingMember := range encryptedGroup.RequestingMembers {
		if requestingMember == nil {
			continue
		}
		decryptedRequestingMember, err := decryptRequestingMember(ctx, requestingMember, groupSecretParams)
		if err != nil {
			return nil, err
		}
		decryptedGroup.RequestingMembers = append(decryptedGroup.RequestingMembers, decryptedRequestingMember)
	}

	for _, bannedMember := range encryptedGroup.BannedMembers {
		if bannedMember == nil {
			continue
		}
		encryptedUserID := libsignalgo.UUIDCiphertext(bannedMember.UserId)
		userID, err := groupSecretParams.DecryptUUID(encryptedUserID)
		if err != nil {
			log.Err(err).Msg("DecryptUUID UserId error")
			return nil, err
		}
		decryptedGroup.BannedMembers = append(decryptedGroup.BannedMembers, &BannedMember{
			UserID:    userID,
			Timestamp: bannedMember.Timestamp,
		})
	}

	if encryptedGroup.AccessControl != nil {
		decryptedGroup.AccessControl = &GroupAccessControl{
			Members:           (AccessControl)(encryptedGroup.AccessControl.Members),
			Attributes:        (AccessControl)(encryptedGroup.AccessControl.Attributes),
			AddFromInviteLink: (AccessControl)(encryptedGroup.AccessControl.AddFromInviteLink),
		}
	}
	if len(encryptedGroup.InviteLinkPassword) > 0 {
		inviteLinkPassword := InviteLinkPasswordFromBytes(encryptedGroup.InviteLinkPassword)
		decryptedGroup.InviteLinkPassword = &inviteLinkPassword
	}
	return decryptedGroup, nil
}

func decryptGroupPropertyIntoBlob(groupSecretParams libsignalgo.GroupSecretParams, encryptedProperty []byte) (*signalpb.GroupAttributeBlob, error) {
	decryptedProperty, err := groupSecretParams.DecryptBlobWithPadding(encryptedProperty)
	if err != nil {
		return nil, fmt.Errorf("error decrypting blob with padding: %w", err)
	}
	var propertyBlob signalpb.GroupAttributeBlob
	err = proto.Unmarshal(decryptedProperty, &propertyBlob)
	if err != nil {
		return nil, fmt.Errorf("error unmarshalling blob: %w", err)
	}
	return &propertyBlob, nil
}

func encryptBlobIntoGroupProperty(groupSecretParams libsignalgo.GroupSecretParams, attributeBlob *signalpb.GroupAttributeBlob) (*[]byte, error) {
	decryptedProperty, err := proto.Marshal(attributeBlob)
	if err != nil {
		return nil, fmt.Errorf("error marshalling groupProperty: %w", err)
	}
	encryptedProperty, err := groupSecretParams.EncryptBlobWithPaddingDeterministic(libsignalgo.GenerateRandomness(), decryptedProperty, 0)
	if err != nil {
		return nil, fmt.Errorf("error encrypting blob with padding: %w", err)
	}
	return &encryptedProperty, nil
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
		return nil, fmt.Errorf("error deriving group secret params from master key: %w", err)
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
		return nil, fmt.Errorf("failed to get group master key: %w", err)
	}
	if groupMasterKey == "" {
		return nil, fmt.Errorf("No group master key found for group identifier %s", gid)
	}
	return cli.fetchGroupWithMasterKey(ctx, groupMasterKey)
}
func (cli *Client) fetchGroupWithMasterKey(ctx context.Context, groupMasterKey types.SerializedGroupMasterKey) (*Group, error) {
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
	response, err := web.SendHTTPRequest(ctx, http.MethodGet, "/v1/groups", opts)
	if err != nil {
		return nil, err
	}
	if response.StatusCode != 200 {
		return nil, fmt.Errorf("fetchGroupByID SendHTTPRequest bad status: %d", response.StatusCode)
	}
	var encryptedGroup signalpb.Group
	groupBytes, err := io.ReadAll(response.Body)
	if err != nil {
		return nil, err
	}
	err = proto.Unmarshal(groupBytes, &encryptedGroup)
	if err != nil {
		return nil, fmt.Errorf("failed to unmarshal group: %w", err)
	}

	group, err := decryptGroup(ctx, &encryptedGroup, groupMasterKey)
	if err != nil {
		return nil, fmt.Errorf("failed to decrypt group: %w", err)
	}

	// Store the profile keys in case they're new
	for _, member := range group.Members {
		err = cli.Store.ProfileKeyStore.StoreProfileKey(ctx, member.UserID, member.ProfileKey)
		if err != nil {
			return nil, fmt.Errorf("failed to store profile key: %w", err)
		}
	}
	for _, pendingMember := range group.PendingMembers {
		err = cli.Store.ProfileKeyStore.StoreProfileKey(ctx, pendingMember.UserID, pendingMember.ProfileKey)
		if err != nil {
			return nil, fmt.Errorf("failed to store profile key: %w", err)
		}
	}
	for _, requestingMember := range group.RequestingMembers {
		err = cli.Store.ProfileKeyStore.StoreProfileKey(ctx, requestingMember.UserID, requestingMember.ProfileKey)
		if err != nil {
			return nil, fmt.Errorf("failed to store profile key: %w", err)
		}
	}
	return group, nil
}

func (cli *Client) DownloadGroupAvatar(ctx context.Context, group GroupAvatarMeta) ([]byte, error) {
	groupMasterKey := group.getGroupMasterKey()
	avatarPath := group.GetAvatarPath()
	username, password := cli.Store.BasicAuthCreds()
	opts := &web.HTTPReqOpt{
		Host:     web.CDN1Hostname,
		Username: &username,
		Password: &password,
	}
	resp, err := web.SendHTTPRequest(ctx, http.MethodGet, *avatarPath, opts)
	if err != nil {
		return nil, fmt.Errorf("failed to send request: %w", err)
	}
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return nil, fmt.Errorf("unexpected response status %d", resp.StatusCode)
	}
	encryptedAvatar, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("failed to read response: %w", err)
	}

	decrypted, err := decryptGroupAvatar(encryptedAvatar, groupMasterKey)
	if err != nil {
		return nil, fmt.Errorf("failed to decrypt avatar: %w", err)
	}
	return decrypted, nil
}

func (cli *Client) RetrieveGroupByID(ctx context.Context, gid types.GroupIdentifier, revision uint32) (*Group, error) {
	cli.initGroupCache()

	lastFetched, ok := cli.GroupCache.lastFetched[gid]
	if ok && time.Since(lastFetched) < 1*time.Hour {
		group, ok := cli.GroupCache.groups[gid]
		if ok && group.Revision >= revision {
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

// We should store the group master key in the group store as soon as we see it,
// then use the group identifier to refer to groups. As a convenience, we return
// the group identifier, which is derived from the group master key.
func (cli *Client) StoreMasterKey(ctx context.Context, groupMasterKey types.SerializedGroupMasterKey) (types.GroupIdentifier, error) {
	groupIdentifier, err := groupIdentifierFromMasterKey(groupMasterKey)
	if err != nil {
		return "", fmt.Errorf("groupIdentifierFromMasterKey error: %w", err)
	}
	err = cli.Store.GroupStore.StoreMasterKey(ctx, groupIdentifier, groupMasterKey)
	if err != nil {
		return "", fmt.Errorf("StoreMasterKey error: %w", err)
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
			activeCalls: make(map[types.GroupIdentifier]string),
		}
	}
}

type GroupCache struct {
	groups      map[types.GroupIdentifier]*Group
	lastFetched map[types.GroupIdentifier]time.Time
	activeCalls map[types.GroupIdentifier]string
}

func (cli *Client) DecryptGroupChange(ctx context.Context, groupContext *signalpb.GroupContextV2) (*GroupChange, error) {
	masterKeyBytes := libsignalgo.GroupMasterKey(groupContext.MasterKey)
	groupMasterKey := masterKeyFromBytes(masterKeyBytes)
	log := zerolog.Ctx(ctx).With().Str("action", "decrypt group change").Logger()

	encryptedGroupChange := &signalpb.GroupChange{}

	groupChangeBytes := groupContext.GroupChange
	err := proto.Unmarshal(groupChangeBytes, encryptedGroupChange)
	if err != nil {
		return nil, fmt.Errorf("Error unmarshalling group change: %w", err)
	}
	serverSignature := encryptedGroupChange.ServerSignature
	encryptedActionsBytes := encryptedGroupChange.Actions

	err = libsignalgo.ServerPublicParamsVerifySignature(prodServerPublicParams, encryptedActionsBytes, libsignalgo.NotarySignature(serverSignature))
	if err != nil {
		return nil, fmt.Errorf("Failed to verify Server Signature: %w", err)
	}

	encryptedActions := signalpb.GroupChange_Actions{}

	err = proto.Unmarshal(encryptedActionsBytes, &encryptedActions)
	if err != nil {
		return nil, fmt.Errorf("Error unmashalling group change actions: %w", err)
	}

	groupSecretParams, err := libsignalgo.DeriveGroupSecretParamsFromMasterKey(masterKeyToBytes(groupMasterKey))
	if err != nil {
		log.Err(err).Msg("DeriveGroupSecretParamsFromMasterKey error")
		return nil, err
	}

	decryptedGroupChange := &GroupChange{
		groupMasterKey: groupMasterKey,
		Revision:       encryptedActions.Revision,
	}

	if encryptedActions.ModifyTitle != nil {
		titleBlob, err := decryptGroupPropertyIntoBlob(groupSecretParams, encryptedActions.ModifyTitle.Title)
		if err != nil {
			return nil, err
		}
		// The actual title is in the blob
		newTitle := cleanupStringProperty(titleBlob.GetTitle())
		decryptedGroupChange.ModifyTitle = &newTitle
	}
	if encryptedActions.ModifyAvatar != nil {
		decryptedGroupChange.ModifyAvatar = &encryptedActions.ModifyAvatar.Avatar
	}
	if encryptedActions.ModifyDescription != nil {
		descriptionBlob, err := decryptGroupPropertyIntoBlob(groupSecretParams, encryptedActions.ModifyDescription.Description)
		if err == nil {
			// treat a failure in obtaining the description as non-fatal
			newDescription := cleanupStringProperty(descriptionBlob.GetDescription())
			decryptedGroupChange.ModifyDescription = &newDescription
		}
	}

	for _, addMember := range encryptedActions.AddMembers {
		if addMember == nil {
			continue
		}
		decryptedMember, err := decryptMember(ctx, addMember.Added, groupSecretParams)
		if err != nil {
			return nil, err
		}
		decryptedGroupChange.AddMembers = append(decryptedGroupChange.AddMembers, &AddMember{
			GroupMember:        *decryptedMember,
			JoinFromInviteLink: addMember.JoinFromInviteLink,
		})
		err = cli.Store.ProfileKeyStore.StoreProfileKey(ctx, decryptedMember.UserID, decryptedMember.ProfileKey)
		if err != nil {
			log.Err(err).Msg("failed to store profile key")
			return nil, err
		}
	}

	for _, deleteMember := range encryptedActions.DeleteMembers {
		if deleteMember == nil {
			continue
		}
		encryptedUserID := libsignalgo.UUIDCiphertext(deleteMember.DeletedUserId)
		userID, err := groupSecretParams.DecryptUUID(encryptedUserID)
		if err != nil {
			log.Err(err).Msg("DecryptUUID UserId error for deleteMember")
			return nil, err
		}
		decryptedGroupChange.DeleteMembers = append(decryptedGroupChange.DeleteMembers, &userID)
	}

	for _, modifyMemberRole := range encryptedActions.ModifyMemberRoles {
		encryptedUserID := libsignalgo.UUIDCiphertext(modifyMemberRole.UserId)
		userID, err := groupSecretParams.DecryptUUID(encryptedUserID)
		if err != nil {
			log.Err(err).Msg("DecryptUUID UserId error for modifyMemberRole")
			return nil, err
		}
		decryptedGroupChange.ModifyMemberRoles = append(decryptedGroupChange.ModifyMemberRoles, &RoleMember{
			UserID: userID,
			Role:   GroupMemberRole(modifyMemberRole.Role),
		})
	}

	for _, modifyProfileKey := range encryptedActions.ModifyMemberProfileKeys {
		if modifyProfileKey == nil {
			continue
		}
		encryptedUserID := libsignalgo.UUIDCiphertext(modifyProfileKey.UserId)
		userID, err := groupSecretParams.DecryptUUID(encryptedUserID)
		if err != nil {
			log.Err(err).Msg("DecryptUUID UserId error for modifyProfileKey")
			return nil, err
		}
		encryptedProfileKey := libsignalgo.ProfileKeyCiphertext(modifyProfileKey.ProfileKey)
		profileKey, err := groupSecretParams.DecryptProfileKey(encryptedProfileKey, userID)
		if err != nil {
			log.Err(err).Msg("DecryptProfileKey ProfileKey error for modifyProfileKey")
			return nil, err
		}
		decryptedGroupChange.ModifyMemberProfileKeys = append(decryptedGroupChange.ModifyMemberProfileKeys, &ProfileKeyMember{
			UserID:     userID,
			ProfileKey: *profileKey,
		})
		cli.Store.ProfileKeyStore.StoreProfileKey(ctx, userID, *profileKey)
		if err != nil {
			log.Err(err).Msg("failed to store profile key")
			return nil, err
		}
	}

	for _, addPendingMember := range encryptedActions.AddPendingMembers {
		if addPendingMember == nil {
			continue
		}
		pendingMember := addPendingMember.Added
		decryptedPendingMember, err := decryptPendingMember(ctx, pendingMember, groupSecretParams)
		if err != nil {
			continue
			// decryptPendingMember returns an error if the userID is a PNI, keep decrypting
		}
		decryptedGroupChange.AddPendingMembers = append(decryptedGroupChange.AddPendingMembers, decryptedPendingMember)
	}

	for _, deletePendingMember := range encryptedActions.DeletePendingMembers {
		if deletePendingMember == nil {
			continue
		}
		encryptedUserID := libsignalgo.UUIDCiphertext(deletePendingMember.DeletedUserId)
		userID, err := groupSecretParams.DecryptUUID(encryptedUserID)
		if err != nil {
			log.Err(err).Msg("DecryptUUID UserId error for deletePendingMember")
			return nil, err
		}
		decryptedGroupChange.DeletePendingMembers = append(decryptedGroupChange.DeletePendingMembers, &userID)
	}

	for _, promotePendingMember := range encryptedActions.PromotePendingMembers {
		if promotePendingMember == nil {
			continue
		}
		encryptedUserID := libsignalgo.UUIDCiphertext(promotePendingMember.UserId)
		userID, err := groupSecretParams.DecryptUUID(encryptedUserID)
		if err != nil {
			log.Err(err).Msg("DecryptUUID UserId error for promotePendingMember")
			return nil, err
		}
		encryptedProfileKey := libsignalgo.ProfileKeyCiphertext(promotePendingMember.ProfileKey)
		profileKey, err := groupSecretParams.DecryptProfileKey(encryptedProfileKey, userID)
		if err != nil {
			log.Err(err).Msg("DecryptProfileKey ProfileKey error for promotePendingMember")
			return nil, err
		}
		decryptedGroupChange.PromotePendingMembers = append(decryptedGroupChange.PromotePendingMembers, &ProfileKeyMember{
			UserID:     userID,
			ProfileKey: *profileKey,
		})
		cli.Store.ProfileKeyStore.StoreProfileKey(ctx, userID, *profileKey)
		if err != nil {
			log.Err(err).Msg("failed to store profile key")
			return nil, err
		}
	}

	for _, promotePendingMember := range encryptedActions.PromotePendingPniAciMembers {
		// TODO: pretending this is a PendingMember should do for mautrix-signal, but we probably want to treat them separately at some point
		if promotePendingMember == nil {
			continue
		}
		encryptedUserID := libsignalgo.UUIDCiphertext(promotePendingMember.UserId)
		userID, err := groupSecretParams.DecryptUUID(encryptedUserID)
		if err != nil {
			log.Err(err).Msg("DecryptUUID UserId error for promotePendingPniAciMember")
			return nil, err
		}
		encryptedProfileKey := libsignalgo.ProfileKeyCiphertext(promotePendingMember.ProfileKey)
		profileKey, err := groupSecretParams.DecryptProfileKey(encryptedProfileKey, userID)
		if err != nil {
			log.Err(err).Msg("DecryptProfileKey ProfileKey error for promotePendingPniAciMember")
			return nil, err
		}
		decryptedGroupChange.PromotePendingMembers = append(decryptedGroupChange.PromotePendingMembers, &ProfileKeyMember{
			UserID:     userID,
			ProfileKey: *profileKey,
		})
		cli.Store.ProfileKeyStore.StoreProfileKey(ctx, userID, *profileKey)
		if err != nil {
			log.Err(err).Msg("failed to store profile key")
			return nil, err
		}
	}

	for _, addRequestingMember := range encryptedActions.AddRequestingMembers {
		if addRequestingMember == nil {
			continue
		}
		decryptedRequestingMember, err := decryptRequestingMember(ctx, addRequestingMember.Added, groupSecretParams)
		if err != nil {
			return nil, err
		}
		decryptedGroupChange.AddRequestingMembers = append(decryptedGroupChange.AddRequestingMembers, decryptedRequestingMember)
		cli.Store.ProfileKeyStore.StoreProfileKey(ctx, decryptedRequestingMember.UserID, decryptedRequestingMember.ProfileKey)
		if err != nil {
			log.Err(err).Msg("failed to store profile key")
			return nil, err
		}
	}

	for _, deleteRequestingMember := range encryptedActions.DeleteRequestingMembers {
		if deleteRequestingMember == nil {
			continue
		}
		encryptedUserID := libsignalgo.UUIDCiphertext(deleteRequestingMember.DeletedUserId)
		userID, err := groupSecretParams.DecryptUUID(encryptedUserID)
		if err != nil {
			log.Err(err).Msg("DecryptUUID UserId error for deleteRequestingMember")
			return nil, err
		}
		decryptedGroupChange.DeleteRequestingMembers = append(decryptedGroupChange.DeleteRequestingMembers, &userID)
	}

	for _, promoteRequestingMember := range encryptedActions.PromoteRequestingMembers {
		if promoteRequestingMember == nil {
			continue
		}
		encryptedUserID := libsignalgo.UUIDCiphertext(promoteRequestingMember.UserId)
		userID, err := groupSecretParams.DecryptUUID(encryptedUserID)
		if err != nil {
			log.Err(err).Msg("DecryptUUID UserId error for promoteRequestingMember")
			return nil, err
		}
		decryptedGroupChange.PromoteRequestingMembers = append(decryptedGroupChange.PromoteRequestingMembers, &RoleMember{
			UserID: userID,
			Role:   GroupMemberRole(promoteRequestingMember.Role),
		})
	}

	for _, addBannedMember := range encryptedActions.AddBannedMembers {
		if addBannedMember == nil {
			continue
		}
		bannedMember := addBannedMember.Added
		encryptedUserID := libsignalgo.UUIDCiphertext(bannedMember.UserId)
		userID, err := groupSecretParams.DecryptUUID(encryptedUserID)
		if err != nil {
			log.Err(err).Msg("DecryptUUID UserId error for addBannedMember")
			return nil, err
		}
		decryptedGroupChange.AddBannedMembers = append(decryptedGroupChange.AddBannedMembers, &BannedMember{
			UserID:    userID,
			Timestamp: bannedMember.Timestamp,
		})
	}

	for _, deleteBannedMember := range encryptedActions.DeleteBannedMembers {
		if deleteBannedMember == nil {
			continue
		}
		encryptedUserID := libsignalgo.UUIDCiphertext(deleteBannedMember.DeletedUserId)
		userID, err := groupSecretParams.DecryptUUID(encryptedUserID)
		if err != nil {
			log.Err(err).Msg("DecryptUUID UserId error for deleteBannedMember")
			return nil, err
		}
		decryptedGroupChange.DeleteBannedMembers = append(decryptedGroupChange.DeleteBannedMembers, &userID)
	}

	if encryptedActions.ModifyAttributesAccess != nil {
		decryptedGroupChange.ModifyAttributesAccess = (*AccessControl)(&encryptedActions.ModifyAttributesAccess.AttributesAccess)
	}

	if encryptedActions.ModifyMemberAccess != nil {
		decryptedGroupChange.ModifyMemberAccess = (*AccessControl)(&encryptedActions.ModifyMemberAccess.MembersAccess)
	}

	if encryptedActions.ModifyAddFromInviteLinkAccess != nil {
		decryptedGroupChange.ModifyAddFromInviteLinkAccess = (*AccessControl)(&encryptedActions.ModifyAddFromInviteLinkAccess.AddFromInviteLinkAccess)
	}

	if encryptedActions.ModifyAnnouncementsOnly != nil {
		decryptedGroupChange.ModifyAnnouncementsOnly = &encryptedActions.ModifyAnnouncementsOnly.AnnouncementsOnly
	}
	if encryptedActions.ModifyDisappearingMessagesTimer != nil && len(encryptedActions.ModifyDisappearingMessagesTimer.Timer) > 0 {
		timerBlob, err := decryptGroupPropertyIntoBlob(groupSecretParams, encryptedActions.ModifyDisappearingMessagesTimer.Timer)
		if err != nil {
			return nil, err
		}
		newDisappaeringMessagesDuration := timerBlob.GetDisappearingMessagesDuration()
		decryptedGroupChange.ModifyDisappearingMessagesDuration = &newDisappaeringMessagesDuration
	}
	if encryptedActions.ModifyInviteLinkPassword != nil {
		inviteLinkPassword := InviteLinkPasswordFromBytes(encryptedActions.ModifyInviteLinkPassword.InviteLinkPassword)
		decryptedGroupChange.ModifyInviteLinkPassword = &inviteLinkPassword
	}

	return decryptedGroupChange, nil
}

func decryptMember(ctx context.Context, member *signalpb.Member, groupSecretParams libsignalgo.GroupSecretParams) (*GroupMember, error) {
	log := zerolog.Ctx(ctx)
	encryptedUserID := libsignalgo.UUIDCiphertext(member.UserId)
	userID, err := groupSecretParams.DecryptUUID(encryptedUserID)
	if err != nil {
		log.Err(err).Msg("DecryptUUID UserId error")
		return nil, err
	}
	encryptedProfileKey := libsignalgo.ProfileKeyCiphertext(member.ProfileKey)
	profileKey, err := groupSecretParams.DecryptProfileKey(encryptedProfileKey, userID)
	if err != nil {
		log.Err(err).Msg("DecryptProfileKey ProfileKey error")
		return nil, err
	}
	return &GroupMember{
		UserID:           userID,
		ProfileKey:       *profileKey,
		Role:             GroupMemberRole(member.Role),
		JoinedAtRevision: member.JoinedAtRevision,
	}, nil
}

func decryptPendingMember(ctx context.Context, pendingMember *signalpb.PendingMember, groupSecretParams libsignalgo.GroupSecretParams) (*PendingMember, error) {
	log := zerolog.Ctx(ctx)
	encryptedUserID := libsignalgo.UUIDCiphertext(pendingMember.Member.UserId)
	userID, err := groupSecretParams.DecryptUUID(encryptedUserID)
	if err != nil {
		log.Err(err).Msg("DecryptUUID UserId error for pendingMember")
		return nil, err
	}
	// pendingMembers don't have profile keys
	encryptedAddedByUserID := pendingMember.AddedByUserId
	addedByUserId, err := groupSecretParams.DecryptUUID(libsignalgo.UUIDCiphertext(encryptedAddedByUserID))
	if err != nil {
		log.Err(err).Msg("DecryptUUID addedByUserId error for pendingMember")
		return nil, err
	}
	return &PendingMember{
		GroupMember: GroupMember{
			UserID:           userID,
			Role:             GroupMemberRole(pendingMember.Member.Role),
			JoinedAtRevision: pendingMember.Member.JoinedAtRevision,
		},
		AddedByUserID: addedByUserId,
		Timestamp:     pendingMember.Timestamp,
	}, nil
}

func decryptRequestingMember(ctx context.Context, requestingMember *signalpb.RequestingMember, groupSecretParams libsignalgo.GroupSecretParams) (*RequestingMember, error) {
	log := zerolog.Ctx(ctx)
	encryptedUserID := libsignalgo.UUIDCiphertext(requestingMember.UserId)
	userID, err := groupSecretParams.DecryptUUID(encryptedUserID)
	if err != nil {
		log.Err(err).Msg("DecryptUUID UserId error for requestingMember")
		return nil, err
	}
	encryptedProfileKey := libsignalgo.ProfileKeyCiphertext(requestingMember.ProfileKey)
	profileKey, err := groupSecretParams.DecryptProfileKey(encryptedProfileKey, userID)
	if err != nil {
		log.Err(err).Msg("DecryptProfileKey ProfileKey error for requestingMember")
		return nil, err
	}
	return &RequestingMember{
		UserID:     userID,
		ProfileKey: *profileKey,
		Timestamp:  requestingMember.Timestamp,
	}, nil
}

func (cli *Client) EncryptAndSignGroupChange(ctx context.Context, decryptedGroupChange *GroupChange, gid types.GroupIdentifier) (*signalpb.GroupChange, error) {
	log := zerolog.Ctx(ctx).With().Str("action", "EncryptGroupChange").Logger()
	groupMasterKey := decryptedGroupChange.groupMasterKey
	masterKeyBytes := masterKeyToBytes(groupMasterKey)
	groupSecretParams, err := libsignalgo.DeriveGroupSecretParamsFromMasterKey(masterKeyBytes)
	if err != nil {
		log.Err(err).Msg("Could not get groupSecretParams from master key")
		return nil, err
	}
	groupChangeActions := &signalpb.GroupChange_Actions{Revision: decryptedGroupChange.Revision}
	if decryptedGroupChange.ModifyTitle != nil {
		attributeBlob := signalpb.GroupAttributeBlob{Content: &signalpb.GroupAttributeBlob_Title{Title: *decryptedGroupChange.ModifyTitle}}
		encryptedTitle, err := encryptBlobIntoGroupProperty(groupSecretParams, &attributeBlob)
		if err != nil {
			log.Err(err).Msg("Could not get encrypt Title")
			return nil, err
		}
		groupChangeActions.ModifyTitle = &signalpb.GroupChange_Actions_ModifyTitleAction{Title: *encryptedTitle}
	}
	if decryptedGroupChange.ModifyDescription != nil {
		attributeBlob := signalpb.GroupAttributeBlob{Content: &signalpb.GroupAttributeBlob_Description{Description: *decryptedGroupChange.ModifyDescription}}
		encryptedDescription, err := encryptBlobIntoGroupProperty(groupSecretParams, &attributeBlob)
		if err != nil {
			log.Err(err).Msg("Could not get encrypt description")
			return nil, err
		}
		groupChangeActions.ModifyDescription = &signalpb.GroupChange_Actions_ModifyDescriptionAction{Description: *encryptedDescription}
	}
	if decryptedGroupChange.ModifyAvatar != nil {
		groupChangeActions.ModifyAvatar = &signalpb.GroupChange_Actions_ModifyAvatarAction{Avatar: *decryptedGroupChange.ModifyAvatar}
	}
	for _, addMember := range decryptedGroupChange.AddMembers {
		encryptedMember, err := cli.encryptMember(ctx, &addMember.GroupMember, &groupSecretParams)
		if err != nil {
			log.Err(err).Msg("Failed to encrypt GroupMember")
		}
		groupChangeActions.AddMembers = append(groupChangeActions.AddMembers, &signalpb.GroupChange_Actions_AddMemberAction{
			Added:              encryptedMember,
			JoinFromInviteLink: addMember.JoinFromInviteLink,
		})
	}
	for _, deleteMember := range decryptedGroupChange.DeleteMembers {
		encryptedUserID, err := groupSecretParams.EncryptUUID(*deleteMember)
		if err != nil {
			log.Err(err).Msg("Encrypt UserId error for deleteMember")
			return nil, err
		}
		groupChangeActions.DeleteMembers = append(groupChangeActions.DeleteMembers, &signalpb.GroupChange_Actions_DeleteMemberAction{
			DeletedUserId: encryptedUserID[:],
		})
	}
	for _, modifyMemberRoles := range decryptedGroupChange.ModifyMemberRoles {
		encryptedUserID, err := groupSecretParams.EncryptUUID(modifyMemberRoles.UserID)
		if err != nil {
			log.Err(err).Msg("Encrypt UserId error for modifyMemberRoles")
			return nil, err
		}
		groupChangeActions.ModifyMemberRoles = append(groupChangeActions.ModifyMemberRoles, &signalpb.GroupChange_Actions_ModifyMemberRoleAction{
			UserId: encryptedUserID[:],
			Role:   signalpb.Member_Role(modifyMemberRoles.Role),
		})
	}
	// for _, addPendingMember := range decryptedGroupChange.AddPendingMembers {
	// }
	for _, deletePendingMember := range decryptedGroupChange.DeletePendingMembers {
		encryptedUserID, err := groupSecretParams.EncryptUUID(*deletePendingMember)
		if err != nil {
			log.Err(err).Msg("Encrypt UserId error for deletePendingMember")
			return nil, err
		}
		groupChangeActions.DeletePendingMembers = append(groupChangeActions.DeletePendingMembers, &signalpb.GroupChange_Actions_DeletePendingMemberAction{
			DeletedUserId: encryptedUserID[:],
		})
	}
	for _, promotePendingMember := range decryptedGroupChange.PromotePendingMembers {
		expiringProfileKeyCredential, err := cli.FetchExpiringProfileKeyCredentialById(ctx, promotePendingMember.UserID)
		if err != nil {
			log.Err(err).Msg("failed getting expiring profile key credential for addMember")
			return nil, err
		}
		presentation, err := groupSecretParams.CreateExpiringProfileKeyCredentialPresentation(
			prodServerPublicParams,
			*expiringProfileKeyCredential,
		)
		if err != nil {
			log.Err(err).Msg("failed creating expiring profile key credential presentation for addMember")
			return nil, err
		}
		groupChangeActions.PromotePendingMembers = append(groupChangeActions.PromotePendingMembers, &signalpb.GroupChange_Actions_PromotePendingMemberAction{
			Presentation: *presentation,
		})
	}
	for _, addRequestingMember := range decryptedGroupChange.AddRequestingMembers {
		expiringProfileKeyCredential, err := cli.FetchExpiringProfileKeyCredentialById(ctx, addRequestingMember.UserID)
		if err != nil {
			log.Err(err).Msg("failed getting expiring profile key credential for addMember")
			return nil, err
		}
		presentation, err := groupSecretParams.CreateExpiringProfileKeyCredentialPresentation(
			prodServerPublicParams,
			*expiringProfileKeyCredential,
		)
		if err != nil {
			log.Err(err).Msg("failed creating expiring profile key credential presentation for addMember")
			return nil, err
		}
		groupChangeActions.AddRequestingMembers = append(groupChangeActions.AddRequestingMembers, &signalpb.GroupChange_Actions_AddRequestingMemberAction{
			Added: &signalpb.RequestingMember{
				Presentation: *presentation,
			},
		})
	}
	for _, deleteRequestingMember := range decryptedGroupChange.DeleteRequestingMembers {
		encryptedUserID, err := groupSecretParams.EncryptUUID(*deleteRequestingMember)
		if err != nil {
			log.Err(err).Msg("Encrypt UserId error for promotePendingMember")
			return nil, err
		}
		groupChangeActions.DeleteRequestingMembers = append(groupChangeActions.DeleteRequestingMembers, &signalpb.GroupChange_Actions_DeleteRequestingMemberAction{
			DeletedUserId: encryptedUserID[:],
		})
	}
	for _, promoteRequestingMember := range decryptedGroupChange.PromoteRequestingMembers {
		encryptedUserID, err := groupSecretParams.EncryptUUID(promoteRequestingMember.UserID)
		if err != nil {
			log.Err(err).Msg("Encrypt UserId error for promoteRequestingMember")
			return nil, err
		}

		groupChangeActions.PromoteRequestingMembers = append(groupChangeActions.PromoteRequestingMembers, &signalpb.GroupChange_Actions_PromoteRequestingMemberAction{
			UserId: encryptedUserID[:],
			Role:   signalpb.Member_Role(promoteRequestingMember.Role),
		})
	}
	for _, addBannedMember := range decryptedGroupChange.AddBannedMembers {
		encryptedUserID, err := groupSecretParams.EncryptUUID(addBannedMember.UserID)
		if err != nil {
			log.Err(err).Msg("Encrypt UserId error for promoteRequestingMember")
			return nil, err
		}
		groupChangeActions.AddBannedMembers = append(groupChangeActions.AddBannedMembers, &signalpb.GroupChange_Actions_AddBannedMemberAction{
			Added: &signalpb.BannedMember{
				UserId:    encryptedUserID[:],
				Timestamp: addBannedMember.Timestamp,
			},
		})
	}
	for _, deleteBannedMember := range decryptedGroupChange.DeleteBannedMembers {
		encryptedUserID, err := groupSecretParams.EncryptUUID(*deleteBannedMember)
		if err != nil {
			log.Err(err).Msg("Encrypt UserId error for promoteRequestingMember")
			return nil, err
		}
		groupChangeActions.DeleteBannedMembers = append(groupChangeActions.DeleteBannedMembers, &signalpb.GroupChange_Actions_DeleteBannedMemberAction{
			DeletedUserId: encryptedUserID[:],
		})
	}
	if decryptedGroupChange.ModifyAnnouncementsOnly != nil {
		groupChangeActions.ModifyAnnouncementsOnly = &signalpb.GroupChange_Actions_ModifyAnnouncementsOnlyAction{
			AnnouncementsOnly: *decryptedGroupChange.ModifyAnnouncementsOnly,
		}
	}
	if decryptedGroupChange.ModifyAttributesAccess != nil {
		groupChangeActions.ModifyAttributesAccess = &signalpb.GroupChange_Actions_ModifyAttributesAccessControlAction{
			AttributesAccess: signalpb.AccessControl_AccessRequired(*decryptedGroupChange.ModifyAttributesAccess),
		}
	}
	if decryptedGroupChange.ModifyMemberAccess != nil {
		groupChangeActions.ModifyMemberAccess = &signalpb.GroupChange_Actions_ModifyMembersAccessControlAction{
			MembersAccess: signalpb.AccessControl_AccessRequired(*decryptedGroupChange.ModifyMemberAccess),
		}
	}
	if decryptedGroupChange.ModifyAddFromInviteLinkAccess != nil {
		groupChangeActions.ModifyAddFromInviteLinkAccess = &signalpb.GroupChange_Actions_ModifyAddFromInviteLinkAccessControlAction{
			AddFromInviteLinkAccess: signalpb.AccessControl_AccessRequired(*decryptedGroupChange.ModifyAddFromInviteLinkAccess),
		}
	}
	if decryptedGroupChange.ModifyDisappearingMessagesDuration != nil {
		attributeBlob := signalpb.GroupAttributeBlob{Content: &signalpb.GroupAttributeBlob_DisappearingMessagesDuration{DisappearingMessagesDuration: *decryptedGroupChange.ModifyDisappearingMessagesDuration}}
		encryptedTimer, err := encryptBlobIntoGroupProperty(groupSecretParams, &attributeBlob)
		if err != nil {
			log.Err(err).Msg("Could not get encrypt Title")
			return nil, err
		}
		groupChangeActions.ModifyDisappearingMessagesTimer = &signalpb.GroupChange_Actions_ModifyDisappearingMessagesTimerAction{Timer: *encryptedTimer}
	}
	if decryptedGroupChange.ModifyInviteLinkPassword != nil {
		inviteLinkPasswordBytes, err := inviteLinkPasswordToBytes(*decryptedGroupChange.ModifyInviteLinkPassword)
		if err != nil {
			log.Err(err).Msg("Failed to decode invite link password")
		}
		groupChangeActions.ModifyInviteLinkPassword = &signalpb.GroupChange_Actions_ModifyInviteLinkPasswordAction{
			InviteLinkPassword: inviteLinkPasswordBytes,
		}
	}

	return cli.patchGroup(ctx, groupChangeActions, groupMasterKey, nil)
}

func (cli *Client) encryptMember(ctx context.Context, member *GroupMember, groupSecretParams *libsignalgo.GroupSecretParams) (*signalpb.Member, error) {
	log := zerolog.Ctx(ctx)
	expiringProfileKeyCredential, err := cli.FetchExpiringProfileKeyCredentialById(ctx, member.UserID)
	if err != nil {
		log.Err(err).Msg("failed getting expiring profile key credential for addMember")
		return nil, err
	}
	presentation, err := groupSecretParams.CreateExpiringProfileKeyCredentialPresentation(
		prodServerPublicParams,
		*expiringProfileKeyCredential,
	)
	if err != nil {
		log.Err(err).Msg("failed creating expiring profile key credential presentation for addMember")
		return nil, err
	}
	encryptedMember := signalpb.Member{
		Presentation: *presentation,
		Role:         signalpb.Member_Role(member.Role),
	}
	return &encryptedMember, nil
}

var (
	NoContentError               = RespError{Err: "NoContentError"}
	GroupPatchNotAcceptedError   = RespError{Err: "GroupPatchNotAcceptedError"}
	ConflictError                = RespError{Err: "ConflictError"}
	AuthorizationFailedError     = RespError{Err: "AuthorizationFailedError"}
	NotFoundError                = RespError{Err: "NotFoundError"}
	ContactManifestMismatchError = RespError{Err: "ContactManifestMismatchError"}
	RateLimitError               = RespError{Err: "RateLimitError"}
	DeprecatedVersionError       = RespError{Err: "DeprecatedVersionError"}
	GroupExistsError             = RespError{Err: "GroupExistsError"}
)

type RespError struct {
	Err string
}

func (e RespError) Error() string {
	return e.Err
}

func (cli *Client) patchGroup(ctx context.Context, groupChange *signalpb.GroupChange_Actions, groupMasterKey types.SerializedGroupMasterKey, groupLinkPassword []byte) (*signalpb.GroupChange, error) {
	log := zerolog.Ctx(ctx).With().Str("action", "patchGroup").Logger()
	groupAuth, err := cli.GetAuthorizationForToday(ctx, masterKeyToBytes(groupMasterKey))
	if err != nil {
		log.Err(err).Msg("Failed to get Authorization for today")
		return nil, err
	}
	var path string
	if groupLinkPassword == nil {
		path = "/v1/groups/"
	} else {
		path = fmt.Sprintf("/v1/groups/?inviteLinkPassword=%s", base64.StdEncoding.EncodeToString(groupLinkPassword))
	}
	requestBody, err := proto.Marshal(groupChange)
	if err != nil {
		log.Err(err).Msg("Failed to marshal request")
		return nil, err
	}
	opts := &web.HTTPReqOpt{
		Username:    &groupAuth.Username,
		Password:    &groupAuth.Password,
		ContentType: web.ContentTypeProtobuf,
		Body:        requestBody,
		Host:        web.StorageHostname,
	}
	resp, err := web.SendHTTPRequest(ctx, http.MethodPatch, path, opts)
	if err != nil {
		return nil, fmt.Errorf("SendRequest error: %w", err)
	}
	switch resp.StatusCode {
	case http.StatusNoContent:
		return nil, NoContentError
	case http.StatusBadRequest:
		return nil, GroupPatchNotAcceptedError
	case http.StatusForbidden:
		return nil, AuthorizationFailedError
	case http.StatusNotFound:
		return nil, NotFoundError
	case http.StatusConflict:
		if resp.Body != nil {
			return nil, ContactManifestMismatchError
		} else {
			return nil, ConflictError
		}
	case http.StatusTooManyRequests:
		return nil, RateLimitError
	case 499:
		return nil, DeprecatedVersionError
	}
	if resp.Body == nil {
		return nil, errors.New("no response body")
	}
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("failed to read storage manifest response: %w", err)
	}
	signedGroupChange := signalpb.GroupChange{}
	err = proto.Unmarshal(body, &signedGroupChange)
	if err != nil {
		return nil, fmt.Errorf("failed to unmarshal signed groupChange: %w", err)
	}
	return &signedGroupChange, nil
}

func (cli *Client) UpdateGroup(ctx context.Context, groupChange *GroupChange, gid types.GroupIdentifier) (uint32, error) {
	log := zerolog.Ctx(ctx).With().Str("action", "UpdateGroup").Logger()
	groupMasterKey, err := cli.Store.GroupStore.MasterKeyFromGroupIdentifier(ctx, gid)
	if err != nil {
		log.Err(err).Msg("Could not get master key from group id")
		return 0, err
	}
	groupChange.groupMasterKey = groupMasterKey
	masterKeyBytes := masterKeyToBytes(groupMasterKey)
	var refetchedAddMemberCredentials bool
	var signedGroupChange *signalpb.GroupChange
	group, err := cli.RetrieveGroupByID(ctx, gid, 0)
	if err != nil {
		log.Err(err).Msg("Failed to retrieve Group")
	}
	if group.InviteLinkPassword == nil && groupChange.ModifyAddFromInviteLinkAccess != nil && groupChange.ModifyInviteLinkPassword != nil {
		inviteLinkPasswordBytes := make([]byte, 16)
		rand.Read(inviteLinkPasswordBytes)
		inviteLinkPassword := InviteLinkPasswordFromBytes(inviteLinkPasswordBytes)
		groupChange.ModifyInviteLinkPassword = &inviteLinkPassword
	}
	groupChange.Revision = group.Revision + 1
	for attempt := 0; attempt < 5; attempt++ {
		signedGroupChange, err = cli.EncryptAndSignGroupChange(ctx, groupChange, gid)
		if errors.Is(err, GroupPatchNotAcceptedError) {
			log.Warn().Str("Error applying GroupChange, retrying...", err.Error())
			if len(groupChange.AddMembers) > 0 && !refetchedAddMemberCredentials {
				refetchedAddMemberCredentials = true
				// change = refetchAddMemberCredentials(change); TODO
			} else {
				return 0, fmt.Errorf("Group Change Failed: %w", err)
			}
		} else if errors.Is(err, ConflictError) {
			delete(cli.GroupCache.groups, gid)
			delete(cli.GroupCache.lastFetched, gid)
			delete(cli.GroupCache.activeCalls, gid)
			group, err = cli.RetrieveGroupByID(ctx, gid, 0)
			groupChange.resolveConflict(group)
			if groupChange.isEmptpy() {
				log.Debug().Msg("Change is empty after conflict resolution")
			}
			groupChange.Revision = group.Revision + 1
		} else {
			break
		}
	}
	delete(cli.GroupCache.groups, gid)
	delete(cli.GroupCache.lastFetched, gid)
	delete(cli.GroupCache.activeCalls, gid)
	if err != nil {
		log.Err(err).Msg("couldn't patch group on server")
		return 0, err
	}
	groupChangeBytes, err := proto.Marshal(signedGroupChange)
	if err != nil {
		log.Err(err).Msg("Error marshalling signed GroupChange")
		return 0, err
	}
	groupContext := &signalpb.GroupContextV2{Revision: &groupChange.Revision, GroupChange: groupChangeBytes, MasterKey: masterKeyBytes[:]}
	_, err = cli.SendGroupChange(ctx, group, groupContext, groupChange)
	if err != nil {
		log.Err(err).Msg("Error sending GroupChange to group members")
	}
	return groupChange.Revision, nil
}

func (cli *Client) EncryptGroup(ctx context.Context, decryptedGroup *Group, groupSecretParams libsignalgo.GroupSecretParams) (*signalpb.Group, error) {
	log := zerolog.Ctx(ctx)
	attributeBlob := signalpb.GroupAttributeBlob{Content: &signalpb.GroupAttributeBlob_Title{Title: decryptedGroup.Title}}
	encryptedTitle, err := encryptBlobIntoGroupProperty(groupSecretParams, &attributeBlob)
	if err != nil {
		log.Err(err).Msg("Could not get encrypt Title")
		return nil, err
	}
	groupPublicParams, err := groupSecretParams.GetPublicParams()
	if err != nil {
		log.Err(err).Msg("Couldn't get public params from GroupSecretParams")
		return nil, err
	}
	encryptedGroup := &signalpb.Group{
		PublicKey:         groupPublicParams[:],
		Title:             *encryptedTitle,
		Avatar:            decryptedGroup.AvatarPath,
		AnnouncementsOnly: decryptedGroup.AnnouncementsOnly,
		Revision:          0,
	}
	if decryptedGroup.Description != "" {
		attributeBlob := signalpb.GroupAttributeBlob{Content: &signalpb.GroupAttributeBlob_Description{Description: decryptedGroup.Description}}
		encryptedDescription, err := encryptBlobIntoGroupProperty(groupSecretParams, &attributeBlob)
		if err != nil {
			log.Err(err).Msg("Could not get encrypt Description")
			return nil, err
		}
		encryptedGroup.Description = *encryptedDescription
	}
	if decryptedGroup.AccessControl != nil {
		encryptedGroup.AccessControl = &signalpb.AccessControl{
			Members:           signalpb.AccessControl_AccessRequired(decryptedGroup.AccessControl.Members),
			Attributes:        signalpb.AccessControl_AccessRequired(decryptedGroup.AccessControl.Attributes),
			AddFromInviteLink: signalpb.AccessControl_AccessRequired(decryptedGroup.AccessControl.AddFromInviteLink),
		}
		if decryptedGroup.AccessControl.AddFromInviteLink != AccessControl_UNSATISFIABLE {
			inviteLinkPasswordBytes := make([]byte, 16)
			rand.Read(inviteLinkPasswordBytes)
			encryptedGroup.InviteLinkPassword = inviteLinkPasswordBytes
		}
	}
	for _, member := range decryptedGroup.Members {
		encryptedMember, err := cli.encryptMember(ctx, member, &groupSecretParams)
		if err != nil {
			log.Err(err).Msg("Failed to encrypt GroupMember")
		}
		encryptedGroup.Members = append(encryptedGroup.Members, encryptedMember)
	}
	return encryptedGroup, nil
}

func (cli *Client) CreateGroupOnServer(ctx context.Context, decryptedGroup *Group, avatarBytes []byte) (*Group, error) {
	log := zerolog.Ctx(ctx).With().Str("action", "CreateGroupOnServer").Logger()
	masterKeyByteArray := make([]byte, 32)
	rand.Read(masterKeyByteArray)
	masterKeyBytes := libsignalgo.GroupMasterKey(masterKeyByteArray)
	groupMasterKey := masterKeyFromBytes(masterKeyBytes)
	groupId, err := groupIdentifierFromMasterKey(groupMasterKey)
	if err != nil {
		log.Err(err).Msg("Couldn't get gid from masterkey")
		return nil, err
	}
	err = cli.Store.GroupStore.StoreMasterKey(ctx, groupId, groupMasterKey)
	if err != nil {
		return nil, fmt.Errorf("StoreMasterKey error: %w", err)
	}
	log.Debug().Msg(string(groupMasterKey))
	groupSecretParams, err := libsignalgo.DeriveGroupSecretParamsFromMasterKey(masterKeyBytes)
	if err != nil {
		log.Err(err).Msg("DeriveGroupSecretParamsFromMasterKey error")
		return nil, err
	}
	if len(avatarBytes) > 0 {
		avatarPath, err := cli.UploadGroupAvatar(ctx, avatarBytes, groupId)
		if err != nil {
			log.Err(err).Msg("Failed to upload group avatar")
			return nil, err
		}
		decryptedGroup.AvatarPath = *avatarPath
	}
	encryptedGroup, err := cli.EncryptGroup(ctx, decryptedGroup, groupSecretParams)
	if err != nil {
		log.Err(err).Msg("Failed to encrypt group")
		return nil, err
	}
	log.Debug().Stringer("groupID", groupId)
	groupAuth, err := cli.GetAuthorizationForToday(ctx, masterKeyBytes)
	if err != nil {
		log.Err(err).Msg("Failed to get Authorization for today")
		return nil, err
	}
	path := "/v1/groups/"
	requestBody, err := proto.Marshal(encryptedGroup)
	if err != nil {
		log.Err(err).Msg("Failed to marshal request")
		return nil, err
	}
	opts := &web.HTTPReqOpt{
		Username:    &groupAuth.Username,
		Password:    &groupAuth.Password,
		ContentType: web.ContentTypeProtobuf,
		Body:        requestBody,
		Host:        web.StorageHostname,
	}
	resp, err := web.SendHTTPRequest(ctx, http.MethodPut, path, opts)
	if err != nil {
		return nil, fmt.Errorf("SendRequest error: %w", err)
	}
	switch resp.StatusCode {
	case http.StatusNoContent:
		return nil, NoContentError
	case http.StatusForbidden:
		return nil, AuthorizationFailedError
	case http.StatusNotFound:
		return nil, NotFoundError
	case http.StatusConflict:
		return nil, GroupExistsError
	case http.StatusTooManyRequests:
		return nil, RateLimitError
	case 499:
		return nil, DeprecatedVersionError
	case http.StatusBadRequest:
		return nil, fmt.Errorf("failed to put new group: bad request")
	}
	group, err := cli.fetchGroupWithMasterKey(ctx, groupMasterKey)
	if err != nil {
		return nil, fmt.Errorf("failed to get new group: %w", err)
	}
	log.Debug().Stringer("group id", group.GroupIdentifier).Msg("new group created")
	return group, nil
}

func GenerateInviteLinkPassword() types.SerializedInviteLinkPassword {
	inviteLinkPasswordBytes := make([]byte, 16)
	rand.Read(inviteLinkPasswordBytes)
	return InviteLinkPasswordFromBytes(inviteLinkPasswordBytes)
}
