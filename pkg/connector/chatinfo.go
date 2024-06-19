// mautrix-signal - A Matrix-Signal puppeting bridge.
// Copyright (C) 2024 Tulir Asokan
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

package connector

import (
	"context"
	"crypto/sha256"
	"errors"
	"fmt"
	"strconv"
	"strings"

	"github.com/google/uuid"
	"github.com/rs/zerolog"
	"maunium.net/go/mautrix/bridgev2"
	"maunium.net/go/mautrix/bridgev2/networkid"

	"go.mau.fi/mautrix-signal/pkg/libsignalgo"
	"go.mau.fi/mautrix-signal/pkg/signalmeow/types"
)

const PrivateChatTopic = "Signal private chat"
const NoteToSelfName = "Signal Note to Self"

func (s *SignalClient) GetUserInfo(ctx context.Context, ghost *bridgev2.Ghost) (*bridgev2.UserInfo, error) {
	userID, err := parseUserID(ghost.ID)
	if err != nil {
		return nil, err
	}
	contact, err := s.Client.ContactByACI(ctx, userID)
	if err != nil {
		return nil, err
	}
	return s.contactToUserInfo(contact), nil
}

func (s *SignalClient) GetChatInfo(ctx context.Context, portal *bridgev2.Portal) (*bridgev2.PortalInfo, error) {
	userID, groupID, err := s.parsePortalID(portal.ID)
	if err != nil {
		return nil, err
	}
	if groupID != "" {
		groupInfo, err := s.Client.RetrieveGroupByID(ctx, groupID, 0)
		if err != nil {
			return nil, err
		}
		isDM := false
		isSpace := false
		members := make([]networkid.UserID, len(groupInfo.Members))
		for i, member := range groupInfo.Members {
			members[i] = makeUserID(member.ACI)
		}
		return &bridgev2.PortalInfo{
			Name:  &groupInfo.Title,
			Topic: &groupInfo.Description,
			Avatar: &bridgev2.Avatar{
				ID: makeAvatarPathID(groupInfo.AvatarPath),
				Get: func(ctx context.Context) ([]byte, error) {
					return s.Client.DownloadGroupAvatar(ctx, groupInfo)
				},
				Remove: groupInfo.AvatarPath == "",
			},
			Members:      members,
			IsDirectChat: &isDM,
			IsSpace:      &isSpace,
		}, nil
	} else {
		aci, pni := serviceIDToACIAndPNI(userID)
		contact, err := s.Client.Store.RecipientStore.LoadAndUpdateRecipient(ctx, aci, pni, nil)
		if err != nil {
			return nil, err
		}
		return s.makeCreateDMResponse(contact).PortalInfo, nil
	}
}

func (s *SignalClient) contactToUserInfo(contact *types.Recipient) *bridgev2.UserInfo {
	isBot := false
	ui := &bridgev2.UserInfo{
		IsBot: &isBot,
	}
	name := s.Main.Config.FormatDisplayname(contact)
	ui.Name = &name
	if s.Main.Config.UseContactAvatars && contact.ContactAvatar.Hash != "" {
		ui.Avatar = &bridgev2.Avatar{
			ID: networkid.AvatarID("hash:" + contact.ContactAvatar.Hash),
			Get: func(ctx context.Context) ([]byte, error) {
				if contact.ContactAvatar.Image == nil {
					return nil, fmt.Errorf("contact avatar not available")
				}
				return contact.ContactAvatar.Image, nil
			},
		}
	} else if contact.Profile.AvatarPath != "" {
		ui.Avatar = &bridgev2.Avatar{
			ID: makeAvatarPathID(contact.Profile.AvatarPath),
			Get: func(ctx context.Context) ([]byte, error) {
				return s.Client.DownloadUserAvatar(ctx, contact.Profile.AvatarPath, contact.Profile.Key)
			},
		}
	} else {
		ui.Avatar = &bridgev2.Avatar{
			ID:     "",
			Remove: true,
		}
	}
	return ui
}

func (s *SignalClient) ResolveIdentifier(ctx context.Context, number string, createChat bool) (*bridgev2.ResolveIdentifierResponse, error) {
	number, err := bridgev2.CleanPhoneNumber(number)
	if err != nil {
		return nil, err
	}
	e164Number, err := strconv.ParseUint(strings.TrimPrefix(number, "+"), 10, 64)
	if err != nil {
		return nil, fmt.Errorf("error parsing phone number: %w", err)
	}
	e164String := fmt.Sprintf("+%d", e164Number)
	var aci, pni uuid.UUID
	var recipient *types.Recipient
	if recipient, err = s.Client.ContactByE164(ctx, e164String); err != nil {
		return nil, fmt.Errorf("error looking up number in local contact list: %w", err)
	} else if recipient != nil {
		aci = recipient.ACI
		pni = recipient.PNI
	} else if resp, err := s.Client.LookupPhone(ctx, e164Number); err != nil {
		return nil, fmt.Errorf("error looking up number on server: %w", err)
	} else {
		aci = resp[e164Number].ACI
		pni = resp[e164Number].PNI
		if aci == uuid.Nil && pni == uuid.Nil {
			return nil, errors.New("user not found on Signal")
		}
		recipient, err = s.Client.Store.RecipientStore.UpdateRecipientE164(ctx, aci, pni, e164String)
		if err != nil {
			zerolog.Ctx(ctx).Err(err).Msg("Failed to save recipient entry after looking up phone")
		}
		aci, pni = recipient.ACI, recipient.PNI
	}
	zerolog.Ctx(ctx).Debug().
		Uint64("e164", e164Number).
		Stringer("aci", aci).
		Stringer("pni", pni).
		Msg("Found resolve identifier target user")

	// createChat is a no-op: chats don't need to be created, and we always return chat info
	if aci != uuid.Nil {
		ghost, err := s.Main.Bridge.GetGhostByID(ctx, makeUserID(aci))
		if err != nil {
			return nil, fmt.Errorf("failed to get ghost: %w", err)
		}
		return &bridgev2.ResolveIdentifierResponse{
			UserID:   makeUserID(aci),
			UserInfo: s.contactToUserInfo(recipient),
			Ghost:    ghost,
			Chat:     s.makeCreateDMResponse(recipient),
		}, nil
	} else {
		return &bridgev2.ResolveIdentifierResponse{
			UserID:   makeUserIDFromServiceID(libsignalgo.NewPNIServiceID(pni)),
			UserInfo: s.contactToUserInfo(recipient),
			Chat:     s.makeCreateDMResponse(recipient),
		}, nil
	}
}

func (s *SignalClient) CreateGroup(ctx context.Context, name string, users ...networkid.UserID) (*bridgev2.CreateChatResponse, error) {
	//TODO implement me
	return nil, fmt.Errorf("not implemented")
}

func (s *SignalClient) makeCreateDMResponse(recipient *types.Recipient) *bridgev2.CreateChatResponse {
	isDirectChat := true
	isSpace := false
	name := ""
	topic := PrivateChatTopic
	members := []networkid.UserID{makeUserID(s.Client.Store.ACI)}
	if s.Main.Config.NumberInTopic && recipient.E164 != "" {
		topic = fmt.Sprintf("%s with %s", PrivateChatTopic, recipient.E164)
	}
	var serviceID libsignalgo.ServiceID
	var avatar *bridgev2.Avatar
	if recipient.ACI == uuid.Nil {
		name = s.Main.Config.FormatDisplayname(recipient)
		serviceID = libsignalgo.NewPNIServiceID(recipient.PNI)
	} else {
		if recipient.ACI == s.Client.Store.ACI {
			name = NoteToSelfName
			avatar = &bridgev2.Avatar{
				ID:     networkid.AvatarID(s.Main.Config.NoteToSelfAvatar),
				Remove: len(s.Main.Config.NoteToSelfAvatar) == 0,
				MXC:    s.Main.Config.NoteToSelfAvatar,
				Hash:   sha256.Sum256([]byte(s.Main.Config.NoteToSelfAvatar)),
			}
		} else {
			// The other user is only present if their ACI is known
			members = append(members, makeUserID(recipient.ACI))
		}
		serviceID = libsignalgo.NewACIServiceID(recipient.ACI)
	}
	return &bridgev2.CreateChatResponse{
		PortalID: s.makeDMPortalKey(serviceID),
		PortalInfo: &bridgev2.PortalInfo{
			Name:         &name,
			Avatar:       avatar,
			Topic:        &topic,
			Members:      members,
			IsDirectChat: &isDirectChat,
			IsSpace:      &isSpace,
		},
	}
}

func makeAvatarPathID(avatarPath string) networkid.AvatarID {
	if avatarPath == "" {
		return ""
	}
	return networkid.AvatarID("path:" + avatarPath)
}

func serviceIDToACIAndPNI(serviceID libsignalgo.ServiceID) (aci, pni uuid.UUID) {
	if serviceID.Type == libsignalgo.ServiceIDTypeACI {
		return serviceID.UUID, uuid.Nil
	} else {
		return uuid.Nil, serviceID.UUID
	}
}
