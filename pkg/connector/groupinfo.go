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
	"fmt"
	"time"

	"github.com/google/uuid"
	"github.com/rs/zerolog"
	"go.mau.fi/util/jsontime"
	"go.mau.fi/util/ptr"
	"maunium.net/go/mautrix/bridgev2"
	"maunium.net/go/mautrix/bridgev2/database"
	"maunium.net/go/mautrix/bridgev2/networkid"
	"maunium.net/go/mautrix/event"

	"go.mau.fi/mautrix-signal/pkg/libsignalgo"
	"go.mau.fi/mautrix-signal/pkg/signalid"
	"go.mau.fi/mautrix-signal/pkg/signalmeow"
	"go.mau.fi/mautrix-signal/pkg/signalmeow/store"
	"go.mau.fi/mautrix-signal/pkg/signalmeow/types"
)

var defaultPL = 0
var moderatorPL = 50

func roleToPL(role signalmeow.GroupMemberRole) *int {
	switch role {
	case signalmeow.GroupMember_ADMINISTRATOR:
		return &moderatorPL
	case signalmeow.GroupMember_DEFAULT:
		fallthrough
	default:
		return &defaultPL
	}
}

func applyAnnouncementsOnly(plc *bridgev2.PowerLevelOverrides, announcementsOnly bool) {
	if announcementsOnly {
		plc.EventsDefault = &moderatorPL
	} else {
		plc.EventsDefault = &defaultPL
	}
}

func applyAttributesAccess(plc *bridgev2.PowerLevelOverrides, attributeAccess signalmeow.AccessControl) {
	attributePL := defaultPL
	if attributeAccess == signalmeow.AccessControl_ADMINISTRATOR {
		attributePL = moderatorPL
	}
	plc.Events[event.StateRoomName] = attributePL
	plc.Events[event.StateRoomAvatar] = attributePL
	plc.Events[event.StateTopic] = attributePL
	plc.Events[event.StateBeeperDisappearingTimer] = attributePL
}

func applyMembersAccess(plc *bridgev2.PowerLevelOverrides, memberAccess signalmeow.AccessControl) {
	if memberAccess == signalmeow.AccessControl_ADMINISTRATOR {
		plc.Invite = &moderatorPL
	} else {
		plc.Invite = &defaultPL
	}
}

func inviteLinkToJoinRule(inviteLinkAccess signalmeow.AccessControl) event.JoinRule {
	switch inviteLinkAccess {
	case signalmeow.AccessControl_UNSATISFIABLE:
		return event.JoinRuleInvite
	case signalmeow.AccessControl_ADMINISTRATOR:
		return event.JoinRuleKnock
	case signalmeow.AccessControl_ANY:
		// TODO allow public portals?
		publicPortals := false
		if publicPortals {
			return event.JoinRulePublic
		} else {
			return event.JoinRuleKnock
		}
	default:
		return event.JoinRuleInvite
	}
}

func (s *SignalClient) getGroupInfo(ctx context.Context, groupID types.GroupIdentifier, minRevision uint32, backupChat *store.BackupChat) (*bridgev2.ChatInfo, error) {
	groupInfo, err := s.Client.RetrieveGroupByID(ctx, groupID, minRevision)
	if err != nil {
		return nil, fmt.Errorf("failed to retrieve group by id: %w", err)
	}
	return s.wrapGroupInfo(ctx, groupInfo, backupChat)
}

func (s *SignalClient) wrapGroupInfo(ctx context.Context, groupInfo *signalmeow.Group, backupChat *store.BackupChat) (*bridgev2.ChatInfo, error) {
	members := &bridgev2.ChatMemberList{
		IsFull:    true,
		MemberMap: make(map[networkid.UserID]bridgev2.ChatMember, len(groupInfo.Members)+len(groupInfo.PendingMembers)+len(groupInfo.RequestingMembers)+len(groupInfo.BannedMembers)),
		PowerLevels: &bridgev2.PowerLevelOverrides{
			Events: map[event.Type]int{
				event.StatePowerLevels: moderatorPL,
			},
		},
	}
	applyAnnouncementsOnly(members.PowerLevels, groupInfo.AnnouncementsOnly)
	joinRule := event.JoinRuleInvite
	if groupInfo.AccessControl != nil {
		applyAttributesAccess(members.PowerLevels, groupInfo.AccessControl.Attributes)
		applyMembersAccess(members.PowerLevels, groupInfo.AccessControl.Members)
		joinRule = inviteLinkToJoinRule(groupInfo.AccessControl.AddFromInviteLink)
	}
	for _, member := range groupInfo.Members {
		evtSender := s.makeEventSender(member.ACI)
		members.MemberMap[evtSender.Sender] = bridgev2.ChatMember{
			EventSender: evtSender,
			PowerLevel:  roleToPL(member.Role),
			Membership:  event.MembershipJoin,
		}
	}
	for _, member := range groupInfo.PendingMembers {
		aci := s.maybeResolvePNItoACI(ctx, &member.ServiceID)
		if aci == nil {
			continue
		}
		evtSender := s.makeEventSender(*aci)
		members.MemberMap[evtSender.Sender] = bridgev2.ChatMember{
			EventSender: evtSender,
			PowerLevel:  roleToPL(member.Role),
			Membership:  event.MembershipInvite,
		}
	}
	for _, member := range groupInfo.RequestingMembers {
		evtSender := s.makeEventSender(member.ACI)
		members.MemberMap[evtSender.Sender] = bridgev2.ChatMember{
			EventSender: evtSender,
			Membership:  event.MembershipKnock,
		}
	}
	for _, member := range groupInfo.BannedMembers {
		aci := s.maybeResolvePNItoACI(ctx, &member.ServiceID)
		if aci == nil {
			continue
		}
		evtSender := s.makeEventSender(*aci)
		members.MemberMap[evtSender.Sender] = bridgev2.ChatMember{
			EventSender: evtSender,
			Membership:  event.MembershipBan,
		}
	}
	if backupChat == nil {
		var err error
		// TODO allow using backup chat for data too instead of asking server?
		backupChat, err = s.Client.Store.BackupStore.GetBackupChatByGroupID(ctx, groupInfo.GroupIdentifier)
		if err != nil {
			zerolog.Ctx(ctx).Warn().Err(err).Msg("Failed to get backup chat for group")
		}
	}
	avatar, err := s.makeGroupAvatar(ctx, groupInfo.GroupIdentifier, &groupInfo.AvatarPath, groupInfo.GroupMasterKey)
	if err != nil {
		return nil, fmt.Errorf("failed to make group avatar: %w", err)
	}
	return &bridgev2.ChatInfo{
		Name:   &groupInfo.Title,
		Topic:  &groupInfo.Description,
		Avatar: avatar,
		Disappear: &database.DisappearingSetting{
			Type:  event.DisappearingTypeAfterRead,
			Timer: time.Duration(groupInfo.DisappearingMessagesDuration) * time.Second,
		},
		Members:      members,
		Type:         ptr.Ptr(database.RoomTypeDefault),
		JoinRule:     &event.JoinRulesEventContent{JoinRule: joinRule},
		ExtraUpdates: bridgev2.MergeExtraUpdaters(makeRevisionUpdater(groupInfo.Revision), updatePortalSyncMeta),
		CanBackfill:  backupChat != nil,
	}, nil
}

func updatePortalSyncMeta(ctx context.Context, portal *bridgev2.Portal) bool {
	meta := portal.Metadata.(*signalid.PortalMetadata)
	meta.LastSync = jsontime.UnixNow()
	return true
}

func (s *SignalClient) makeGroupAvatar(ctx context.Context, groupID types.GroupIdentifier, path *string, groupMasterKey types.SerializedGroupMasterKey) (*bridgev2.Avatar, error) {
	if path == nil {
		return nil, nil
	}
	avatar := &bridgev2.Avatar{
		ID:     makeAvatarPathID(*path),
		Remove: *path == "",
	}
	if s.Main.MsgConv.DirectMedia {
		userID, err := signalid.ParseUserLoginID(s.UserLogin.ID)
		if err != nil {
			return nil, fmt.Errorf("failed to parse user login ID: %w", err)
		}
		groupIDBytes, err := groupID.Bytes()
		if err != nil {
			return nil, fmt.Errorf("failed to get group id bytes: %w", err)
		}
		mediaID, err := signalid.DirectMediaGroupAvatar{
			UserID:          userID,
			GroupID:         groupIDBytes,
			GroupAvatarPath: *path,
		}.AsMediaID()
		if err != nil {
			return nil, err
		}
		avatar.MXC, err = s.Main.Bridge.Matrix.GenerateContentURI(ctx, mediaID)
		if err != nil {
			return nil, err
		}
		avatar.Hash = signalid.HashMediaID(mediaID)
	} else {
		avatar.Get = func(ctx context.Context) ([]byte, error) {
			return s.Client.DownloadGroupAvatar(ctx, *path, groupMasterKey)
		}
	}
	return avatar, nil
}

func makeRevisionUpdater(rev uint32) func(ctx context.Context, portal *bridgev2.Portal) bool {
	return func(ctx context.Context, portal *bridgev2.Portal) bool {
		meta := portal.Metadata.(*signalid.PortalMetadata)
		if meta.Revision < rev {
			meta.Revision = rev
			return true
		}
		return false
	}
}

func (s *SignalClient) groupChangeToChatInfoChange(ctx context.Context, groupID types.GroupIdentifier, rev uint32, groupChange *signalmeow.GroupChange) (*bridgev2.ChatInfoChange, error) {
	avatar, err := s.makeGroupAvatar(ctx, groupID, groupChange.ModifyAvatar, groupChange.GroupMasterKey)
	if err != nil {
		return nil, err
	}
	ic := &bridgev2.ChatInfoChange{
		ChatInfo: &bridgev2.ChatInfo{
			ExtraUpdates: makeRevisionUpdater(rev),
			Name:         groupChange.ModifyTitle,
			Topic:        groupChange.ModifyDescription,
			Avatar:       avatar,
		},
	}
	if groupChange.ModifyDisappearingMessagesDuration != nil {
		ic.ChatInfo.Disappear = &database.DisappearingSetting{
			Type:  event.DisappearingTypeAfterRead,
			Timer: time.Duration(*groupChange.ModifyDisappearingMessagesDuration) * time.Second,
		}
	}

	var pls *bridgev2.PowerLevelOverrides
	if groupChange.ModifyAnnouncementsOnly != nil ||
		groupChange.ModifyAttributesAccess != nil ||
		groupChange.ModifyMemberAccess != nil {
		pls = &bridgev2.PowerLevelOverrides{Events: make(map[event.Type]int)}
		if groupChange.ModifyAnnouncementsOnly != nil {
			applyAnnouncementsOnly(pls, *groupChange.ModifyAnnouncementsOnly)
		}
		if groupChange.ModifyAttributesAccess != nil {
			applyAttributesAccess(pls, *groupChange.ModifyAttributesAccess)
		}
		if groupChange.ModifyMemberAccess != nil {
			applyMembersAccess(pls, *groupChange.ModifyMemberAccess)
		}
	}
	if groupChange.ModifyAddFromInviteLinkAccess != nil {
		ic.ChatInfo.JoinRule = &event.JoinRulesEventContent{
			JoinRule: inviteLinkToJoinRule(*groupChange.ModifyAddFromInviteLinkAccess),
		}
	}
	var mc []bridgev2.ChatMember
	for _, member := range groupChange.AddMembers {
		mc = append(mc, bridgev2.ChatMember{
			EventSender: s.makeEventSender(member.ACI),
			PowerLevel:  roleToPL(member.Role),
			Membership:  event.MembershipJoin,
		})
	}
	for _, member := range groupChange.ModifyMemberRoles {
		mc = append(mc, bridgev2.ChatMember{
			EventSender: s.makeEventSender(member.ACI),
			PowerLevel:  roleToPL(member.Role),
			Membership:  event.MembershipJoin,
		})
	}
	bannedMembers := make(map[libsignalgo.ServiceID]bool)
	for _, member := range groupChange.AddBannedMembers {
		aci := s.maybeResolvePNItoACI(ctx, &member.ServiceID)
		if aci == nil {
			continue
		}
		bannedMembers[member.ServiceID] = true
		mc = append(mc, bridgev2.ChatMember{
			EventSender: s.makeEventSender(*aci),
			Membership:  event.MembershipBan,
		})
	}
	for _, memberACI := range groupChange.DeleteMembers {
		if bannedMembers[libsignalgo.NewACIServiceID(*memberACI)] {
			continue
		}
		mc = append(mc, bridgev2.ChatMember{
			EventSender:    s.makeEventSender(*memberACI),
			Membership:     event.MembershipLeave,
			PrevMembership: event.MembershipJoin,
		})
	}
	for _, member := range groupChange.AddPendingMembers {
		aci := s.maybeResolvePNItoACI(ctx, &member.ServiceID)
		if aci == nil {
			continue
		}
		mc = append(mc, bridgev2.ChatMember{
			EventSender: s.makeEventSender(*aci),
			PowerLevel:  roleToPL(member.Role),
			Membership:  event.MembershipInvite,
		})
	}
	for _, memberServiceID := range groupChange.DeletePendingMembers {
		if bannedMembers[*memberServiceID] {
			continue
		}
		aci := s.maybeResolvePNItoACI(ctx, memberServiceID)
		if aci == nil {
			continue
		}
		mc = append(mc, bridgev2.ChatMember{
			EventSender:    s.makeEventSender(*aci),
			Membership:     event.MembershipLeave,
			PrevMembership: event.MembershipInvite,
		})
	}
	for _, member := range groupChange.AddRequestingMembers {
		mc = append(mc, bridgev2.ChatMember{
			EventSender: s.makeEventSender(member.ACI),
			Membership:  event.MembershipKnock,
		})
	}
	for _, memberACI := range groupChange.DeleteRequestingMembers {
		if bannedMembers[libsignalgo.NewACIServiceID(*memberACI)] {
			continue
		}
		mc = append(mc, bridgev2.ChatMember{
			EventSender:    s.makeEventSender(*memberACI),
			Membership:     event.MembershipLeave,
			PrevMembership: event.MembershipKnock,
		})
	}
	for _, memberServiceID := range groupChange.DeleteBannedMembers {
		aci := s.maybeResolvePNItoACI(ctx, memberServiceID)
		if aci == nil {
			continue
		}
		mc = append(mc, bridgev2.ChatMember{
			EventSender:    s.makeEventSender(*aci),
			Membership:     event.MembershipLeave,
			PrevMembership: event.MembershipBan,
		})
	}
	for _, member := range groupChange.PromotePendingMembers {
		mc = append(mc, bridgev2.ChatMember{
			EventSender:    s.makeEventSender(member.ACI),
			Membership:     event.MembershipJoin,
			PrevMembership: event.MembershipInvite,
		})
	}
	for _, member := range groupChange.PromotePendingPniAciMembers {
		mc = append(mc, bridgev2.ChatMember{
			EventSender:    s.makeEventSender(member.ACI),
			Membership:     event.MembershipJoin,
			PrevMembership: event.MembershipInvite,
		})
	}
	for _, member := range groupChange.PromoteRequestingMembers {
		mc = append(mc, bridgev2.ChatMember{
			EventSender:    s.makeEventSender(member.ACI),
			Membership:     event.MembershipJoin,
			PrevMembership: event.MembershipKnock,
		})
	}
	if len(mc) > 0 || pls != nil {
		ic.MemberChanges = &bridgev2.ChatMemberList{Members: mc, PowerLevels: pls}
	}
	return ic, nil
}

func (s *SignalClient) maybeResolvePNItoACI(ctx context.Context, serviceID *libsignalgo.ServiceID) *uuid.UUID {
	if serviceID.Type == libsignalgo.ServiceIDTypeACI {
		return &serviceID.UUID
	}
	device, err := s.Client.Store.DeviceStore.DeviceByPNI(ctx, serviceID.UUID)
	if err != nil || device == nil {
		return nil
	}
	return &device.ACI
}

func (s *SignalClient) catchUpGroup(ctx context.Context, portal *bridgev2.Portal, fromRevision, toRevision uint32, ts uint64) {
	if fromRevision >= toRevision {
		return
	}
	log := zerolog.Ctx(ctx).With().
		Str("action", "catch up group changes").
		Uint32("from_revision", fromRevision).
		Uint32("to_revision", toRevision).
		Logger()
	if fromRevision == 0 {
		log.Info().Msg("Syncing full group info")
		info, err := s.getGroupInfo(ctx, types.GroupIdentifier(portal.ID), toRevision, nil)
		if err != nil {
			log.Err(err).Msg("Failed to get group info")
		} else {
			portal.UpdateInfo(ctx, info, s.UserLogin, nil, time.Time{})
		}
	} else {
		log.Info().Msg("Syncing missed group changes")
		groupChanges, err := s.Client.GetGroupHistoryPage(ctx, types.GroupIdentifier(portal.ID), fromRevision, false)
		if err != nil {
			log.Err(err).Msg("Failed to get group history page")
			s.catchUpGroup(ctx, portal, 0, toRevision, ts)
			return
		}
		for _, gc := range groupChanges {
			log.Debug().Uint32("current_rev", gc.GroupChange.Revision).Msg("Processing group change")
			chatInfoChange, err := s.groupChangeToChatInfoChange(ctx, types.GroupIdentifier(portal.ID), gc.GroupChange.Revision, gc.GroupChange)
			if err != nil {
				log.Err(err).Msg("Failed to convert group info")
			} else if gc.GroupChange.SourceServiceID.Type == libsignalgo.ServiceIDTypeACI {
				portal.ProcessChatInfoChange(ctx, s.makeEventSender(gc.GroupChange.SourceServiceID.UUID), s.UserLogin, chatInfoChange, time.UnixMilli(int64(ts)))
			}
			if gc.GroupChange.Revision == toRevision {
				break
			}
		}
	}
}
