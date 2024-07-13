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
	"time"

	"github.com/rs/zerolog"
	"go.mau.fi/util/ptr"
	"maunium.net/go/mautrix/bridgev2"
	"maunium.net/go/mautrix/bridgev2/database"
	"maunium.net/go/mautrix/event"

	"go.mau.fi/mautrix-signal/pkg/libsignalgo"
	"go.mau.fi/mautrix-signal/pkg/signalmeow"
	"go.mau.fi/mautrix-signal/pkg/signalmeow/types"
)

var defaultPL = 0
var moderatorPL = 50

func roleToPL(role signalmeow.GroupMemberRole) int {
	switch role {
	case signalmeow.GroupMember_ADMINISTRATOR:
		return moderatorPL
	case signalmeow.GroupMember_DEFAULT:
		fallthrough
	default:
		return defaultPL
	}
}

func applyAnnouncementsOnly(plc *bridgev2.PowerLevelChanges, announcementsOnly bool) {
	if announcementsOnly {
		plc.EventsDefault = &moderatorPL
	} else {
		plc.EventsDefault = &defaultPL
	}
}

func applyAttributesAccess(plc *bridgev2.PowerLevelChanges, attributeAccess signalmeow.AccessControl) {
	attributePL := defaultPL
	if attributeAccess == signalmeow.AccessControl_ADMINISTRATOR {
		attributePL = moderatorPL
	}
	plc.Events[event.StateRoomName] = attributePL
	plc.Events[event.StateRoomAvatar] = attributePL
	plc.Events[event.StateTopic] = attributePL
}

func applyMembersAccess(plc *bridgev2.PowerLevelChanges, memberAccess signalmeow.AccessControl) {
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

func (s *SignalClient) getGroupInfo(ctx context.Context, groupID types.GroupIdentifier, minRevision uint32) (*bridgev2.ChatInfo, error) {
	groupInfo, err := s.Client.RetrieveGroupByID(ctx, groupID, minRevision)
	if err != nil {
		return nil, err
	}
	members := &bridgev2.ChatMemberList{
		IsFull:  true,
		Members: make([]bridgev2.ChatMember, len(groupInfo.Members), len(groupInfo.Members)+len(groupInfo.PendingMembers)+len(groupInfo.RequestingMembers)+len(groupInfo.BannedMembers)),
		PowerLevels: &bridgev2.PowerLevelChanges{
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
	for i, member := range groupInfo.Members {
		members.Members[i] = bridgev2.ChatMember{
			EventSender: s.makeEventSender(member.ACI),
			PowerLevel:  roleToPL(member.Role),
			Membership:  event.MembershipJoin,
		}
	}
	for _, member := range groupInfo.PendingMembers {
		if member.ServiceID.Type != libsignalgo.ServiceIDTypeACI {
			continue
		}
		members.Members = append(members.Members, bridgev2.ChatMember{
			EventSender: s.makeEventSender(member.ServiceID.UUID),
			PowerLevel:  roleToPL(member.Role),
			Membership:  event.MembershipInvite,
		})
	}
	for _, member := range groupInfo.RequestingMembers {
		members.Members = append(members.Members, bridgev2.ChatMember{
			EventSender: s.makeEventSender(member.ACI),
			Membership:  event.MembershipKnock,
		})
	}
	for _, member := range groupInfo.BannedMembers {
		if member.ServiceID.Type != libsignalgo.ServiceIDTypeACI {
			continue
		}
		members.Members = append(members.Members, bridgev2.ChatMember{
			EventSender: s.makeEventSender(member.ServiceID.UUID),
			Membership:  event.MembershipBan,
		})
	}
	return &bridgev2.ChatInfo{
		Name:   &groupInfo.Title,
		Topic:  &groupInfo.Description,
		Avatar: s.makeGroupAvatar(groupInfo),
		Disappear: &database.DisappearingSetting{
			Type:  database.DisappearingTypeAfterRead,
			Timer: time.Duration(groupInfo.DisappearingMessagesDuration) * time.Second,
		},
		Members:      members,
		Type:         ptr.Ptr(database.RoomTypeDefault),
		JoinRule:     &event.JoinRulesEventContent{JoinRule: joinRule},
		ExtraUpdates: makeRevisionUpdater(groupInfo.Revision),
	}, nil
}

func (s *SignalClient) makeGroupAvatar(meta signalmeow.GroupAvatarMeta) *bridgev2.Avatar {
	path := meta.GetAvatarPath()
	if path == nil {
		return nil
	}
	return &bridgev2.Avatar{
		ID: makeAvatarPathID(*path),
		Get: func(ctx context.Context) ([]byte, error) {
			return s.Client.DownloadGroupAvatar(ctx, meta)
		},
		Remove: *path == "",
	}
}

func makeRevisionUpdater(rev uint32) func(ctx context.Context, portal *bridgev2.Portal) bool {
	return func(ctx context.Context, portal *bridgev2.Portal) bool {
		meta := portal.Metadata.(*PortalMetadata)
		if meta.Revision < rev {
			meta.Revision = rev
			return true
		}
		return false
	}
}

func (s *SignalClient) groupChangeToChatInfoChange(ctx context.Context, rev uint32, groupChange *signalmeow.GroupChange) *bridgev2.ChatInfoChange {
	ic := &bridgev2.ChatInfoChange{
		ChatInfo: &bridgev2.ChatInfo{
			ExtraUpdates: makeRevisionUpdater(rev),
			Name:         groupChange.ModifyTitle,
			Topic:        groupChange.ModifyDescription,
			Avatar:       s.makeGroupAvatar(groupChange),
		},
	}
	if groupChange.ModifyDisappearingMessagesDuration != nil {
		ic.ChatInfo.Disappear = &database.DisappearingSetting{
			Type:  database.DisappearingTypeAfterRead,
			Timer: time.Duration(*groupChange.ModifyDisappearingMessagesDuration) * time.Second,
		}
	}

	var pls *bridgev2.PowerLevelChanges
	if groupChange.ModifyAnnouncementsOnly != nil ||
		groupChange.ModifyAttributesAccess != nil ||
		groupChange.ModifyMemberAccess != nil {
		pls = &bridgev2.PowerLevelChanges{Events: make(map[event.Type]int)}
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
	for _, memberACI := range groupChange.DeleteMembers {
		mc = append(mc, bridgev2.ChatMember{
			EventSender:    s.makeEventSender(*memberACI),
			Membership:     event.MembershipLeave,
			PrevMembership: event.MembershipJoin,
		})
	}
	for _, member := range groupChange.AddPendingMembers {
		if member.ServiceID.Type != libsignalgo.ServiceIDTypeACI {
			continue
		}
		mc = append(mc, bridgev2.ChatMember{
			EventSender: s.makeEventSender(member.ServiceID.UUID),
			PowerLevel:  roleToPL(member.Role),
			Membership:  event.MembershipInvite,
		})
	}
	for _, memberServiceID := range groupChange.DeletePendingMembers {
		if memberServiceID.Type != libsignalgo.ServiceIDTypeACI {
			continue
		}
		mc = append(mc, bridgev2.ChatMember{
			EventSender:    s.makeEventSender(memberServiceID.UUID),
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
		mc = append(mc, bridgev2.ChatMember{
			EventSender:    s.makeEventSender(*memberACI),
			Membership:     event.MembershipLeave,
			PrevMembership: event.MembershipKnock,
		})
	}
	for _, member := range groupChange.AddBannedMembers {
		if member.ServiceID.Type != libsignalgo.ServiceIDTypeACI {
			continue
		}
		mc = append(mc, bridgev2.ChatMember{
			EventSender: s.makeEventSender(member.ServiceID.UUID),
			Membership:  event.MembershipBan,
		})
	}
	for _, memberServiceID := range groupChange.DeleteBannedMembers {
		if memberServiceID.Type != libsignalgo.ServiceIDTypeACI {
			continue
		}
		mc = append(mc, bridgev2.ChatMember{
			EventSender:    s.makeEventSender(memberServiceID.UUID),
			Membership:     event.MembershipLeave,
			PrevMembership: event.MembershipBan,
		})
	}
	if len(mc) > 0 || pls != nil {
		ic.MemberChanges = &bridgev2.ChatMemberList{Members: mc, PowerLevels: pls}
	}
	return ic
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
		info, err := s.getGroupInfo(ctx, types.GroupIdentifier(portal.ID), toRevision)
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
			return
		}
		for _, gc := range groupChanges {
			log.Debug().Uint32("current_rev", gc.GroupChange.Revision).Msg("Processing group change")
			chatInfoChange := s.groupChangeToChatInfoChange(ctx, gc.GroupChange.Revision, gc.GroupChange)
			portal.ProcessChatInfoChange(ctx, s.makeEventSender(gc.GroupChange.SourceACI), s.UserLogin, chatInfoChange, time.UnixMilli(int64(ts)))
			if gc.GroupChange.Revision == toRevision {
				break
			}
		}
	}
}
