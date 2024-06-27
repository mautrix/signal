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
	"maunium.net/go/mautrix/bridgev2"
	"maunium.net/go/mautrix/bridgev2/database"
	"maunium.net/go/mautrix/bridgev2/networkid"

	"go.mau.fi/mautrix-signal/pkg/signalmeow"
	"go.mau.fi/mautrix-signal/pkg/signalmeow/types"
)

func (s *SignalClient) getGroupInfo(ctx context.Context, groupID types.GroupIdentifier, minRevision uint32) (*bridgev2.PortalInfo, error) {
	groupInfo, err := s.Client.RetrieveGroupByID(ctx, groupID, minRevision)
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
		Name:   &groupInfo.Title,
		Topic:  &groupInfo.Description,
		Avatar: s.makeGroupAvatar(groupInfo),
		Disappear: &database.DisappearingSetting{
			Type:  database.DisappearingTypeAfterRead,
			Timer: time.Duration(groupInfo.DisappearingMessagesDuration) * time.Second,
		},
		Members:      members,
		IsDirectChat: &isDM,
		IsSpace:      &isSpace,
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
		currentRev, _ := database.GetNumberFromMap[uint32](portal.Metadata.Extra, "revision")
		if currentRev < rev {
			portal.Metadata.Extra["revision"] = rev
			return true
		}
		return false
	}
}

func (s *SignalClient) groupChangeToChatInfoChange(ctx context.Context, rev uint32, groupChange *signalmeow.GroupChange) *bridgev2.ChatInfoChange {
	ic := &bridgev2.ChatInfoChange{
		PortalInfo: &bridgev2.PortalInfo{
			ExtraUpdates: makeRevisionUpdater(rev),
			Name:         groupChange.ModifyTitle,
			Topic:        groupChange.ModifyDescription,
			Avatar:       s.makeGroupAvatar(groupChange),
		},
	}
	if groupChange.ModifyDisappearingMessagesDuration != nil {
		ic.PortalInfo.Disappear = &database.DisappearingSetting{
			Type:  database.DisappearingTypeAfterRead,
			Timer: time.Duration(*groupChange.ModifyDisappearingMessagesDuration) * time.Second,
		}
	}
	// TODO handle member/permission/etc changes
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
