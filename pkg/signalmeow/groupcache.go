// mautrix-signal - A Matrix-signal puppeting bridge.
// Copyright (C) 2025 Tulir Asokan
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
	"fmt"
	"slices"
	"sync"
	"time"

	"github.com/google/uuid"

	"go.mau.fi/mautrix-signal/pkg/libsignalgo"
	"go.mau.fi/mautrix-signal/pkg/signalmeow/types"
)

type cachedGroup struct {
	*Group
	SendEndorsement []byte
	FetchedAt       time.Time
	UpdatedAt       time.Time
}

type GroupCache struct {
	credentials     *GroupCredentials
	credentialsLock sync.RWMutex

	data map[types.GroupIdentifier]*cachedGroup
	lock sync.RWMutex

	activeCalls map[types.GroupIdentifier]string
	callsLock   sync.RWMutex
}

func NewGroupCache() *GroupCache {
	return &GroupCache{
		data:        make(map[types.GroupIdentifier]*cachedGroup),
		activeCalls: make(map[types.GroupIdentifier]string),
	}
}

func (gc *GroupCache) GetCredentials(
	ctx context.Context,
	fetch func(context.Context, time.Time) (*GroupCredentials, error),
) (*GroupCredential, error) {
	today := time.Now().Truncate(24 * time.Hour)
	gc.credentialsLock.RLock()
	cred := gc.getCachedCredentials(today.Unix())
	gc.credentialsLock.RUnlock()
	if cred != nil {
		return cred, nil
	}

	gc.credentialsLock.Lock()
	defer gc.credentialsLock.Unlock()
	cred = gc.getCachedCredentials(today.Unix())
	if cred != nil {
		return cred, nil
	}
	creds, err := fetch(ctx, today)
	if err != nil {
		return nil, err
	}
	gc.credentials = creds
	cred = gc.getCachedCredentials(today.Unix())
	if cred == nil {
		return nil, fmt.Errorf("no credentials for today after fetch")
	}
	return cred, nil
}

func (gc *GroupCache) getCachedCredentials(today int64) *GroupCredential {
	if gc.credentials == nil {
		return nil
	}
	for _, cred := range gc.credentials.Credentials {
		if cred.RedemptionTime == today {
			return &cred
		}
	}
	return nil
}

func (gc *GroupCache) UpdateActiveCall(id types.GroupIdentifier, callID string) bool {
	gc.callsLock.Lock()
	defer gc.callsLock.Unlock()
	currentCallID, ok := gc.activeCalls[id]
	if ok {
		// If we do, then this must be ending the call
		if currentCallID == callID {
			delete(gc.activeCalls, id)
			return false
		}
	}
	gc.activeCalls[id] = callID
	return true
}

func (gc *GroupCache) Get(id types.GroupIdentifier) (*Group, bool) {
	gc.lock.RLock()
	defer gc.lock.RUnlock()
	c, ok := gc.data[id]
	if !ok {
		return nil, false
	}
	return c.Group, true
}

func (gc *GroupCache) Delete(id types.GroupIdentifier) {
	gc.lock.Lock()
	defer gc.lock.Unlock()
	delete(gc.data, id)
}

func (gc *GroupCache) Put(data *Group, endorsementResponse []byte) {
	gc.lock.Lock()
	defer gc.lock.Unlock()
	cached, exists := gc.data[data.GroupIdentifier]
	if exists && cached.Revision > data.Revision {
		return
	}
	gc.data[data.GroupIdentifier] = &cachedGroup{
		Group:     data,
		FetchedAt: time.Now(),
		UpdatedAt: time.Now(),

		//SendEndorsement: endorsementResponse,
	}
}

func (gc *GroupCache) ApplyUpdate(change *GroupChange, endorsementResponse []byte) {
	rawGroupID, err := masterKeyToBytes(change.GroupMasterKey).GroupIdentifier()
	if err != nil {
		return
	}
	id := types.GroupIdentifier(rawGroupID.String())

	gc.lock.Lock()
	defer gc.lock.Unlock()

	cached, exists := gc.data[id]
	if !exists || cached.Revision >= change.Revision {
		return
	} else if cached.Revision < change.Revision-1 {
		// We missed an update, evict
		delete(gc.data, id)
		return
	}

	// Pending member adds, promotes and removes
	cached.PendingMembers = append(cached.PendingMembers, change.AddPendingMembers...)
	for _, promo := range change.PromotePendingMembers {
		cached.PendingMembers = slices.DeleteFunc(cached.PendingMembers, func(p *PendingMember) bool {
			return p.ServiceID.Type == libsignalgo.ServiceIDTypeACI && p.ServiceID.UUID == promo.ACI
		})
		cached.Members = append(cached.Members, &GroupMember{
			ACI:              promo.ACI,
			ProfileKey:       promo.ProfileKey,
			Role:             GroupMember_DEFAULT,
			JoinedAtRevision: change.Revision,
		})
	}
	for _, promo := range change.PromotePendingPniAciMembers {
		cached.PendingMembers = slices.DeleteFunc(cached.PendingMembers, func(p *PendingMember) bool {
			return (p.ServiceID.Type == libsignalgo.ServiceIDTypePNI && p.ServiceID.UUID == promo.PNI) ||
				(p.ServiceID.Type == libsignalgo.ServiceIDTypeACI && p.ServiceID.UUID == promo.ACI)
		})
		cached.Members = append(cached.Members, &GroupMember{
			ACI:              promo.ACI,
			ProfileKey:       promo.ProfileKey,
			Role:             GroupMember_DEFAULT,
			JoinedAtRevision: change.Revision,
		})
	}
	cached.PendingMembers = slices.DeleteFunc(cached.PendingMembers, func(p *PendingMember) bool {
		return slices.ContainsFunc(change.DeletePendingMembers, func(s *libsignalgo.ServiceID) bool {
			return s != nil && p.ServiceID == *s
		})
	})

	// Requesting member adds, promotes and removes
	cached.RequestingMembers = append(cached.RequestingMembers, change.AddRequestingMembers...)
	for _, promo := range change.PromoteRequestingMembers {
		var profileKey libsignalgo.ProfileKey
		cached.RequestingMembers = slices.DeleteFunc(cached.RequestingMembers, func(r *RequestingMember) bool {
			if r.ACI == promo.ACI {
				profileKey = r.ProfileKey
				return true
			}
			return false
		})
		cached.Members = append(cached.Members, &GroupMember{
			ACI:              promo.ACI,
			ProfileKey:       profileKey,
			Role:             promo.Role,
			JoinedAtRevision: change.Revision,
		})
	}
	cached.RequestingMembers = slices.DeleteFunc(cached.RequestingMembers, func(r *RequestingMember) bool {
		return slices.ContainsFunc(change.DeleteRequestingMembers, func(u *uuid.UUID) bool {
			return u != nil && r.ACI == *u
		})
	})

	// Direct member adds, removes and modifications
	for _, member := range change.AddMembers {
		cached.Members = append(cached.Members, &GroupMember{
			ACI:              member.ACI,
			Role:             member.Role,
			ProfileKey:       member.ProfileKey,
			JoinedAtRevision: member.JoinedAtRevision,
		})
	}
	for _, rm := range change.ModifyMemberRoles {
		cached.findMemberOrEmpty(rm.ACI).Role = rm.Role
	}
	for _, pk := range change.ModifyMemberProfileKeys {
		cached.findMemberOrEmpty(pk.ACI).ProfileKey = pk.ProfileKey
	}
	cached.Members = slices.DeleteFunc(cached.Members, func(member *GroupMember) bool {
		return slices.ContainsFunc(change.DeleteMembers, func(u *uuid.UUID) bool {
			return u != nil && *u == member.ACI
		})
	})

	// Banned members
	cached.BannedMembers = append(cached.BannedMembers, change.AddBannedMembers...)
	cached.BannedMembers = slices.DeleteFunc(cached.BannedMembers, func(b *BannedMember) bool {
		return slices.ContainsFunc(change.DeleteBannedMembers, func(s *libsignalgo.ServiceID) bool {
			return s != nil && b.ServiceID == *s
		})
	})

	// Non-member modifications
	if change.ModifyInviteLinkPassword != nil {
		cached.InviteLinkPassword = change.ModifyInviteLinkPassword
	}
	if change.ModifyTitle != nil {
		cached.Title = *change.ModifyTitle
	}
	if change.ModifyDescription != nil {
		cached.Description = *change.ModifyDescription
	}
	if change.ModifyAvatar != nil {
		cached.AvatarPath = *change.ModifyAvatar
	}
	if change.ModifyAnnouncementsOnly != nil {
		cached.AnnouncementsOnly = *change.ModifyAnnouncementsOnly
	}
	if change.ModifyDisappearingMessagesDuration != nil {
		cached.DisappearingMessagesDuration = *change.ModifyDisappearingMessagesDuration
	}
	if change.ModifyAttributesAccess != nil {
		cached.AccessControl.Attributes = *change.ModifyAttributesAccess
	}
	if change.ModifyMemberAccess != nil {
		cached.AccessControl.Members = *change.ModifyMemberAccess
	}
	if change.ModifyAddFromInviteLinkAccess != nil {
		cached.AccessControl.AddFromInviteLink = *change.ModifyAddFromInviteLinkAccess
	}

	// TODO handle endorsement responses
	cached.UpdatedAt = time.Now()
	cached.Revision = change.Revision
}
