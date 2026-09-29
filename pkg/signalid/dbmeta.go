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

package signalid

import (
	"go.mau.fi/util/jsontime"
	"maunium.net/go/mautrix/bridgev2/networkid"
)

type PortalMetadata struct {
	Revision               uint32 `json:"revision,omitempty"`
	ExpirationTimerVersion uint32 `json:"expiration_timer_version,omitempty"`
	// Lazy resync tracking
	LastSync jsontime.Unix `json:"last_sync,omitempty"`
}

type MessageMetadata struct {
	ContainsAttachments bool              `json:"contains_attachments,omitempty"`
	MatrixPollOptionIDs []string          `json:"matrix_poll_option_ids,omitempty"`
	VoteCount           map[string]uint32 `json:"vote_count,omitempty"`
}

type UserLoginMetadata struct {
	ChatsSynced     bool               `json:"chats_synced,omitempty"`
	LastContactSync jsontime.UnixMilli `json:"last_contact_sync,omitempty"`
	// MarkedUnreadCheckpoints is the last Signal Storage Service markedUnread
	// value this login has bridged (or established as a baseline from) for
	// each portal, keyed by portal ID. A missing key means no storage
	// service record has been observed yet for that portal by this login.
	//
	// This is kept per-login rather than on PortalMetadata because a Group
	// V2 portal can be shared by multiple logins when split_portals is
	// disabled; each login's Storage Service state (and double puppet used
	// to apply it) is independent, so a shared portal-level checkpoint would
	// let one login's sync state clobber another's.
	MarkedUnreadCheckpoints map[networkid.PortalID]bool `json:"marked_unread_checkpoints,omitempty"`
}

type GhostMetadata struct {
	ProfileFetchedAt jsontime.UnixMilli `json:"profile_fetched_at"`
}
