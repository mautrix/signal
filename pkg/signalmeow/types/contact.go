// mautrix-signal - A Matrix-signal puppeting bridge.
// Copyright (C) 2023 Scott Weber, Tulir Asokan
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

package types

import (
	"github.com/google/uuid"

	"go.mau.fi/mautrix-signal/pkg/libsignalgo"
)

// The Contact struct combines information from two sources:
// - A Signal "contact": contact info harvested from our user's phone's contact list
// - A Signal "profile": contact info entered by the target user when registering for Signal
// Users of this Contact struct should prioritize "contact" information, but fall back
// to "profile" information if the contact information is not available.
type Contact struct {
	UUID              uuid.UUID
	E164              string
	ContactName       string
	ContactAvatar     ContactAvatar
	ProfileKey        *libsignalgo.ProfileKey
	ProfileName       string
	ProfileAbout      string
	ProfileAboutEmoji string
	ProfileAvatarPath string
	ProfileAvatarHash string
}

type ContactAvatar struct {
	Image       []byte
	ContentType string
	Hash        string
}
