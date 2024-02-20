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

package main

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"net/http"
	"regexp"

	"github.com/google/uuid"
	"github.com/rs/zerolog"
	"maunium.net/go/mautrix"
	"maunium.net/go/mautrix/appservice"
	"maunium.net/go/mautrix/bridge"
	"maunium.net/go/mautrix/id"

	"go.mau.fi/mautrix-signal/database"
	"go.mau.fi/mautrix-signal/pkg/signalmeow/types"
)

func (br *SignalBridge) GetPuppetByMXID(mxid id.UserID) *Puppet {
	signalID, ok := br.ParsePuppetMXID(mxid)
	if !ok {
		return nil
	}

	return br.GetPuppetBySignalID(signalID)
}

func (br *SignalBridge) GetPuppetBySignalIDString(id string) *Puppet {
	parsed, err := uuid.Parse(id)
	if err != nil {
		return nil
	}
	return br.GetPuppetBySignalID(parsed)
}

func (br *SignalBridge) GetPuppetBySignalID(id uuid.UUID) *Puppet {
	br.puppetsLock.Lock()
	defer br.puppetsLock.Unlock()

	if id == uuid.Nil {
		br.ZLog.Warn().Msg("Trying to get puppet with empty signal_user_id")
		return nil
	}

	puppet, ok := br.puppets[id]
	if !ok {
		dbPuppet, err := br.DB.Puppet.GetBySignalID(context.TODO(), id)
		if err != nil {
			br.ZLog.Err(err).Msg("Failed to get puppet from database")
			return nil
		}
		return br.loadPuppet(context.TODO(), dbPuppet, &id)
	}
	return puppet
}

func (br *SignalBridge) GetPuppetByCustomMXID(mxid id.UserID) *Puppet {
	br.puppetsLock.Lock()
	defer br.puppetsLock.Unlock()

	puppet, ok := br.puppetsByCustomMXID[mxid]
	if !ok {
		dbPuppet, err := br.DB.Puppet.GetByCustomMXID(context.TODO(), mxid)
		if err != nil {
			br.ZLog.Err(err).Msg("Failed to get puppet from database")
			return nil
		}
		return br.loadPuppet(context.TODO(), dbPuppet, nil)
	}
	return puppet
}

func (br *SignalBridge) GetAllPuppetsWithCustomMXID() []*Puppet {
	puppets, err := br.DB.Puppet.GetAllWithCustomMXID(context.TODO())
	if err != nil {
		br.ZLog.Error().Err(err).Msg("Failed to get all puppets with custom MXID")
		return nil
	}
	return br.dbPuppetsToPuppets(puppets)
}

func (br *SignalBridge) FormatPuppetMXID(u uuid.UUID) id.UserID {
	return id.NewUserID(
		br.Config.Bridge.FormatUsername(u.String()),
		br.Config.Homeserver.Domain,
	)
}

func (br *SignalBridge) loadPuppet(ctx context.Context, dbPuppet *database.Puppet, u *uuid.UUID) *Puppet {
	if dbPuppet == nil {
		if u == nil {
			return nil
		}
		dbPuppet = br.DB.Puppet.New()
		dbPuppet.SignalID = *u
		err := dbPuppet.Insert(ctx)
		if err != nil {
			br.ZLog.Error().Err(err).Stringer("signal_user_id", *u).Msg("Failed to insert new puppet")
			return nil
		}
	}

	puppet := br.NewPuppet(dbPuppet)
	br.puppets[puppet.SignalID] = puppet
	if puppet.CustomMXID != "" {
		br.puppetsByCustomMXID[puppet.CustomMXID] = puppet
	}
	return puppet
}

func (br *SignalBridge) dbPuppetsToPuppets(dbPuppets []*database.Puppet) []*Puppet {
	br.puppetsLock.Lock()
	defer br.puppetsLock.Unlock()

	output := make([]*Puppet, len(dbPuppets))
	for index, dbPuppet := range dbPuppets {
		if dbPuppet == nil {
			continue
		}
		puppet, ok := br.puppets[dbPuppet.SignalID]
		if !ok {
			puppet = br.loadPuppet(context.TODO(), dbPuppet, nil)
		}
		output[index] = puppet
	}
	return output
}

func (br *SignalBridge) NewPuppet(dbPuppet *database.Puppet) *Puppet {
	return &Puppet{
		Puppet: dbPuppet,
		bridge: br,
		log:    br.ZLog.With().Stringer("signal_user_id", dbPuppet.SignalID).Logger(),

		MXID: br.FormatPuppetMXID(dbPuppet.SignalID),
	}
}

func (br *SignalBridge) ParsePuppetMXID(mxid id.UserID) (uuid.UUID, bool) {
	if userIDRegex == nil {
		pattern := fmt.Sprintf(
			"^@%s:%s$",
			// The "SignalID" portion of the MXID is a (lowercase) UUID
			br.Config.Bridge.FormatUsername("([0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12})"),
			br.Config.Homeserver.Domain,
		)
		br.ZLog.Debug().Str("pattern", pattern).Msg("Compiling userIDRegex")

		userIDRegex = regexp.MustCompile(pattern)
	}

	match := userIDRegex.FindStringSubmatch(string(mxid))
	if len(match) == 2 {
		parsed, err := uuid.Parse(match[1])
		if err != nil {
			return uuid.Nil, false
		}
		return parsed, true
	}

	return uuid.Nil, false
}

type Puppet struct {
	*database.Puppet

	bridge *SignalBridge
	log    zerolog.Logger

	MXID id.UserID

	customIntent *appservice.IntentAPI
	customUser   *User
}

var userIDRegex *regexp.Regexp

var (
	_ bridge.Ghost            = (*Puppet)(nil)
	_ bridge.GhostWithProfile = (*Puppet)(nil)
)

func (puppet *Puppet) GetMXID() id.UserID {
	return puppet.MXID
}

func (puppet *Puppet) DefaultIntent() *appservice.IntentAPI {
	return puppet.bridge.AS.Intent(puppet.MXID)
}

func (puppet *Puppet) CustomIntent() *appservice.IntentAPI {
	if puppet == nil {
		return nil
	}
	return puppet.customIntent
}

func (puppet *Puppet) IntentFor(portal *Portal) *appservice.IntentAPI {
	if puppet != nil {
		if puppet.customIntent == nil || portal.UserID() == puppet.SignalID {
			return puppet.DefaultIntent()
		}
		return puppet.customIntent
	}
	return nil
}

func (puppet *Puppet) GetDisplayname() string {
	return puppet.Name
}

func (puppet *Puppet) GetAvatarURL() id.ContentURI {
	return puppet.AvatarURL
}

func (puppet *Puppet) UpdateInfo(ctx context.Context, source *User) {
	log := zerolog.Ctx(ctx).With().
		Str("function", "Puppet.UpdateInfo").
		Stringer("signal_user_id", puppet.SignalID).
		Logger()
	ctx = log.WithContext(ctx)
	var err error
	log.Debug().Msg("Fetching contact info to update puppet")
	info, err := source.Client.ContactByID(ctx, puppet.SignalID)
	if err != nil {
		log.Err(err).Msg("Failed to fetch contact info")
		return
	}

	log.Trace().Msg("Updating puppet info")

	update := false
	if info.E164 != "" && puppet.Number != info.E164 {
		puppet.Number = info.E164
		update = true
	}
	update = puppet.updateName(ctx, info) || update
	update = puppet.updateAvatar(ctx, source, info) || update
	if update {
		puppet.ContactInfoSet = false
		puppet.UpdateContactInfo(ctx)
		err = puppet.Update(ctx)
		if err != nil {
			log.Err(err).Msg("Failed to save puppet to database after updating")
		}
		go puppet.updatePortalMeta(ctx)
		log.Debug().Msg("Puppet info updated")
	}
}
func (puppet *Puppet) UpdateContactInfo(ctx context.Context) {
	if !puppet.bridge.SpecVersions.Supports(mautrix.BeeperFeatureArbitraryProfileMeta) || puppet.ContactInfoSet {
		return
	}

	identifiers := []string{
		fmt.Sprintf("signal:%s", puppet.SignalID),
	}
	if puppet.Number != "" {
		identifiers = append(identifiers, fmt.Sprintf("tel:%s", puppet.Number))
	}
	contactInfo := map[string]any{
		"com.beeper.bridge.identifiers": identifiers,
		"com.beeper.bridge.remote_id":   puppet.SignalID.String(),
		"com.beeper.bridge.service":     "signal",
		"com.beeper.bridge.network":     "signal",
	}
	err := puppet.DefaultIntent().BeeperUpdateProfile(ctx, contactInfo)
	if err != nil {
		zerolog.Ctx(ctx).Err(err).Msg("Failed to store custom contact info in profile")
	} else {
		puppet.ContactInfoSet = true
	}
}

func (puppet *Puppet) updatePortalMeta(ctx context.Context) {
	for _, portal := range puppet.bridge.FindPrivateChatPortalsWith(puppet.SignalID) {
		// Get room create lock to prevent races between receiving contact info and room creation.
		portal.roomCreateLock.Lock()
		portal.UpdateDMInfo(ctx, false)
		portal.roomCreateLock.Unlock()
	}
}

func (puppet *Puppet) updateAvatar(ctx context.Context, source *User, info *types.Contact) bool {
	var avatarData []byte
	var avatarContentType string
	log := zerolog.Ctx(ctx)
	if puppet.bridge.Config.Bridge.UseContactAvatars && info.ContactAvatar.Hash != "" {
		if puppet.AvatarHash == info.ContactAvatar.Hash && puppet.AvatarSet {
			return false
		}
		avatarData = info.ContactAvatar.Image
		avatarContentType = info.ContactAvatar.ContentType
		if avatarData == nil {
			// TODO what to do? 🤔
			return false
		}
		puppet.AvatarSet = false
		puppet.AvatarPath = ""
	} else {
		if puppet.AvatarPath == info.Profile.AvatarPath && puppet.AvatarSet {
			return false
		}
		if info.Profile.AvatarPath == "" {
			puppet.AvatarURL = id.ContentURI{}
			puppet.AvatarPath = ""
			puppet.AvatarHash = ""
			puppet.AvatarSet = false
			err := puppet.DefaultIntent().SetAvatarURL(ctx, puppet.AvatarURL)
			if err != nil {
				log.Err(err).Msg("Failed to remove user avatar")
				return true
			}
			log.Debug().Msg("Avatar removed")
			puppet.AvatarSet = true
			return true
		}
		var err error
		avatarData, err = source.Client.DownloadUserAvatar(ctx, info.Profile.AvatarPath, info.Profile.Key)
		if err != nil {
			log.Err(err).
				Str("profile_avatar_path", info.Profile.AvatarPath).
				Msg("Failed to download new user avatar")
			return true
		}
		avatarContentType = http.DetectContentType(avatarData)
	}
	hash := sha256.Sum256(avatarData)
	newHash := hex.EncodeToString(hash[:])
	if puppet.AvatarHash == newHash && puppet.AvatarSet {
		log.Debug().
			Str("avatar_hash", newHash).
			Str("new_avatar_path", puppet.AvatarPath).
			Msg("Avatar path changed, but hash didn't")
		// Path changed, but actual avatar didn't
		return true
	}
	puppet.AvatarPath = info.Profile.AvatarPath
	puppet.AvatarHash = newHash
	puppet.AvatarSet = false
	puppet.AvatarURL = id.ContentURI{}
	resp, err := puppet.DefaultIntent().UploadBytes(ctx, avatarData, avatarContentType)
	if err != nil {
		log.Err(err).
			Str("avatar_hash", puppet.AvatarHash).
			Msg("Failed to upload new user avatar")
		return true
	}
	puppet.AvatarURL = resp.ContentURI
	err = puppet.DefaultIntent().SetAvatarURL(ctx, puppet.AvatarURL)
	if err != nil {
		log.Err(err).Msg("Failed to update user avatar")
		return true
	}
	log.Debug().
		Str("avatar_hash", newHash).
		Stringer("avatar_mxc", resp.ContentURI).
		Msg("Avatar updated successfully")
	puppet.AvatarSet = true
	return true
}

func (puppet *Puppet) updateName(ctx context.Context, contact *types.Contact) bool {
	// TODO set name quality
	newName := puppet.bridge.Config.Bridge.FormatDisplayname(contact)
	if puppet.NameSet && puppet.Name == newName {
		return false
	}
	puppet.Name = newName
	puppet.NameSet = false
	err := puppet.DefaultIntent().SetDisplayName(ctx, newName)
	if err != nil {
		zerolog.Ctx(ctx).Err(err).Msg("Failed to update user displayname")
	} else {
		puppet.NameSet = true
	}
	return true
}
