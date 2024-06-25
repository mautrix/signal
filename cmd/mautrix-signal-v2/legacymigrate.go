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

package main

import (
	_ "embed"

	up "go.mau.fi/util/configupgrade"

	"maunium.net/go/mautrix/bridgev2/bridgeconfig"
)

const legacyMigrateRenameTables = `
ALTER TABLE portal RENAME TO portal_old;
ALTER TABLE puppet RENAME TO puppet_old;
ALTER TABLE "user" RENAME TO user_old;
ALTER TABLE user_portal RENAME TO user_portal_old;
ALTER TABLE message RENAME TO message_old;
ALTER TABLE reaction RENAME TO reaction_old;
ALTER TABLE disappearing_message RENAME TO disappearing_message_old;
`

//go:embed legacymigrate.sql
var legacyMigrateCopyData string

func migrateLegacyConfig(helper up.Helper) {
	helper.Set(up.Str, "mautrix.bridge.e2ee", "encryption", "pickle_key")
	bridgeconfig.CopyToOtherLocation(helper, up.Str, []string{"bridge", "displayname_template"}, []string{"network", "displayname_template"})
	bridgeconfig.CopyToOtherLocation(helper, up.Str, []string{"bridge", "note_to_self_avatar"}, []string{"network", "note_to_self_avatar"})
	bridgeconfig.CopyToOtherLocation(helper, up.Str, []string{"bridge", "location_format"}, []string{"network", "location_format"})
	bridgeconfig.CopyToOtherLocation(helper, up.Bool, []string{"bridge", "use_contact_avatars"}, []string{"network", "use_contact_avatars"})
	bridgeconfig.CopyToOtherLocation(helper, up.Bool, []string{"bridge", "use_outdated_profiles"}, []string{"network", "use_outdated_profiles"})
	bridgeconfig.CopyToOtherLocation(helper, up.Bool, []string{"bridge", "number_in_topic"}, []string{"network", "number_in_topic"})
	bridgeconfig.CopyToOtherLocation(helper, up.Str, []string{"signal", "device_name"}, []string{"network", "device_name"})
}
