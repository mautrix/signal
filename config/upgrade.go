// mautrix-signal - A Matrix-Signal puppeting bridge.
// Copyright (C) 2022 Tulir Asokan
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

package config

import (
	up "go.mau.fi/util/configupgrade"
	"go.mau.fi/util/random"
	"maunium.net/go/mautrix/bridge/bridgeconfig"
)

func DoUpgrade(helper *up.Helper) {
	bridgeconfig.Upgrader.DoUpgrade(helper)

	helper.Copy(up.Bool, "metrics", "enabled")
	helper.Copy(up.Str, "metrics", "listen")

	helper.Copy(up.Str, "bridge", "username_template")
	helper.Copy(up.Str, "bridge", "displayname_template")
	helper.Copy(up.Str, "bridge", "private_chat_portal_meta")
	helper.Copy(up.Int, "bridge", "portal_message_buffer")
	helper.Copy(up.Bool, "bridge", "delivery_receipts")
	helper.Copy(up.Bool, "bridge", "message_status_events")
	helper.Copy(up.Bool, "bridge", "message_error_notices")
	helper.Copy(up.Bool, "bridge", "sync_direct_chat_list")
	helper.Copy(up.Bool, "bridge", "resend_bridge_info")
	helper.Copy(up.Bool, "bridge", "federate_rooms")
	helper.Copy(up.Map, "bridge", "double_puppet_server_map")
	helper.Copy(up.Bool, "bridge", "double_puppet_allow_discovery")
	helper.Copy(up.Map, "bridge", "login_shared_secret_map")
	helper.Copy(up.Str, "bridge", "command_prefix")
	helper.Copy(up.Str, "bridge", "management_room_text", "welcome")
	helper.Copy(up.Str, "bridge", "management_room_text", "welcome_connected")
	helper.Copy(up.Str, "bridge", "management_room_text", "welcome_unconnected")
	helper.Copy(up.Str|up.Null, "bridge", "management_room_text", "additional_help")
	helper.Copy(up.Bool, "bridge", "encryption", "allow")
	helper.Copy(up.Bool, "bridge", "encryption", "default")
	helper.Copy(up.Bool, "bridge", "encryption", "require")
	helper.Copy(up.Bool, "bridge", "encryption", "appservice")
	helper.Copy(up.Bool, "bridge", "encryption", "allow_key_sharing")
	helper.Copy(up.Bool, "bridge", "encryption", "delete_keys", "delete_outbound_on_ack")
	helper.Copy(up.Bool, "bridge", "encryption", "delete_keys", "dont_store_outbound")
	helper.Copy(up.Bool, "bridge", "encryption", "delete_keys", "ratchet_on_decrypt")
	helper.Copy(up.Bool, "bridge", "encryption", "delete_keys", "delete_fully_used_on_decrypt")
	helper.Copy(up.Bool, "bridge", "encryption", "delete_keys", "delete_prev_on_new_session")
	helper.Copy(up.Bool, "bridge", "encryption", "delete_keys", "delete_on_device_delete")
	helper.Copy(up.Bool, "bridge", "encryption", "delete_keys", "periodically_delete_expired")
	helper.Copy(up.Bool, "bridge", "encryption", "delete_keys", "delete_outdated_inbound")
	helper.Copy(up.Str, "bridge", "encryption", "verification_levels", "receive")
	helper.Copy(up.Str, "bridge", "encryption", "verification_levels", "send")
	helper.Copy(up.Str, "bridge", "encryption", "verification_levels", "share")
	helper.Copy(up.Bool, "bridge", "encryption", "rotation", "enable_custom")
	helper.Copy(up.Int, "bridge", "encryption", "rotation", "milliseconds")
	helper.Copy(up.Int, "bridge", "encryption", "rotation", "messages")
	helper.Copy(up.Bool, "bridge", "encryption", "rotation", "disable_device_change_key_rotation")

	helper.Copy(up.Str, "bridge", "provisioning", "prefix")
	if secret, ok := helper.Get(up.Str, "bridge", "provisioning", "shared_secret"); !ok || secret == "generate" {
		sharedSecret := random.String(64)
		helper.Set(up.Str, sharedSecret, "bridge", "provisioning", "shared_secret")
	} else {
		helper.Copy(up.Str, "bridge", "provisioning", "shared_secret")
	}

	helper.Copy(up.Map, "bridge", "permissions")
}

var SpacedBlocks = [][]string{
	{"homeserver", "software"},
	{"appservice"},
	{"appservice", "hostname"},
	{"appservice", "database"},
	{"appservice", "id"},
	{"appservice", "as_token"},
	{"metrics"},
	{"bridge"},
	{"bridge", "command_prefix"},
	{"bridge", "management_room_text"},
	{"bridge", "encryption"},
	{"bridge", "provisioning"},
	{"bridge", "permissions"},
	{"logging"},
}
