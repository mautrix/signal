# mautrix-signal - A Matrix-Signal puppeting bridge
# Copyright (C) 2021 Tulir Asokan
#
# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU Affero General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU Affero General Public License for more details.
#
# You should have received a copy of the GNU Affero General Public License
# along with this program.  If not, see <https://www.gnu.org/licenses/>.
from typing import Any, List, NamedTuple
import os

from mautrix.bridge.config import BaseBridgeConfig
from mautrix.client import Client
from mautrix.types import UserID
from mautrix.util.config import ConfigUpdateHelper, ForbiddenDefault, ForbiddenKey

Permissions = NamedTuple("Permissions", relay=bool, user=bool, admin=bool, level=str)


class Config(BaseBridgeConfig):
    @property
    def forbidden_defaults(self) -> List[ForbiddenDefault]:
        return [
            *super().forbidden_defaults,
            ForbiddenDefault("appservice.database", "postgres://username:password@hostname/db"),
            ForbiddenDefault("bridge.permissions", ForbiddenKey("example.com")),
        ]

    def do_update(self, helper: ConfigUpdateHelper) -> None:
        super().do_update(helper)
        copy, copy_dict, base = helper

        copy("signal.socket_path")
        copy("signal.outgoing_attachment_dir")
        copy("signal.avatar_dir")
        copy("signal.data_dir")
        copy("signal.delete_unknown_accounts_on_start")
        copy("signal.remove_file_after_handling")
        copy("signal.registration_enabled")
        copy("signal.enable_disappearing_messages_in_groups")

        copy("metrics.enabled")
        copy("metrics.listen_port")

        copy("bridge.username_template")
        copy("bridge.displayname_template")
        if self["bridge.allow_contact_list_name_updates"]:
            base["bridge.contact_list_names"] = "allow"
        else:
            copy("bridge.contact_list_names")
        copy("bridge.displayname_preference")

        copy("bridge.autocreate_group_portal")
        copy("bridge.autocreate_contact_portal")
        copy("bridge.sync_with_custom_puppets")
        copy("bridge.public_portals")
        copy("bridge.sync_direct_chat_list")
        copy("bridge.double_puppet_server_map")
        copy("bridge.double_puppet_allow_discovery")
        if self["bridge.login_shared_secret"]:
            base["bridge.login_shared_secret_map"] = {
                base["homeserver.domain"]: self["bridge.login_shared_secret"]
            }
        else:
            copy("bridge.login_shared_secret_map")
        copy("bridge.federate_rooms")
        copy("bridge.private_chat_portal_meta")
        copy("bridge.delivery_receipts")
        copy("bridge.delivery_error_reports")
        copy("bridge.message_status_events")
        copy("bridge.resend_bridge_info")
        copy("bridge.periodic_sync")

        copy("bridge.provisioning.enabled")
        copy("bridge.provisioning.prefix")
        if base["bridge.provisioning.prefix"].endswith("/v1"):
            base["bridge.provisioning.prefix"] = base["bridge.provisioning.prefix"][: -len("/v1")]
        copy("bridge.provisioning.shared_secret")
        if base["bridge.provisioning.shared_secret"] == "generate":
            base["bridge.provisioning.shared_secret"] = self._new_token()
        copy("bridge.provisioning.segment_key")

        copy("bridge.command_prefix")

        copy_dict("bridge.permissions")

        copy("bridge.relay.enabled")
        copy_dict("bridge.relay.message_formats")
        copy("bridge.relay.relaybot")
        copy("bridge.bridge_matrix_leave")
        copy("bridge.location_format")

    def _get_permissions(self, key: str) -> Permissions:
        level = self["bridge.permissions"].get(key, "")
        admin = level == "admin"
        user = level == "user" or admin
        relay = level == "relay" or user
        return Permissions(relay, user, admin, level)

    def get_permissions(self, mxid: UserID) -> Permissions:
        permissions = self["bridge.permissions"]
        if mxid in permissions:
            return self._get_permissions(mxid)

        _, homeserver = Client.parse_user_id(mxid)
        if homeserver in permissions:
            return self._get_permissions(homeserver)

        return self._get_permissions("*")
