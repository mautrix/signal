# mautrix-signal - A Matrix-Signal puppeting bridge
# Copyright (C) 2020 Tulir Asokan
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
from mautrix.bridge.commands import HelpSection, command_handler
from mausignald.types import Address

from .. import puppet as pu, portal as po
from .typehint import CommandEvent

SECTION_CREATING_PORTALS = HelpSection("Creating portals", 20, "")

remove_extra_chars = str.maketrans("", "", " .,-()")


@command_handler(needs_auth=True, management_only=False, help_section=SECTION_CREATING_PORTALS,
                 help_text="Open a private chat portal with a specific phone number",
                 help_args="<_phone_>")
async def pm(evt: CommandEvent) -> None:
    if len(evt.args) == 0 or not evt.args[0].startswith("+"):
        await evt.reply("**Usage:** `$cmdprefix+sp pm <phone>` "
                        "(enter phone number in international format)")
        return
    phone = "".join(evt.args).translate(remove_extra_chars)
    if not phone[1:].isdecimal():
        await evt.reply("**Usage:** `$cmdprefix+sp pm <phone>` "
                        "(enter phone number in international format)")
        return
    puppet = await pu.Puppet.get_by_address(Address(number=phone))
    portal = await po.Portal.get_by_chat_id(puppet.address, receiver=evt.sender.username,
                                            create=True)
    if portal.mxid:
        await evt.reply(f"You already have a private chat with {puppet.name}: "
                        f"[{portal.mxid}](https://matrix.to/#/{portal.mxid})")
        await portal.main_intent.invite_user(portal.mxid, evt.sender.mxid)
        return
    await portal.create_matrix_room(evt.sender, puppet.address)
    await evt.reply(f"Created a portal room with [{puppet.name}](https://matrix.to/#/{puppet.mxid}) and invited you to it")
