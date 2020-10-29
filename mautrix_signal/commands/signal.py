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
from typing import Optional
import base64
import io

from mautrix.types import MediaMessageEventContent, MessageType, ImageInfo
from mautrix.bridge.commands import HelpSection, command_handler
from mausignald.types import Address

from .. import puppet as pu, portal as po
from .auth import make_qr
from .typehint import CommandEvent

try:
    import qrcode
    import PIL as _
except ImportError:
    qrcode = None

SECTION_SIGNAL = HelpSection("Signal actions", 20, "")

remove_extra_chars = str.maketrans("", "", " .,-()")


async def _get_puppet_from_cmd(evt: CommandEvent) -> Optional['pu.Puppet']:
    if len(evt.args) == 0 or not evt.args[0].startswith("+"):
        await evt.reply("**Usage:** `$cmdprefix+sp pm <phone>` "
                        "(enter phone number in international format)")
        return None
    phone = "".join(evt.args).translate(remove_extra_chars)
    if not phone[1:].isdecimal():
        await evt.reply("**Usage:** `$cmdprefix+sp pm <phone>` "
                        "(enter phone number in international format)")
        return None
    return await pu.Puppet.get_by_address(Address(number=phone))


def _format_safety_number(number: str) -> str:
    line_size = 20
    chunk_size = 5
    return "\n".join(" ".join([number[chunk:chunk + chunk_size]
                               for chunk in range(line, line + line_size, chunk_size)])
                     for line in range(0, len(number), line_size))


def _pill(puppet: 'pu.Puppet') -> str:
    return f"[{puppet.name}](https://matrix.to/#/{puppet.mxid})"


@command_handler(needs_auth=True, management_only=False, help_section=SECTION_SIGNAL,
                 help_text="Open a private chat portal with a specific phone number",
                 help_args="<_phone_>")
async def pm(evt: CommandEvent) -> None:
    puppet = await _get_puppet_from_cmd(evt)
    if not puppet:
        return
    portal = await po.Portal.get_by_chat_id(puppet.address, receiver=evt.sender.username,
                                            create=True)
    if portal.mxid:
        await evt.reply(f"You already have a private chat with {puppet.name}: "
                        f"[{portal.mxid}](https://matrix.to/#/{portal.mxid})")
        await portal.main_intent.invite_user(portal.mxid, evt.sender.mxid)
        return
    await portal.create_matrix_room(evt.sender, puppet.address)
    await evt.reply(f"Created a portal room with {_pill(puppet)} and invited you to it")


@command_handler(needs_auth=True, management_only=False, help_section=SECTION_SIGNAL,
                 help_text="View the safety number of a specific user",
                 help_args="[--qr] [_phone_]")
async def safety_number(evt: CommandEvent) -> None:
    show_qr = evt.args and evt.args[0].lower() == "--qr"
    if show_qr:
        if not qrcode:
            await evt.reply("Can't generate QR code: qrcode and/or PIL not installed")
            return
        evt.args = evt.args[1:]
    if len(evt.args) == 0 and evt.portal and evt.portal.is_direct:
        puppet = await pu.Puppet.get_by_address(evt.portal.chat_id)
    else:
        puppet = await _get_puppet_from_cmd(evt)
    if not puppet:
        return

    resp = await evt.bridge.signal.get_identities(evt.sender.username, puppet.address)
    if not resp.identities:
        await evt.reply(f"No identities found for {_pill(puppet)}")
        return
    most_recent = resp.identities[0]
    for identity in resp.identities:
        if identity.added > most_recent.added:
            most_recent = identity
    uuid = most_recent.address.uuid or "unknown"
    await evt.reply(f"### {puppet.name}\n\n"
                    f"**UUID:** {uuid}  \n"
                    f"**Trust level:** {most_recent.trust_level}  \n"
                    f"**Safety number:**\n"
                    f"```\n{_format_safety_number(most_recent.safety_number)}\n```")
    if show_qr and most_recent.qr_code_data:
        data = base64.b64decode(most_recent.qr_code_data)
        content = await make_qr(evt.main_intent, data, "verification-qr.png")
        await evt.main_intent.send_message(evt.room_id, content)
