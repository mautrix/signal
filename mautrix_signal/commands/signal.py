# mautrix-signal - A Matrix-Signal puppeting bridge
# Copyright (C) 2022 Tulir Asokan
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
from __future__ import annotations

import base64
import json

from mausignald.errors import UnknownIdentityKey
from mausignald.types import Address, TrustLevel
from mautrix.bridge.commands import SECTION_ADMIN, HelpSection, command_handler
from mautrix.types import EventID

from .. import portal as po, puppet as pu
from ..util import normalize_number
from .auth import make_qr
from .typehint import CommandEvent

try:
    import PIL as _
    import qrcode
except ImportError:
    qrcode = None

SECTION_SIGNAL = HelpSection("Signal actions", 20, "")


async def _get_puppet_from_cmd(evt: CommandEvent) -> pu.Puppet | None:
    try:
        phone = normalize_number("".join(evt.args))
    except Exception:
        await evt.reply(
            f"**Usage:** `$cmdprefix+sp {evt.command} <phone>` "
            "(enter phone number in international format)"
        )
        return None

    puppet: pu.Puppet = await pu.Puppet.get_by_address(Address(number=phone))
    if not puppet.uuid and evt.sender.username:
        uuid = await evt.bridge.signal.find_uuid(evt.sender.username, puppet.number)
        if uuid:
            await puppet.handle_uuid_receive(uuid)
    return puppet


def _format_safety_number(number: str) -> str:
    line_size = 20
    chunk_size = 5
    return "\n".join(
        " ".join(
            [
                number[chunk : chunk + chunk_size]
                for chunk in range(line, line + line_size, chunk_size)
            ]
        )
        for line in range(0, len(number), line_size)
    )


def _pill(puppet: "pu.Puppet") -> str:
    return f"[{puppet.name}](https://matrix.to/#/{puppet.mxid})"


@command_handler(
    needs_auth=True,
    management_only=False,
    help_section=SECTION_SIGNAL,
    help_text="Open a private chat portal with a specific phone number",
    help_args="<_phone_>",
)
async def pm(evt: CommandEvent) -> None:
    puppet = await _get_puppet_from_cmd(evt)
    if not puppet:
        return
    portal = await po.Portal.get_by_chat_id(
        puppet.address, receiver=evt.sender.username, create=True
    )
    if portal.mxid:
        await evt.reply(
            f"You already have a private chat with {puppet.name}: "
            f"[{portal.mxid}](https://matrix.to/#/{portal.mxid})"
        )
        await portal.main_intent.invite_user(portal.mxid, evt.sender.mxid)
        return
    await portal.create_matrix_room(evt.sender, puppet.address)
    await evt.reply(f"Created a portal room with {_pill(puppet)} and invited you to it")


@command_handler(
    needs_auth=True,
    management_only=False,
    help_section=SECTION_SIGNAL,
    help_text="Join a Signal group with an invite link",
    help_args="<_link_>",
)
async def join(evt: CommandEvent) -> EventID:
    if len(evt.args) == 0:
        return await evt.reply("**Usage:** `$cmdprefix+sp join <invite link>`")
    try:
        resp = await evt.bridge.signal.join_group(evt.sender.username, evt.args[0])
        if resp.pending_admin_approval:
            return await evt.reply(
                f"Successfully requested to join {resp.title}, waiting for admin approval."
            )
        else:
            return await evt.reply(f"Successfully joined {resp.title}")
    except Exception:
        evt.log.exception("Error trying to join group")
        await evt.reply("Failed to join group (see logs for more details)")


@command_handler(
    needs_auth=True,
    management_only=False,
    help_section=SECTION_SIGNAL,
    help_text="Get the invite link to the current group",
)
async def invite_link(evt: CommandEvent) -> EventID:
    if not evt.is_portal:
        return await evt.reply("This is not a portal room.")
    group = await evt.bridge.signal.get_group(
        evt.sender.username, evt.portal.chat_id, evt.portal.revision
    )
    if not group:
        await evt.reply("Failed to get group info")
    elif not group.invite_link:
        await evt.reply("Invite link not available")
    else:
        await evt.reply(group.invite_link)


@command_handler(
    needs_auth=True,
    management_only=False,
    help_section=SECTION_SIGNAL,
    help_text="View the safety number of a specific user",
    help_args="[--qr] [_phone_]",
)
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
    uuid = resp.address.uuid or "unknown"
    await evt.reply(
        f"### {puppet.name}\n\n"
        f"**UUID:** {uuid}  \n"
        f"**Trust level:** {most_recent.trust_level}  \n"
        f"**Safety number:**\n"
        f"```\n{_format_safety_number(most_recent.safety_number)}\n```"
    )
    if show_qr and most_recent.qr_code_data:
        data = base64.b64decode(most_recent.qr_code_data)
        content = await make_qr(evt.main_intent, data, "verification-qr.png")
        await evt.main_intent.send_message(evt.room_id, content)


@command_handler(
    needs_auth=True,
    management_only=False,
    help_section=SECTION_SIGNAL,
    help_text="Set your Signal profile name",
    help_args="<_name_>",
)
async def set_profile_name(evt: CommandEvent) -> None:
    await evt.bridge.signal.set_profile(evt.sender.username, name=" ".join(evt.args))
    await evt.reply("Successfully updated profile name")


_trust_levels = [x.value for x in TrustLevel]


@command_handler(
    needs_auth=True,
    management_only=False,
    help_section=SECTION_SIGNAL,
    help_text="Mark another user's safety number as trusted",
    help_args="<_recipient phone_> [_level_] <_safety number_>",
)
async def mark_trusted(evt: CommandEvent) -> EventID:
    if len(evt.args) < 2:
        return await evt.reply(
            "**Usage:** `$cmdprefix+sp mark-trusted <recipient phone> [level] <safety number>`"
        )
    number = normalize_number(evt.args[0])
    remaining_args = evt.args[1:]
    trust_level = TrustLevel.TRUSTED_VERIFIED
    if len(evt.args) > 2 and evt.args[1].upper() in _trust_levels:
        trust_level = TrustLevel(evt.args[1])
        remaining_args = evt.args[2:]
    safety_num = "".join(remaining_args).replace("\n", "")
    if len(safety_num) != 60 or not safety_num.isdecimal():
        return await evt.reply("That doesn't look like a valid safety number")
    try:
        await evt.bridge.signal.trust(
            evt.sender.username,
            Address(number=number),
            safety_number=safety_num,
            trust_level=trust_level,
        )
    except UnknownIdentityKey as e:
        return await evt.reply(f"Failed to mark {number} as {trust_level.human_str}: {e}")
    return await evt.reply(f"Successfully marked {number} as {trust_level.human_str}")


@command_handler(
    needs_admin=False,
    needs_auth=True,
    help_section=SECTION_SIGNAL,
    help_text="Sync data from Signal",
)
async def sync(evt: CommandEvent) -> None:
    await evt.sender.sync()
    await evt.reply("Sync complete")


@command_handler(
    needs_admin=True,
    needs_auth=False,
    help_section=SECTION_ADMIN,
    help_text="Send raw requests to signald",
    help_args="[--user] <type> <_json_>",
)
async def raw(evt: CommandEvent) -> None:
    add_username = False
    while True:
        flag = evt.args[0].lower()
        if flag == "--user":
            add_username = True
        else:
            break
        evt.args = evt.args[1:]
    type = evt.args[0]
    version = "v0"
    if "." in type:
        version, type = type.split(".", 1)
    try:
        args = json.loads(" ".join(evt.args[1:]))
    except json.JSONDecodeError as e:
        await evt.reply(f"JSON decode error: {e}")
        return
    if add_username:
        if version == "v0" or (version == "v1" and type in ("send", "react")):
            args["username"] = evt.sender.username
        else:
            args["account"] = evt.sender.username
    if version:
        args["version"] = version

    try:
        resp_type, resp_data = await evt.bridge.signal._raw_request(type, **args)
    except Exception as e:
        await evt.reply(f"Error sending request: {e}")
    else:
        if resp_data is None:
            await evt.reply(f"Got reply `{resp_type}` with no content")
        else:
            await evt.reply(
                f"Got reply `{resp_type}`:\n\n```json\n{json.dumps(resp_data, indent=2)}\n```"
            )
