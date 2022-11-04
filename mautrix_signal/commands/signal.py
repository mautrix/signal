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

from typing import Awaitable
import asyncio
import base64
import json

from mausignald.errors import UnknownIdentityKey, UnregisteredUserError
from mausignald.types import Address, GroupID, TrustLevel
from mautrix.appservice import IntentAPI
from mautrix.bridge.commands import SECTION_ADMIN, HelpSection, command_handler
from mautrix.types import (
    ContentURI,
    EventID,
    EventType,
    JoinRule,
    PowerLevelStateEventContent,
    RoomID,
)

from .. import portal as po, puppet as pu
from ..util import normalize_number, user_has_power_level
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

    puppet: pu.Puppet = await pu.Puppet.get_by_number(phone)
    if not puppet:
        if not evt.sender.username:
            await evt.reply("UUID of user not known")
            return None
        try:
            uuid = await evt.bridge.signal.find_uuid(evt.sender.username, phone)
        except UnregisteredUserError:
            await evt.reply("User not registered")
            return None

        if uuid:
            puppet = await pu.Puppet.get_by_uuid(uuid)
        else:
            await evt.reply("UUID of user not found")
            return None
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
    portal = await po.Portal.get_by_chat_id(puppet.uuid, receiver=evt.sender.username, create=True)
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
        puppet = await evt.portal.get_dm_puppet()
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


missing_power_warning = (
    "Warning: The bridge bot ([{bot_mxid}](https://matrix.to/#/{bot_mxid})) does not have "
    "sufficient privileges to change power levels on Matrix. Power level changes will not be "
    "bridged."
)

low_power_warning = (
    "Warning: The bridge bot ([{bot_mxid}](https://matrix.to/#/{bot_mxid})) has a power level "
    "below or equal to 50. Bridged moderator rights are currently hardcoded to PL 50, so the "
    "bridge bot must have a higher level to properly bridge them."
)

meta_power_warning = (
    "Warning: Permissions for changing name, topic and avatar cannot be set separately on Signal. "
    "Changes to those may not be bridged properly, unless the permissions are set to the same "
    "level or lower than state_default."
)


@command_handler(
    needs_auth=True,
    management_only=False,
    help_section=SECTION_SIGNAL,
    help_text="Create a Signal group for the current Matrix room.",
)
async def create(evt: CommandEvent) -> EventID:
    if evt.portal:
        return await evt.reply("This is already a portal room.")

    title, about, levels, encrypted, avatar_url, join_rule = await get_initial_state(
        evt.az.intent, evt.room_id
    )

    portal = po.Portal(
        chat_id=GroupID(""),
        mxid=evt.room_id,
        name=title,
        topic=about or "",
        encrypted=encrypted,
        receiver="",
        avatar_url=avatar_url,
    )
    await warn_missing_power(levels, evt)

    await portal.create_signal_group(evt.sender, levels, join_rule)
    await evt.reply(f"Signal chat created. ID: {portal.chat_id}")


@command_handler(
    name="id",
    needs_auth=True,
    management_only=False,
    help_section=SECTION_SIGNAL,
    help_text="Get the ID of the Signal chat where this room is bridged.",
)
async def get_id(evt: CommandEvent) -> EventID:
    if evt.portal:
        return await evt.reply(f"This room is bridged to Signal chat ID `{evt.portal.chat_id}`.")
    await evt.reply("This is not a portal room.")


@command_handler(
    needs_auth=True,
    management_only=False,
    help_section=SECTION_SIGNAL,
    help_text="Bridge the current Matrix room to the Signal chat with the given ID.",
    help_args="<signal chat ID> [matrix room ID]",
)
async def bridge(evt: CommandEvent) -> EventID:
    if len(evt.args) == 0:
        return await evt.reply(
            "**Usage:** `$cmdprefix+sp bridge <signal chat ID> [matrix room ID]`"
        )
    room_id = RoomID(evt.args[1]) if len(evt.args) > 1 else evt.room_id
    that_this = "This" if room_id == evt.room_id else "That"

    portal = await po.Portal.get_by_mxid(room_id)
    if portal:
        return await evt.reply(f"{that_this} room is already a portal room.")

    if not await user_has_power_level(room_id, evt.az.intent, evt.sender, "bridge"):
        return await evt.reply(f"You do not have the permissions to bridge {that_this} room.")

    portal = await po.Portal.get_by_chat_id(GroupID(evt.args[0]), create=True)
    if portal.mxid:
        has_portal_message = (
            "That Signal chat already has a portal at "
            f"[{portal.mxid}](https://matrix.to/#/{portal.mxid}). "
        )
        if not await user_has_power_level(portal.mxid, evt.az.intent, evt.sender, "unbridge"):
            return await evt.reply(
                f"{has_portal_message}"
                "Additionally, you do not have the permissions to unbridge that room."
            )
        evt.sender.command_status = {
            "next": confirm_bridge,
            "action": "Room bridging",
            "mxid": portal.mxid,
            "bridge_to_mxid": room_id,
            "chat_id": portal.chat_id,
        }
        return await evt.reply(
            f"{has_portal_message}"
            "However, you have the permissions to unbridge that room.\n\n"
            "To delete that portal completely and continue bridging, use "
            "`$cmdprefix+sp delete-and-continue`. To unbridge the portal "
            "without kicking Matrix users, use `$cmdprefix+sp unbridge-and-"
            "continue`. To cancel, use `$cmdprefix+sp cancel`"
        )
    evt.sender.command_status = {
        "next": confirm_bridge,
        "action": "Room bridging",
        "bridge_to_mxid": room_id,
        "chat_id": portal.chat_id,
    }
    return await evt.reply(
        "That Signal chat has no existing portal. To confirm bridging the "
        "chat to this room, use `$cmdprefix+sp continue`"
    )


async def cleanup_old_portal_while_bridging(
    evt: CommandEvent, portal: po.Portal
) -> tuple[bool, Awaitable[None] | None]:
    if not portal.mxid:
        await evt.reply(
            "The portal seems to have lost its Matrix room between you"
            "calling `$cmdprefix+sp bridge` and this command.\n\n"
            "Continuing without touching previous Matrix room..."
        )
        return True, None
    elif evt.args[0] == "delete-and-continue":
        return True, portal.cleanup_portal("Portal deleted (moving to another room)")
    elif evt.args[0] == "unbridge-and-continue":
        return True, portal.cleanup_portal(
            "Room unbridged (portal moving to another room)", puppets_only=True
        )
    else:
        await evt.reply(
            "The chat you were trying to bridge already has a Matrix portal room.\n\n"
            "Please use `$cmdprefix+sp delete-and-continue` or `$cmdprefix+sp unbridge-and-"
            "continue` to either delete or unbridge the existing room (respectively) and "
            "continue with the bridging.\n\n"
            "If you changed your mind, use `$cmdprefix+sp cancel` to cancel."
        )
        return False, None


async def confirm_bridge(evt: CommandEvent) -> EventID | None:
    status = evt.sender.command_status
    try:
        portal = await po.Portal.get_by_chat_id(status["chat_id"])
        bridge_to_mxid = status["bridge_to_mxid"]
    except KeyError:
        evt.sender.command_status = None
        return await evt.reply(
            "Fatal error: chat_id missing from command_status. "
            "This shouldn't happen unless you're messing with the command handler code."
        )

    is_logged_in = await evt.sender.is_logged_in()

    if "mxid" in status:
        ok, coro = await cleanup_old_portal_while_bridging(evt, portal)
        if not ok:
            return None
        elif coro:
            await evt.reply("Cleaning up previous portal room...")
            await coro
    elif portal.mxid:
        evt.sender.command_status = None
        return await evt.reply(
            "The portal seems to have created a Matrix room between you "
            "calling `$cmdprefix+sp bridge` and this command.\n\n"
            "Please start over by calling the bridge command again."
        )
    elif evt.args[0] != "continue":
        return await evt.reply(
            "Please use `$cmdprefix+sp continue` to confirm the bridging or "
            "`$cmdprefix+sp cancel` to cancel."
        )
    evt.sender.command_status = None
    async with portal._create_room_lock:
        await _locked_confirm_bridge(
            evt, portal=portal, room_id=bridge_to_mxid, is_logged_in=is_logged_in
        )


async def _locked_confirm_bridge(
    evt: CommandEvent, portal: po.Portal, room_id: RoomID, is_logged_in: bool
) -> EventID | None:
    try:
        group = await evt.bridge.signal.get_group(
            evt.sender.username, portal.chat_id, portal.revision
        )
    except Exception:
        evt.log.exception("Failed to get_group(%s) for manual bridging.", portal.chat_id)
        if is_logged_in:
            return await evt.reply(
                "Failed to get info of signal chat. You are logged in, are you in that chat?"
            )
        else:
            return await evt.reply(
                "Failed to get info of signal chat. "
                "You're not logged in, this should not happen."
            )

    portal.mxid = room_id
    portal.by_mxid[portal.mxid] = portal
    (
        portal.title,
        portal.about,
        levels,
        portal.encrypted,
        portal.photo_id,
    ) = await get_initial_state(evt.az.intent, evt.room_id)
    await portal.save()
    await portal.update_bridge_info()

    asyncio.create_task(portal.update_matrix_room(evt.sender, group))

    await warn_missing_power(levels, evt)

    return await evt.reply("Bridging complete. Portal synchronization should begin momentarily.")


async def get_initial_state(
    intent: IntentAPI, room_id: RoomID
) -> tuple[
    str | None,
    str | None,
    PowerLevelStateEventContent | None,
    bool,
    ContentURI | None,
    JoinRule | None,
]:
    state = await intent.get_state(room_id)
    title: str | None = None
    about: str | None = None
    levels: PowerLevelStateEventContent | None = None
    encrypted: bool = False
    avatar_url: ContentURI | None = None
    join_rule: JoinRule | None = None
    for event in state:
        try:
            if event.type == EventType.ROOM_NAME:
                title = event.content.name
            elif event.type == EventType.ROOM_TOPIC:
                about = event.content.topic
            elif event.type == EventType.ROOM_POWER_LEVELS:
                levels = event.content
            elif event.type == EventType.ROOM_CANONICAL_ALIAS:
                title = title or event.content.canonical_alias
            elif event.type == EventType.ROOM_ENCRYPTION:
                encrypted = True
            elif event.type == EventType.ROOM_AVATAR:
                avatar_url = event.content.url
            elif event.type == EventType.ROOM_JOIN_RULES:
                join_rule = event.content.join_rule
        except KeyError:
            # Some state event probably has empty content
            pass
    return title, about, levels, encrypted, avatar_url, join_rule


async def warn_missing_power(levels: PowerLevelStateEventContent, evt: CommandEvent) -> None:
    bot_pl = levels.get_user_level(evt.az.bot_mxid)
    if bot_pl < levels.get_event_level(EventType.ROOM_POWER_LEVELS):
        await evt.reply(missing_power_warning.format(bot_mxid=evt.az.bot_mxid))
    elif bot_pl <= 50:
        await evt.reply(low_power_warning.format(bot_mxid=evt.az.bot_mxid))
    if levels.state_default < 50 and (
        levels.events[EventType.ROOM_NAME] >= 50
        or levels.events[EventType.ROOM_AVATAR] >= 50
        or levels.events[EventType.ROOM_TOPIC] >= 50
    ):
        await evt.reply(meta_power_warning)
