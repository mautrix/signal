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
from typing import Union
import io

from mausignald.errors import (
    AuthorizationFailedError,
    CaptchaRequiredError,
    ScanTimeoutError,
    TimeoutException,
    UnexpectedResponse,
)
from mautrix.appservice import IntentAPI
from mautrix.bridge.commands import HelpSection, command_handler
from mautrix.types import EventID, ImageInfo, MediaMessageEventContent, MessageType, UserID

from .. import puppet as pu
from ..util import normalize_number
from .typehint import CommandEvent

try:
    import PIL as _
    import qrcode
except ImportError:
    qrcode = None

SECTION_AUTH = HelpSection("Authentication", 10, "")


async def make_qr(
    intent: IntentAPI, data: Union[str, bytes], body: str = None
) -> MediaMessageEventContent:
    # TODO always encrypt QR codes?
    buffer = io.BytesIO()
    image = qrcode.make(data)
    size = image.pixel_size
    image.save(buffer, "PNG")
    qr = buffer.getvalue()
    mxc = await intent.upload_media(qr, "image/png", "qr.png", len(qr))
    return MediaMessageEventContent(
        body=body or data,
        url=mxc,
        msgtype=MessageType.IMAGE,
        info=ImageInfo(mimetype="image/png", size=len(qr), width=size, height=size),
    )


@command_handler(
    needs_auth=False,
    management_only=True,
    needs_admin=True,
    help_section=SECTION_AUTH,
    help_text="Connect to an existing account on signald",
    help_args="[mxid] <phone number>",
)
async def connect_existing(evt: CommandEvent) -> EventID:
    if len(evt.args) == 0:
        return await evt.reply("**Usage:** `$cmdprefix+sp connect-existing [mxid] <phone number>`")
    if evt.args[0].startswith("@"):
        evt.sender = await evt.bridge.get_user(UserID(evt.args[0]))
        evt.args = evt.args[1:]
    if await evt.sender.is_logged_in():
        return await evt.reply(
            "You're already logged in. "
            "If you want to relink, log out with `$cmdprefix+sp logout` first."
        )
    try:
        account_id = normalize_number("".join(evt.args))
    except Exception:
        return await evt.reply("Please enter the phone number in international format (E.164)")
    accounts = await evt.bridge.signal.list_accounts()
    for account in accounts:
        if account.account_id == account_id:
            await evt.sender.on_signin(account)
            return await evt.reply(
                f"Successfully logged in as {pu.Puppet.fmt_phone(evt.sender.username)} "
                f"(device #{account.device_id})"
            )
    return await evt.reply(f"Account with ID {account_id} not found in signald")


@command_handler(
    needs_auth=False,
    management_only=True,
    help_section=SECTION_AUTH,
    help_text="Link the bridge as a secondary device",
    help_args="[device name]",
    aliases=["login"],
)
async def link(evt: CommandEvent) -> None:
    if qrcode is None:
        await evt.reply("Can't generate QR code: qrcode and/or PIL not installed")
        return
    if await evt.sender.is_logged_in():
        await evt.reply(
            "You're already logged in. "
            "If you want to relink, log out with `$cmdprefix+sp logout` first."
        )
        return
    # TODO make default device name configurable
    device_name = " ".join(evt.args) or "Mautrix-Signal bridge"

    sess = await evt.bridge.signal.start_link()
    content = await make_qr(evt.az.intent, sess.uri)
    event_id = await evt.az.intent.send_message(evt.room_id, content)
    try:
        account = await evt.bridge.signal.finish_link(
            session_id=sess.session_id, overwrite=True, device_name=device_name
        )
    except (TimeoutException, ScanTimeoutError):
        await evt.reply("Linking timed out, please try again.")
    except Exception:
        evt.log.exception("Fatal error while waiting for linking to finish")
        await evt.reply(
            "Fatal error while waiting for linking to finish (see logs for more details)"
        )
    else:
        await evt.sender.on_signin(account)
        await evt.reply(
            f"Successfully logged in as {pu.Puppet.fmt_phone(evt.sender.username)} "
            f"(device #{account.device_id})"
        )
    finally:
        await evt.main_intent.redact(evt.room_id, event_id)


@command_handler(
    needs_auth=False,
    management_only=True,
    help_section=SECTION_AUTH,
    is_enabled_for=lambda evt: evt.config["signal.registration_enabled"],
    help_text="Sign into Signal as the primary device",
    help_args="<phone>",
)
async def register(evt: CommandEvent) -> None:
    if len(evt.args) == 0:
        await evt.reply("**Usage**: $cmdprefix+sp register [--voice] [--captcha <token>] <phone>")
        return
    if await evt.sender.is_logged_in():
        await evt.reply(
            "You're already logged in. "
            "If you want to re-register, log out with `$cmdprefix+sp logout` first."
        )
        return
    voice = False
    captcha = None
    while True:
        flag = evt.args[0].lower()
        if flag == "--voice" or flag == "-v":
            voice = True
            evt.args = evt.args[1:]
        elif flag == "--captcha" or flag == "-c":
            if "=" in evt.args[0]:
                captcha = evt.args[0].split("=", 1)[1]
                evt.args = evt.args[1:]
            else:
                captcha = evt.args[1]
                evt.args = evt.args[2:]
        else:
            break
    try:
        phone = normalize_number(evt.args[0])
    except Exception:
        await evt.reply("Please enter the phone number in international format (E.164)")
        return
    try:
        username = await evt.bridge.signal.register(phone, voice=voice, captcha=captcha)
        evt.sender.command_status = {
            "action": "Register",
            "room_id": evt.room_id,
            "next": enter_register_code,
            "username": username,
        }
        await evt.reply("Register SMS requested, please enter the code here.")
    except CaptchaRequiredError:
        await evt.reply(
            "Captcha required. Please follow the instructions at https://signald.org/articles/captcha/ "
            "to obtain a captcha token and paste it here."
        )
        evt.sender.command_status = {
            "action": "Register",
            "room_id": evt.room_id,
            "next": enter_captcha_token,
            "voice": voice,
            "phone": phone,
        }


async def enter_captcha_token(evt: CommandEvent) -> None:
    captcha = evt.args[0]
    phone = evt.sender.command_status["phone"]
    voice = evt.sender.command_status["voice"]
    username = await evt.bridge.signal.register(phone, voice=voice, captcha=captcha)
    evt.sender.command_status = {
        "action": "Register",
        "room_id": evt.room_id,
        "next": enter_register_code,
        "username": username,
    }
    await evt.reply("Register SMS requested, please enter the code here.")


async def enter_register_code(evt: CommandEvent) -> None:
    try:
        username = evt.sender.command_status["username"]
        account = await evt.bridge.signal.verify(username, code=evt.args[0])
    except UnexpectedResponse as e:
        if e.resp_type == "error":
            await evt.reply(e.data)
        else:
            raise
    else:
        await evt.sender.on_signin(account)
        await evt.reply(
            f"Successfully logged in as {pu.Puppet.fmt_phone(evt.sender.username)}."
            f"\n\n**N.B.** You must set a Signal profile name with `$cmdprefix+sp "
            f"set-profile-name <name>` before you can participate in new groups."
        )


@command_handler(
    needs_auth=True,
    management_only=True,
    help_section=SECTION_AUTH,
    help_text="Remove all local data about your Signal link",
)
async def logout(evt: CommandEvent) -> None:
    if not evt.sender.username:
        await evt.reply("You're not logged in")
        return
    await evt.sender.logout()
    await evt.reply("Successfully logged out")


@command_handler(
    needs_auth=False,
    management_only=True,
    needs_admin=True,
    help_section=SECTION_AUTH,
    help_text="Remove all local data about a user's Signal link",
    help_args="<mxid>",
)
async def logout_user(evt: CommandEvent) -> None:
    if len(evt.args) == 0:
        await evt.reply("**Usage**: $cmdprefix+sp logout-user <mxid>")
    user = await evt.bridge.get_user(UserID(evt.args[0]))
    if not await user.is_logged_in():
        await evt.reply("This user is not logged in")
        return
    await user.logout()
    await evt.reply("Successfully logged out")


@command_handler(
    needs_auth=True,
    management_only=True,
    help_section=SECTION_AUTH,
    help_text="List devices linked to your Signal account",
)
async def list_devices(evt: CommandEvent) -> None:
    devices = await evt.bridge.signal.get_linked_devices(evt.sender.username)
    await evt.reply(
        "\n".join(
            f"* #{dev.id}: {dev.name_with_default} (created {dev.created_fmt}, last seen "
            f"{dev.last_seen_fmt})"
            for dev in devices
        )
    )


@command_handler(
    needs_auth=True,
    management_only=True,
    help_section=SECTION_AUTH,
    help_text="Add a device with a `sgnl://linkdevice?...` URI from a QR code",
)
async def add_linked_device(evt: CommandEvent) -> EventID:
    if len(evt.args) == 0:
        return await evt.reply("**Usage:** `$cmdprefix+sp add-linked-device <URI from QR code>`")
    try:
        await evt.bridge.signal.add_linked_device(evt.sender.username, evt.args[0])
    except AuthorizationFailedError as e:
        return await evt.reply(f"{e} Only the primary device can add linked devices.")
    else:
        return await evt.reply("Device linked successfully")


@command_handler(
    needs_auth=True,
    management_only=True,
    help_section=SECTION_AUTH,
    help_text="Remove a linked device",
)
async def remove_linked_device(evt: CommandEvent) -> EventID:
    if len(evt.args) == 0:
        return await evt.reply("**Usage:** `$cmdprefix+sp remove-linked-device <device ID>`")
    device_id = int(evt.args[0])
    try:
        await evt.bridge.signal.remove_linked_device(evt.sender.username, device_id)
    except AuthorizationFailedError as e:
        return await evt.reply(f"{e} Only the primary device can remove linked devices.")
    return await evt.reply("Device removed")
