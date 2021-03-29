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

from mausignald.errors import UnexpectedResponse, TimeoutException
from mautrix.client import Client
from mautrix.bridge import custom_puppet as cpu
from mautrix.appservice import IntentAPI
from mautrix.types import MediaMessageEventContent, MessageType, ImageInfo
from mautrix.bridge.commands import HelpSection, command_handler

from .. import puppet as pu
from .typehint import CommandEvent

try:
    import qrcode
    import PIL as _
except ImportError:
    qrcode = None

SECTION_AUTH = HelpSection("Authentication", 10, "")
remove_extra_chars = str.maketrans("", "", " .,-()")


async def make_qr(intent: IntentAPI, data: Union[str, bytes], body: str = None
                  ) -> MediaMessageEventContent:
    # TODO always encrypt QR codes?
    buffer = io.BytesIO()
    image = qrcode.make(data)
    size = image.pixel_size
    image.save(buffer, "PNG")
    qr = buffer.getvalue()
    mxc = await intent.upload_media(qr, "image/png", "qr.png", len(qr))
    return MediaMessageEventContent(body=body or data, url=mxc, msgtype=MessageType.IMAGE,
                                    info=ImageInfo(mimetype="image/png", size=len(qr),
                                                   width=size, height=size))


@command_handler(needs_auth=False, management_only=True, help_section=SECTION_AUTH,
                 help_text="Link the bridge as a secondary device", help_args="[device name]")
async def link(evt: CommandEvent) -> None:
    if qrcode is None:
        await evt.reply("Can't generate QR code: qrcode and/or PIL not installed")
        return
    # TODO make default device name configurable
    device_name = " ".join(evt.args) or "Mautrix-Signal bridge"

    sess = await evt.bridge.signal.start_link()
    content = await make_qr(evt.az.intent, sess.uri)
    event_id = await evt.az.intent.send_message(evt.room_id, content)
    try:
        account = await evt.bridge.signal.finish_link(session_id=sess.session_id,
                                                      device_name=device_name)
    except TimeoutException:
        await evt.reply("Linking timed out, please try again.")
    except Exception:
        evt.log.exception("Fatal error while waiting for linking to finish")
        await evt.reply("Fatal error while waiting for linking to finish "
                        "(see logs for more details)")
    else:
        await evt.sender.on_signin(account)
        await evt.reply(f"Successfully logged in as {pu.Puppet.fmt_phone(evt.sender.username)}")
    finally:
        await evt.main_intent.redact(evt.room_id, event_id)


@command_handler(needs_auth=False, management_only=True, help_section=SECTION_AUTH,
                 help_text="Sign into Signal as the primary device", help_args="<phone>")
async def register(evt: CommandEvent) -> None:
    if len(evt.args) == 0:
        await evt.reply("**Usage**: $cmdprefix+sp register [--voice] <phone>")
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
    phone = evt.args[0].translate(remove_extra_chars)
    if not phone.startswith("+") or not phone[1:].isdecimal():
        await evt.reply(f"Please enter the phone number in international format (E.164)")
        return
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
        await evt.reply(f"Successfully logged in as {pu.Puppet.fmt_phone(evt.sender.username)}."
                        f"\n\n**N.B.** You must set a Signal profile name with `$cmdprefix+sp "
                        f"set-profile-name <name>` before you can participate in new groups.")


@command_handler(needs_auth=True, management_only=True, help_section=SECTION_AUTH,
                 help_text="Remove all local data about your Signal link")
async def logout(evt: CommandEvent) -> None:
    if not evt.sender.username:
        await evt.reply("You're not logged in")
        return
    await evt.sender.logout()
    await evt.reply("Successfully logged out")


@command_handler(needs_auth=True, management_only=True, help_args="<_access token_>",
                 help_section=SECTION_AUTH, help_text="Replace your Signal account's Matrix puppet"
                                                      " with your Matrix account")
async def login_matrix(evt: CommandEvent) -> None:
    puppet = await pu.Puppet.get_by_address(evt.sender.address)
    _, homeserver = Client.parse_mxid(evt.sender.mxid)
    if homeserver != pu.Puppet.hs_domain:
        await evt.reply("You can't log in with an account on a different homeserver")
        return
    try:
        await puppet.switch_mxid(" ".join(evt.args), evt.sender.mxid)
        await evt.reply("Successfully replaced your Signal account's "
                        "Matrix puppet with your Matrix account.")
    except cpu.OnlyLoginSelf:
        await evt.reply("You may only log in with your own Matrix account")
    except cpu.InvalidAccessToken:
        await evt.reply("Invalid access token")


@command_handler(needs_auth=True, management_only=True, help_section=SECTION_AUTH,
                 help_text="Revert your Signal account's Matrix puppet to the original")
async def logout_matrix(evt: CommandEvent) -> None:
    puppet = await pu.Puppet.get_by_address(evt.sender.address)
    if not puppet.is_real_user:
        await evt.reply("You're not logged in with your Matrix account")
        return
    await puppet.switch_mxid(None, None)
    await evt.reply("Restored the original puppet for your Signal account")
