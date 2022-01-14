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

from typing import TYPE_CHECKING, Any, AsyncGenerator, Awaitable, Callable, Union, cast
from collections import deque
from uuid import UUID, uuid4
import asyncio
import hashlib
import mimetypes
import os
import os.path
import pathlib
import time

from mausignald.errors import NotConnected, ResponseError, RPCError
from mausignald.types import (
    AccessControlMode,
    Address,
    Attachment,
    Contact,
    Group,
    GroupAccessControl,
    GroupID,
    GroupMemberRole,
    GroupV2,
    GroupV2ID,
    Mention,
    MessageData,
    Profile,
    Quote,
    QuotedAttachment,
    Reaction,
    SharedContact,
    Sticker,
)
from mautrix.appservice import AppService, IntentAPI
from mautrix.bridge import BasePortal, async_getter_lock
from mautrix.errors import IntentError, MatrixError, MForbidden
from mautrix.types import (
    AudioInfo,
    ContentURI,
    EncryptedEvent,
    EventID,
    EventType,
    FileInfo,
    ImageInfo,
    MediaMessageEventContent,
    MessageEvent,
    MessageEventContent,
    MessageType,
    PowerLevelStateEventContent,
    RoomID,
    SingleReceiptEventContent,
    TextMessageEventContent,
    UserID,
    VideoInfo,
)
from mautrix.util import ffmpeg, variation_selector
from mautrix.util.bridge_state import BridgeStateEvent
from mautrix.util.format_duration import format_duration
from mautrix.util.message_send_checkpoint import MessageSendCheckpointStatus

from . import matrix as m, puppet as p, signal as s, user as u
from .config import Config
from .db import (
    DisappearingMessage,
    Message as DBMessage,
    Portal as DBPortal,
    Reaction as DBReaction,
)
from .formatter import matrix_to_signal, signal_to_matrix
from .util import id_to_str

if TYPE_CHECKING:
    from .__main__ import SignalBridge

try:
    from mautrix.crypto.attachments import decrypt_attachment, encrypt_attachment
except ImportError:
    encrypt_attachment = decrypt_attachment = None

try:
    from signalstickers_client import StickersClient
    from signalstickers_client.models import StickerPack
except ImportError:
    StickersClient = StickerPack = None

try:
    from mautrix.util import magic
except ImportError:
    magic = None

StateBridge = EventType.find("m.bridge", EventType.Class.STATE)
StateHalfShotBridge = EventType.find("uk.half-shot.bridge", EventType.Class.STATE)
ChatInfo = Union[Group, GroupV2, GroupV2ID, Contact, Profile, Address]
MAX_MATRIX_MESSAGE_SIZE = 60000


class Portal(DBPortal, BasePortal):
    by_mxid: dict[RoomID, Portal] = {}
    by_chat_id: dict[tuple[str, str], Portal] = {}
    _sticker_meta_cache: dict[str, StickerPack] = {}
    config: Config
    matrix: m.MatrixHandler
    signal: s.SignalHandler
    az: AppService
    private_chat_portal_meta: bool
    expiration_time: int | None

    _main_intent: IntentAPI | None
    _create_room_lock: asyncio.Lock
    _msgts_dedup: deque[tuple[Address, int]]
    _reaction_dedup: deque[tuple[Address, int, str, Address]]
    _reaction_lock: asyncio.Lock
    _pending_members: set[UUID] | None
    _expiration_lock: asyncio.Lock

    def __init__(
        self,
        chat_id: GroupID | Address,
        receiver: str,
        mxid: RoomID | None = None,
        name: str | None = None,
        avatar_hash: str | None = None,
        avatar_url: ContentURI | None = None,
        name_set: bool = False,
        avatar_set: bool = False,
        revision: int = 0,
        encrypted: bool = False,
        relay_user_id: UserID | None = None,
        expiration_time: int | None = None,
    ) -> None:
        super().__init__(
            chat_id,
            receiver,
            mxid,
            name,
            avatar_hash,
            avatar_url,
            name_set,
            avatar_set,
            revision,
            encrypted,
            relay_user_id,
            expiration_time,
        )
        self._create_room_lock = asyncio.Lock()
        self.log = self.log.getChild(self.chat_id_str)
        self._main_intent = None
        self._msgts_dedup = deque(maxlen=100)
        self._reaction_dedup = deque(maxlen=100)
        self._last_participant_update = set()
        self._reaction_lock = asyncio.Lock()
        self._pending_members = None
        self._relay_user = None
        self._expiration_lock = asyncio.Lock()

    @property
    def main_intent(self) -> IntentAPI:
        if not self._main_intent:
            raise ValueError("Portal must be postinit()ed before main_intent can be used")
        return self._main_intent

    @property
    def is_direct(self) -> bool:
        return isinstance(self.chat_id, Address)

    def handle_uuid_receive(self, uuid: UUID) -> None:
        if not self.is_direct or self.chat_id.uuid:
            raise ValueError(
                "handle_uuid_receive can only be used for private chat portals with a phone "
                "number chat_id"
            )
        del self.by_chat_id[(self.chat_id_str, self.receiver)]
        self.chat_id = Address(uuid=uuid)
        self.by_chat_id[(self.chat_id_str, self.receiver)] = self

    @classmethod
    def init_cls(cls, bridge: "SignalBridge") -> None:
        cls.config = bridge.config
        cls.matrix = bridge.matrix
        cls.signal = bridge.signal
        cls.az = bridge.az
        cls.loop = bridge.loop
        BasePortal.bridge = bridge
        cls.private_chat_portal_meta = cls.config["bridge.private_chat_portal_meta"]

    @classmethod
    async def start_disappearing_message_expirations(cls):
        await asyncio.gather(
            *(
                cls._expire_event(dm.room_id, dm.mxid, restart=True)
                for dm in await DisappearingMessage.get_all_scheduled()
                if dm.expiration_ts
            )
        )

    # region Misc

    async def _send_delivery_receipt(self, event_id: EventID) -> None:
        if event_id and self.config["bridge.delivery_receipts"]:
            try:
                await self.az.intent.mark_read(self.mxid, event_id)
            except Exception:
                self.log.exception("Failed to send delivery receipt for %s", event_id)

    async def _upsert_reaction(
        self,
        existing: DBReaction,
        intent: IntentAPI,
        mxid: EventID,
        sender: p.Puppet | u.User,
        message: DBMessage,
        emoji: str,
    ) -> None:
        if existing:
            self.log.debug(
                f"_upsert_reaction redacting {existing.mxid} and inserting {mxid}"
                f" (message: {message.mxid})"
            )
            try:
                await intent.redact(existing.mx_room, existing.mxid)
            except MForbidden:
                self.log.debug("Unexpected MForbidden redacting reaction", exc_info=True)
            await existing.edit(emoji=emoji, mxid=mxid, mx_room=message.mx_room)
        else:
            self.log.debug(f"_upsert_reaction inserting {mxid} (message: {message.mxid})")
            await DBReaction(
                mxid=mxid,
                mx_room=message.mx_room,
                emoji=emoji,
                signal_chat_id=self.chat_id,
                signal_receiver=self.receiver,
                msg_author=message.sender,
                msg_timestamp=message.timestamp,
                author=sender.address,
            ).insert()

    # endregion
    # region Matrix event handling

    @staticmethod
    async def _make_attachment(message: MediaMessageEventContent, path: str) -> Attachment:
        outgoing_filename = path
        if message.msgtype == MessageType.AUDIO:
            outgoing_filename = await ffmpeg.convert_path(
                path, ".m4a", output_args=("-c:a", "aac"), remove_input=True
            )
            message.info.mimetype = "audio/mp4"
        attachment = Attachment(
            custom_filename=message.body,
            content_type=message.info.mimetype,
            outgoing_filename=str(outgoing_filename),
        )
        info = message.info
        attachment.width = info.get("w", info.get("width", 0))
        attachment.height = info.get("h", info.get("height", 0))
        attachment.voice_note = message.msgtype == MessageType.AUDIO
        return attachment

    def _write_outgoing_file(self, data: bytes) -> str:
        dir = pathlib.Path(self.config["signal.outgoing_attachment_dir"])
        path = dir.joinpath(f"mautrix-signal-{str(uuid4())}")
        try:
            with open(path, "wb") as file:
                file.write(data)
        except FileNotFoundError:
            dir.mkdir(mode=0o755, parents=True, exist_ok=True)
            with open(path, "wb") as file:
                file.write(data)
        return str(path)

    async def _download_matrix_media(self, message: MediaMessageEventContent) -> str:
        if message.file:
            data = await self.main_intent.download_media(message.file.url)
            data = decrypt_attachment(
                data, message.file.key.key, message.file.hashes.get("sha256"), message.file.iv
            )
        else:
            data = await self.main_intent.download_media(message.url)
        return self._write_outgoing_file(data)

    async def handle_matrix_message(
        self, sender: u.User, message: MessageEventContent, event_id: EventID
    ) -> None:
        try:
            await self._handle_matrix_message(sender, message, event_id)
        except Exception as e:
            self.log.exception(f"Failed to handle Matrix message {event_id}")
            sender.send_remote_checkpoint(
                MessageSendCheckpointStatus.PERM_FAILURE,
                event_id,
                self.mxid,
                EventType.ROOM_MESSAGE,
                message.msgtype,
                error=e,
            )
            auth_failed = (
                "org.whispersystems.signalservice.api.push.exceptions.AuthorizationFailedException"
            )
            if isinstance(e, ResponseError) and auth_failed in e.data.get("exceptions", []):
                await sender.push_bridge_state(BridgeStateEvent.BAD_CREDENTIALS, error=str(e))
            await self._send_message(
                self.main_intent,
                TextMessageEventContent(
                    msgtype=MessageType.NOTICE, body=f"\u26a0 Your message was not bridged: {e}"
                ),
            )

    async def _handle_matrix_message(
        self, sender: u.User, message: MessageEventContent, event_id: EventID
    ) -> None:
        orig_sender = sender
        sender, is_relay = await self.get_relay_sender(sender, f"message {event_id}")
        if not sender:
            orig_sender.send_remote_checkpoint(
                status=MessageSendCheckpointStatus.PERM_FAILURE,
                event_id=event_id,
                room_id=self.mxid,
                event_type=EventType.ROOM_MESSAGE,
                message_type=message.msgtype,
                error="user is not logged in",
            )
            return
        elif is_relay:
            await self.apply_relay_message_format(orig_sender, message)

        request_id = int(time.time() * 1000)
        self._msgts_dedup.appendleft((sender.address, request_id))

        quote = None
        if message.get_reply_to():
            reply = await DBMessage.get_by_mxid(message.get_reply_to(), self.mxid)
            # TODO include actual text? either store in db or fetch event from homeserver
            if reply is not None:
                quote = Quote(id=reply.timestamp, author=reply.sender, text="")
                # TODO only send this when it's actually a reply to an attachment?
                #      Neither Signal Android nor iOS seem to care though, so this works too
                quote.attachments = [QuotedAttachment("", "")]

        attachments: list[Attachment] | None = None
        attachment_path: str | None = None
        mentions: list[Mention] | None = None
        if message.msgtype.is_text:
            text, mentions = await matrix_to_signal(message)
        elif message.msgtype.is_media:
            attachment_path = await self._download_matrix_media(message)
            attachment = await self._make_attachment(message, attachment_path)
            attachments = [attachment]
            text = message.body if is_relay else None
            self.log.trace("Formed outgoing attachment %s", attachment)
        else:
            self.log.debug(f"Unknown msgtype {message.msgtype} in Matrix message {event_id}")
            return

        self.log.debug(f"Sending Matrix message {event_id} to Signal with timestamp {request_id}")
        try:
            retry_count = await self._signal_send_with_retries(
                sender,
                message,
                event_id,
                username=sender.username,
                recipient=self.chat_id,
                body=text,
                mentions=mentions,
                quote=quote,
                attachments=attachments,
                timestamp=request_id,
            )
        except Exception:
            self.log.exception("Sending message failed")
            raise
        else:
            sender.send_remote_checkpoint(
                MessageSendCheckpointStatus.SUCCESS,
                event_id,
                self.mxid,
                EventType.ROOM_MESSAGE,
                message.msgtype,
                retry_num=retry_count,
            )
            await self._send_delivery_receipt(event_id)

            msg = DBMessage(
                mxid=event_id,
                mx_room=self.mxid,
                sender=sender.address,
                timestamp=request_id,
                signal_chat_id=self.chat_id,
                signal_receiver=self.receiver,
            )
            await msg.insert()
            self.log.debug(f"Handled Matrix message {event_id} -> {request_id}")
            if attachment_path and self.config["signal.remove_file_after_handling"]:
                try:
                    os.remove(attachment_path)
                except FileNotFoundError:
                    pass

            # Handle disappearing messages
            if self.expiration_time and (
                self.is_direct or self.config["signal.enable_disappearing_messages_in_groups"]
            ):
                dm = DisappearingMessage(self.mxid, event_id, self.expiration_time)
                await dm.insert()
                await Portal._expire_event(dm.room_id, dm.mxid)

    async def _signal_send_with_retries(
        self, sender: u.User, message: MessageEventContent, event_id: EventID, **send_args
    ) -> int:
        retry_count = 7
        retry_message_event_id = None
        for retry_num in range(retry_count):
            try:
                self.log.info(f"Send attempt {retry_num}")
                await self.signal.send(**send_args)

                # It was successful.
                if retry_message_event_id is not None:
                    await self.main_intent.redact(self.mxid, retry_message_event_id)
                return retry_num
            except NotConnected as e:
                # Only handle NotConnected exceptions so that other exceptions actually continue to
                # error.
                sleep_seconds = (retry_num + 1) ** 2
                msg = f"Not connected to signald. Going to sleep for {sleep_seconds}s. Error: {e}"
                self.log.exception(msg)
                sender.send_remote_checkpoint(
                    MessageSendCheckpointStatus.WILL_RETRY,
                    event_id,
                    self.mxid,
                    EventType.ROOM_MESSAGE,
                    message.msgtype,
                    error=msg,
                    retry_num=retry_num,
                )

                if retry_num > 2:
                    # User has waited > ~15 seconds, send a notice that we are retrying.
                    event_content = TextMessageEventContent(
                        MessageType.NOTICE,
                        f"There was an error connecting to signald. Waiting for {sleep_seconds} "
                        "before retrying.",
                    )
                    if retry_message_event_id is not None:
                        event_content.set_edit(retry_message_event_id)
                    new_event_id = await self.main_intent.send_message(self.mxid, event_content)
                    retry_message_event_id = retry_message_event_id or new_event_id

                await asyncio.sleep(sleep_seconds)

        if retry_message_event_id is not None:
            await self.main_intent.redact(self.mxid, retry_message_event_id)
        raise NotConnected(f"Connection to signald still did not work after {retry_count} retries")

    async def handle_matrix_reaction(
        self, sender: u.User, event_id: EventID, reacting_to: EventID, emoji: str
    ) -> None:
        if not await sender.is_logged_in():
            self.log.trace(f"Ignoring reaction by non-logged-in user {sender.mxid}")
            return

        # Signal doesn't seem to use variation selectors at all
        emoji = variation_selector.remove(emoji)

        message = await DBMessage.get_by_mxid(reacting_to, self.mxid)
        if not message:
            self.log.debug(f"Ignoring reaction to unknown event {reacting_to}")
            return

        existing = await DBReaction.get_by_signal_id(
            self.chat_id, self.receiver, message.sender, message.timestamp, sender.address
        )
        if existing and existing.emoji == emoji:
            return

        dedup_id = (message.sender, message.timestamp, emoji, sender.address)
        self._reaction_dedup.appendleft(dedup_id)
        async with self._reaction_lock:
            reaction = Reaction(
                emoji=emoji,
                remove=False,
                target_author=message.sender,
                target_sent_timestamp=message.timestamp,
            )
            try:
                await self.signal.react(
                    username=sender.username, recipient=self.chat_id, reaction=reaction
                )
            except Exception as e:
                sender.send_remote_checkpoint(
                    MessageSendCheckpointStatus.PERM_FAILURE,
                    event_id,
                    self.mxid,
                    EventType.REACTION,
                    error=e,
                )
            else:
                self.log.trace(f"{sender.mxid} reacted to {message.timestamp} with {emoji}")
                sender.send_remote_checkpoint(
                    MessageSendCheckpointStatus.SUCCESS,
                    event_id,
                    self.mxid,
                    EventType.REACTION,
                )
                await self._upsert_reaction(
                    existing, self.main_intent, event_id, sender, message, emoji
                )
                await self._send_delivery_receipt(event_id)

    async def handle_matrix_redaction(
        self, sender: u.User, event_id: EventID, redaction_event_id: EventID
    ) -> None:
        if not await sender.is_logged_in():
            return

        message = await DBMessage.get_by_mxid(event_id, self.mxid)
        if message:
            try:
                await message.delete()
                await self.signal.remote_delete(
                    sender.username, recipient=self.chat_id, timestamp=message.timestamp
                )
            except Exception as e:
                self.log.exception("Removing message failed")
                sender.send_remote_checkpoint(
                    MessageSendCheckpointStatus.PERM_FAILURE,
                    redaction_event_id,
                    self.mxid,
                    EventType.ROOM_REDACTION,
                    error=e,
                )
            else:
                self.log.trace(f"Removed {message} after Matrix redaction")
                sender.send_remote_checkpoint(
                    MessageSendCheckpointStatus.SUCCESS,
                    redaction_event_id,
                    self.mxid,
                    EventType.ROOM_REDACTION,
                )
                await self._send_delivery_receipt(redaction_event_id)
            return

        reaction = await DBReaction.get_by_mxid(event_id, self.mxid)
        if reaction:
            try:
                await reaction.delete()
                remove_reaction = Reaction(
                    emoji=reaction.emoji,
                    remove=True,
                    target_author=reaction.msg_author,
                    target_sent_timestamp=reaction.msg_timestamp,
                )
                await self.signal.react(
                    username=sender.username, recipient=self.chat_id, reaction=remove_reaction
                )
            except Exception as e:
                self.log.exception("Removing reaction failed")
                sender.send_remote_checkpoint(
                    MessageSendCheckpointStatus.PERM_FAILURE,
                    redaction_event_id,
                    self.mxid,
                    EventType.ROOM_REDACTION,
                    error=e,
                )
            else:
                self.log.trace(f"Removed {reaction} after Matrix redaction")
                sender.send_remote_checkpoint(
                    MessageSendCheckpointStatus.SUCCESS,
                    redaction_event_id,
                    self.mxid,
                    EventType.ROOM_REDACTION,
                )
                await self._send_delivery_receipt(redaction_event_id)
            return

        sender.send_remote_checkpoint(
            MessageSendCheckpointStatus.PERM_FAILURE,
            redaction_event_id,
            self.mxid,
            EventType.ROOM_REDACTION,
            error=f"No message or reaction found for redaction",
        )

    async def handle_matrix_join(self, user: u.User) -> None:
        if self.is_direct or not await user.is_logged_in():
            return
        if self._pending_members is None:
            self.log.debug(
                f"{user.mxid} ({user.uuid}) joined room, but pending_members is None,"
                " updating chat info"
            )
            await self.update_info(user, GroupV2ID(id=self.chat_id))
        if self._pending_members is None:
            self.log.warning(
                f"Didn't get pending member list after info update, {user.mxid} ({user.uuid}) may"
                "not be in the group on Signal."
            )
        elif user.uuid in self._pending_members:
            self.log.debug(f"{user.mxid} ({user.uuid}) joined room, accepting invite on Signal")
            try:
                resp = await self.signal.accept_invitation(user.username, self.chat_id)
                self._pending_members.remove(user.uuid)
            except RPCError as e:
                await self.main_intent.send_notice(
                    self.mxid, f"\u26a0 Failed to accept invite on Signal: {e}"
                )
            else:
                await self.update_info(user, resp)

    async def handle_matrix_leave(self, user: u.User) -> None:
        if not await user.is_logged_in():
            return
        if self.is_direct:
            self.log.info(f"{user.mxid} left private chat portal with {self.chat_id}")
            if user.username == self.receiver:
                self.log.info(
                    f"{user.mxid} was the recipient of this portal. Cleaning up and deleting..."
                )
                await self.cleanup_and_delete()
        else:
            self.log.debug(f"{user.mxid} left portal to {self.chat_id}")
            # TODO cleanup if empty

    async def handle_matrix_name(self, user: u.User, name: str) -> None:
        if self.name == name or self.is_direct or not name:
            return
        sender, is_relay = await self.get_relay_sender(user, "name change")
        if not sender:
            return
        self.name = name
        self.log.debug(
            f"{user.mxid} changed the group name, sending to Signal through {sender.username}"
        )
        try:
            await self.signal.update_group(sender.username, self.chat_id, title=name)
        except Exception:
            self.log.exception("Failed to update Signal group name")
            self.name = None

    async def handle_matrix_avatar(self, user: u.User, url: ContentURI) -> None:
        if self.is_direct or not url:
            return
        sender, is_relay = await self.get_relay_sender(user, "avatar change")
        if not sender:
            return

        data = await self.main_intent.download_media(url)
        new_hash = hashlib.sha256(data).hexdigest()
        if new_hash == self.avatar_hash and self.avatar_set:
            self.log.debug(f"New avatar from Matrix set by {user.mxid} is same as current one")
            return
        self.avatar_url = url
        self.avatar_hash = new_hash
        path = self._write_outgoing_file(data)
        self.log.debug(
            f"{user.mxid} changed the group avatar, sending to Signal through {sender.username}"
        )
        try:
            await self.signal.update_group(sender.username, self.chat_id, avatar_path=path)
            self.avatar_set = True
        except Exception:
            self.log.exception("Failed to update Signal group avatar")
            self.avatar_set = False
        if self.config["signal.remove_file_after_handling"]:
            try:
                os.remove(path)
            except FileNotFoundError:
                pass

    @classmethod
    async def _expire_event(cls, room_id: RoomID, event_id: EventID, restart: bool = False):
        """
        Schedule a task to expire a an event. This should only be called once the message has been
        read, as the timer for redaction will start immediately, and there is no (supported)
        mechanism to stop the countdown, even after bridge restart.

        If there is already an expiration event for the given ``room_id`` and ``event_id``, it will
        not schedule a new task.
        """
        portal = await cls.get_by_mxid(room_id)
        if not portal:
            raise AttributeError(f"No portal found for {room_id}")

        # Need a lock around this critical section to make sure that we know if a task has been
        # created for this particular (room_id, event_id) combination.
        async with portal._expiration_lock:
            if (
                not portal.is_direct
                and not cls.config["signal.enable_disappearing_messages_in_groups"]
            ):
                portal.log.debug(
                    "Not expiring event in group message since "
                    "signal.enable_disappearing_messages_in_groups is not enabled."
                )
                await DisappearingMessage.delete(room_id, event_id)
                return

            disappearing_message = await DisappearingMessage.get(room_id, event_id)
            if disappearing_message is None:
                return
            wait = disappearing_message.expiration_seconds
            now = time.time()
            # If there is an expiration_ts, then there's already a task going, or it's a restart.
            # If it's a restart, then restart the countdown. This is fairly likely to occur if the
            # disappearance timeout is weeks.
            if disappearing_message.expiration_ts:
                if not restart:
                    portal.log.debug(f"Expiration task already exists for {event_id} in {room_id}")
                    return
                portal.log.debug(f"Resuming expiration for {event_id} in {room_id}")
                wait = (disappearing_message.expiration_ts / 1000) - now
            if wait < 0:
                wait = 0

            # Spawn the actual expiration task.
            asyncio.create_task(cls._expire_event_task(portal, event_id, wait))

            # Set the expiration_ts only after we have actually created the expiration task.
            if not disappearing_message.expiration_ts:
                await disappearing_message.set_expiration_ts(int((now + wait) * 1000))

    @classmethod
    async def _expire_event_task(cls, portal: Portal, event_id: EventID, wait: float):
        portal.log.debug(f"Redacting {event_id} in {wait} seconds")
        await asyncio.sleep(wait)

        async with portal._expiration_lock:
            if not await DisappearingMessage.get(portal.mxid, event_id):
                portal.log.debug(
                    f"{event_id} no longer in disappearing messages list, not redacting"
                )
                return

            portal.log.debug(f"Redacting {event_id} because it was expired")
            try:
                await portal.main_intent.redact(portal.mxid, event_id)
                portal.log.debug(f"Redacted {event_id} successfully")
            except Exception as e:
                portal.log.warning(f"Redacting expired event {event_id} failed", e)
            finally:
                await DisappearingMessage.delete(portal.mxid, event_id)

    async def handle_read_receipt(self, event_id: EventID, data: SingleReceiptEventContent):
        # Start the redaction timers for all the disappearing messages in the room when the user
        # reads the room. This is the behavior of the Signal clients.
        await asyncio.gather(
            *(
                Portal._expire_event(dm.room_id, dm.mxid)
                for dm in await DisappearingMessage.get_unscheduled_for_room(self.mxid)
            )
        )

    # endregion
    # region Signal event handling

    @staticmethod
    async def _resolve_address(address: Address) -> Address:
        puppet = await p.Puppet.get_by_address(address, create=False)
        return puppet.address

    async def _find_quote_event_id(self, quote: Quote | None) -> MessageEvent | EventID | None:
        if not quote:
            return None

        author_address = await self._resolve_address(quote.author)
        reply_msg = await DBMessage.get_by_signal_id(
            author_address, quote.id, self.chat_id, self.receiver
        )
        if not reply_msg:
            return None
        try:
            evt = await self.main_intent.get_event(self.mxid, reply_msg.mxid)
            if isinstance(evt, EncryptedEvent):
                return await self.matrix.e2ee.decrypt(evt, wait_session_timeout=0)
            return evt
        except MatrixError:
            return reply_msg.mxid

    async def handle_signal_message(
        self, source: u.User, sender: p.Puppet, message: MessageData
    ) -> None:
        if (sender.address, message.timestamp) in self._msgts_dedup:
            self.log.debug(
                f"Ignoring message {message.timestamp} by {sender.uuid} as it was already handled "
                "(message.timestamp in dedup queue)"
            )
            await self.signal.send_receipt(
                source.username, sender.address, timestamps=[message.timestamp]
            )
            return
        old_message = await DBMessage.get_by_signal_id(
            sender.address, message.timestamp, self.chat_id, self.receiver
        )
        if old_message is not None:
            self.log.debug(
                f"Ignoring message {message.timestamp} by {sender.uuid} as it was already handled "
                "(message.id found in database)"
            )
            await self.signal.send_receipt(
                source.username, sender.address, timestamps=[message.timestamp]
            )
            return
        self.log.debug(f"Started handling message {message.timestamp} by {sender.uuid}")
        self.log.trace(f"Message content: {message}")
        self._msgts_dedup.appendleft((sender.address, message.timestamp))
        intent = sender.intent_for(self)
        await intent.set_typing(self.mxid, False)
        event_id = None
        reply_to = await self._find_quote_event_id(message.quote)

        if message.sticker:
            if message.sticker.attachment.incoming_filename:
                content = await self._handle_signal_attachment(
                    intent, message.sticker.attachment, sticker=True
                )
            elif StickersClient:
                content = await self._handle_signal_sticker(intent, message.sticker)
            else:
                self.log.debug(
                    f"Not handling sticker in {message.timestamp}: no incoming_filename and "
                    "signalstickers-client not installed."
                )
                return

            if content:
                if message.sticker.attachment.blurhash:
                    content.info["blurhash"] = message.sticker.attachment.blurhash
                    content.info["xyz.amorgan.blurhash"] = message.sticker.attachment.blurhash
                await self._add_sticker_meta(message.sticker, content)
                if reply_to and not message.body:
                    content.set_reply(reply_to)
                    reply_to = None
                event_id = await self._send_message(
                    intent, content, timestamp=message.timestamp, event_type=EventType.STICKER
                )

        for contact in message.contacts:
            content = await self._handle_signal_contact(contact)
            if reply_to and not message.body:
                content.set_reply(reply_to)
                reply_to = None
            event_id = await self._send_message(intent, content, timestamp=message.timestamp)

        is_first_text = True
        for attachment in message.attachments:
            if not attachment.incoming_filename:
                self.log.warning(
                    "Failed to bridge attachment, no incoming filename: %s", attachment
                )
                continue
            as_text = (
                is_first_text
                and attachment.content_type == "text/x-signal-plain"
                and attachment.size < MAX_MATRIX_MESSAGE_SIZE
            )
            content = await self._handle_signal_attachment(intent, attachment, text=as_text)
            if as_text:
                is_first_text = False
                message.body = ""
            if reply_to and not message.body:
                # If there's no text, set the first image as the reply
                content.set_reply(reply_to)
                reply_to = None
            event_id = await self._send_message(intent, content, timestamp=message.timestamp)

        if message.body:
            content = await signal_to_matrix(message)
            if reply_to:
                content.set_reply(reply_to)
            event_id = await self._send_message(intent, content, timestamp=message.timestamp)

        if event_id:
            msg = DBMessage(
                mxid=event_id,
                mx_room=self.mxid,
                sender=sender.address,
                timestamp=message.timestamp,
                signal_chat_id=self.chat_id,
                signal_receiver=self.receiver,
            )
            await msg.insert()
            await self.signal.send_receipt(
                source.username, sender.address, timestamps=[message.timestamp]
            )
            await self._send_delivery_receipt(event_id)
            self.log.debug(f"Handled Signal message {message.timestamp} -> {event_id}")

            if message.expires_in_seconds and (
                self.is_direct or self.config["signal.enable_disappearing_messages_in_groups"]
            ):
                disappearing_message = DisappearingMessage(
                    self.mxid, event_id, message.expires_in_seconds
                )
                await disappearing_message.insert()
                self.log.debug(
                    f"{event_id} set to be redacted {message.expires_in_seconds} seconds after "
                    "room is read"
                )
        else:
            self.log.debug(f"Didn't get event ID for {message.timestamp}")

    @staticmethod
    async def _make_media_content(
        attachment: Attachment, data: bytes
    ) -> tuple[MediaMessageEventContent, bytes]:
        if attachment.content_type.startswith("image/"):
            msgtype = MessageType.IMAGE
            info = ImageInfo(
                mimetype=attachment.content_type, width=attachment.width, height=attachment.height
            )
        elif attachment.content_type.startswith("video/"):
            msgtype = MessageType.VIDEO
            info = VideoInfo(
                mimetype=attachment.content_type, width=attachment.width, height=attachment.height
            )
        elif attachment.voice_note or attachment.content_type.startswith("audio/"):
            msgtype = MessageType.AUDIO
            info = AudioInfo(
                mimetype=attachment.content_type if not attachment.voice_note else "audio/ogg"
            )
        else:
            msgtype = MessageType.FILE
            info = FileInfo(mimetype=attachment.content_type)
        if not attachment.custom_filename:
            ext = mimetypes.guess_extension(info.mimetype) or ""
            attachment.custom_filename = attachment.id + ext
        else:
            for ext in mimetypes.guess_all_extensions(info.mimetype):
                if attachment.custom_filename.endswith(ext):
                    break
            else:
                attachment.custom_filename += mimetypes.guess_extension(info.mimetype) or ""
        if attachment.blurhash:
            info["blurhash"] = attachment.blurhash
            info["xyz.amorgan.blurhash"] = attachment.blurhash
        content = MediaMessageEventContent(
            msgtype=msgtype, info=info, body=attachment.custom_filename
        )

        # If this is a voice note, add the additional voice message metadata and convert to OGG.
        if attachment.voice_note:
            content["org.matrix.msc1767.file"] = {
                "url": content.url,
                "name": content.body,
                **(content.file.serialize() if content.file else {}),
                **(content.info.serialize() if content.info else {}),
            }
            content["org.matrix.msc3245.voice"] = {}
            data = await ffmpeg.convert_bytes(
                data, ".ogg", output_args=("-c:a", "libopus"), input_mime=attachment.content_type
            )

        return content, data

    async def _handle_signal_attachment(
        self, intent: IntentAPI, attachment: Attachment, sticker: bool = False, text: bool = False
    ) -> MediaMessageEventContent | TextMessageEventContent:
        self.log.trace(f"Reuploading attachment {attachment}")
        if not attachment.content_type:
            attachment.content_type = (
                magic.mimetype(attachment.incoming_filename)
                if magic is not None
                else "application/octet-stream"
            )

        with open(attachment.incoming_filename, "rb") as file:
            data = file.read()
        if self.config["signal.remove_file_after_handling"]:
            os.remove(attachment.incoming_filename)

        if text:
            assert attachment.content_type == "text/x-signal-plain"
            assert attachment.size < MAX_MATRIX_MESSAGE_SIZE
            content = TextMessageEventContent(msgtype=MessageType.TEXT, body=data.decode("utf-8"))
            return content

        content, data = await self._make_media_content(attachment, data)
        if sticker:
            self._adjust_sticker_size(content.info)

        await self._upload_attachment(intent, content, data, attachment.id)
        return content

    @staticmethod
    async def _handle_signal_contact(contact: SharedContact) -> TextMessageEventContent:
        msg = f"Shared contact: {contact.name!s}"
        if contact.phone:
            msg += "\n"
            for phone in contact.phone:
                msg += f"\nPhone: {phone.value} ({phone.type_or_label})"
        if contact.email:
            msg += "\n"
            for email in contact.email:
                msg += f"\nEmail: {email.value} ({email.type_or_label})"
        content = TextMessageEventContent(msgtype=MessageType.TEXT, body=msg)
        content["fi.mau.signal.contact"] = contact.serialize()
        return content

    async def _add_sticker_meta(self, sticker: Sticker, content: MediaMessageEventContent) -> None:
        try:
            pack = self._sticker_meta_cache[sticker.pack_id]
        except KeyError:
            self.log.debug(f"Fetching sticker pack metadata for {sticker.pack_id}")
            try:
                async with StickersClient() as client:
                    pack = await client.get_pack_metadata(sticker.pack_id, sticker.pack_key)
                self._sticker_meta_cache[sticker.pack_id] = pack
            except Exception:
                self.log.warning(
                    f"Failed to fetch pack metadata for {sticker.pack_id}", exc_info=True
                )
                pack = None
        if not pack:
            content.info["fi.mau.signal.sticker"] = {
                "id": sticker.sticker_id,
                "pack": {
                    "id": sticker.pack_id,
                    "key": sticker.pack_key,
                },
            }
            return
        sticker_meta = pack.stickers[sticker.sticker_id]
        content.body = sticker_meta.emoji
        content.info["fi.mau.signal.sticker"] = {
            "id": sticker.sticker_id,
            "emoji": sticker_meta.emoji,
            "pack": {
                "id": pack.id,
                "key": pack.key,
                "title": pack.title,
                "author": pack.author,
            },
        }

    @staticmethod
    def _adjust_sticker_size(info: ImageInfo) -> None:
        if info.width > 256 or info.height > 256:
            if info.width == info.height:
                info.width = info.height = 256
            elif info.width > info.height:
                info.height = int(info.height / (info.width / 256))
                info.width = 256
            else:
                info.width = int(info.width / (info.height / 256))
                info.height = 256

    async def _handle_signal_sticker(
        self, intent: IntentAPI, sticker: Sticker
    ) -> MediaMessageEventContent | None:
        try:
            self.log.debug(f"Fetching sticker {sticker.pack_id}#{sticker.sticker_id}")
            async with StickersClient() as client:
                data = await client.download_sticker(
                    sticker.sticker_id, sticker.pack_id, sticker.pack_key
                )
        except Exception:
            self.log.warning(f"Failed to download sticker {sticker.sticker_id}", exc_info=True)
            return None
        info = ImageInfo(
            mimetype=sticker.attachment.content_type,
            size=len(data),
            width=sticker.attachment.width,
            height=sticker.attachment.height,
        )
        self._adjust_sticker_size(info)
        if magic:
            info.mimetype = magic.mimetype(data)
        ext = mimetypes.guess_extension(info.mimetype)
        if not ext and info.mimetype == "image/webp":
            ext = ".webp"
        content = MediaMessageEventContent(
            msgtype=MessageType.IMAGE, info=info, body=f"sticker{ext}"
        )
        await self._upload_attachment(intent, content, data, sticker.attachment.id)
        return content

    async def _upload_attachment(
        self, intent: IntentAPI, content: MediaMessageEventContent, data: bytes, id: str
    ) -> None:
        upload_mime_type = content.info.mimetype
        if self.encrypted and encrypt_attachment:
            data, content.file = encrypt_attachment(data)
            upload_mime_type = "application/octet-stream"

        content.url = await intent.upload_media(data, mime_type=upload_mime_type, filename=id)
        if content.file:
            content.file.url = content.url
            content.url = None
        # This is a hack for bad clients like Element iOS that require a thumbnail
        if content.info.mimetype.startswith("image/"):
            if content.file:
                content.info.thumbnail_file = content.file
            elif content.url:
                content.info.thumbnail_url = content.url

    async def handle_signal_reaction(
        self, sender: p.Puppet, reaction: Reaction, timestamp: int
    ) -> None:
        author_address = await self._resolve_address(reaction.target_author)
        target_id = reaction.target_sent_timestamp
        async with self._reaction_lock:
            dedup_id = (author_address, target_id, reaction.emoji, sender.address)
            if dedup_id in self._reaction_dedup:
                return
            self._reaction_dedup.appendleft(dedup_id)

        existing = await DBReaction.get_by_signal_id(
            self.chat_id, self.receiver, author_address, target_id, sender.address
        )

        if reaction.remove:
            if existing:
                try:
                    await sender.intent_for(self).redact(existing.mx_room, existing.mxid)
                except IntentError:
                    await self.main_intent.redact(existing.mx_room, existing.mxid)
                await existing.delete()
                self.log.trace(f"Removed {existing} after Signal removal")
            return
        elif existing and existing.emoji == reaction.emoji:
            return

        message = await DBMessage.get_by_signal_id(
            author_address, target_id, self.chat_id, self.receiver
        )
        if not message:
            self.log.debug(f"Ignoring reaction to unknown message {target_id}")
            return

        intent = sender.intent_for(self)
        matrix_emoji = variation_selector.add(reaction.emoji)
        mxid = await intent.react(message.mx_room, message.mxid, matrix_emoji, timestamp=timestamp)
        self.log.debug(f"{sender.address} reacted to {message.mxid} -> {mxid}")
        await self._upsert_reaction(existing, intent, mxid, sender, message, reaction.emoji)

    async def handle_signal_delete(self, sender: p.Puppet, message_ts: int) -> None:
        message = await DBMessage.get_by_signal_id(
            sender.address, message_ts, self.chat_id, self.receiver
        )
        if not message:
            return
        await message.delete()
        try:
            await sender.intent_for(self).redact(message.mx_room, message.mxid)
        except MForbidden:
            await self.main_intent.redact(message.mx_room, message.mxid)

    # endregion
    # region Updating portal info

    async def update_info(
        self, source: u.User, info: ChatInfo, sender: p.Puppet | None = None
    ) -> None:
        if self.is_direct:
            if not isinstance(info, (Contact, Profile, Address)):
                raise ValueError(f"Unexpected type for direct chat update_info: {type(info)}")
            if not self.name:
                puppet = await p.Puppet.get_by_address(self.chat_id)
                if not puppet.name:
                    await puppet.update_info(info)
                self.name = puppet.name
            return

        if isinstance(info, GroupV2ID):
            info = await self.signal.get_group(source.username, info.id, info.revision or -1)
            if not info:
                self.log.debug(
                    f"Failed to get full group v2 info through {source.username}, "
                    "cancelling update"
                )
                return

        changed = False
        if isinstance(info, Group):
            changed = await self._update_name(info.name, sender) or changed
        elif isinstance(info, GroupV2):
            if self.revision < info.revision:
                self.revision = info.revision
                changed = True
            elif self.revision > info.revision:
                self.log.warning(
                    f"Got outdated info when syncing through {source.username} "
                    f"({info.revision} < {self.revision}), ignoring..."
                )
                return
            changed = await self._update_name(info.title, sender) or changed
        elif isinstance(info, GroupV2ID):
            return
        else:
            raise ValueError(f"Unexpected type for group update_info: {type(info)}")
        changed = await self._update_avatar(info, sender) or changed
        await self._update_participants(source, info)
        try:
            await self._update_power_levels(info)
        except Exception:
            self.log.warning("Error updating power levels", exc_info=True)
        if changed:
            await self.update_bridge_info()
            await self.update()

    async def update_expires_in_seconds(self, sender: p.Puppet, expires_in_seconds: int) -> None:
        if expires_in_seconds == 0:
            expires_in_seconds = None
        if self.expiration_time == expires_in_seconds:
            return

        assert self.mxid
        self.expiration_time = expires_in_seconds
        await self.update()

        time_str = "Off" if expires_in_seconds is None else format_duration(expires_in_seconds)
        body = f"Set the disappearing message timer to {time_str}"
        content = TextMessageEventContent(msgtype=MessageType.NOTICE, body=body)
        await self._send_message(sender.intent_for(self), content)

    async def update_puppet_avatar(self, new_hash: str, avatar_url: ContentURI) -> None:
        if not self.encrypted and not self.private_chat_portal_meta:
            return

        if self.avatar_hash != new_hash or not self.avatar_set:
            self.avatar_hash = new_hash
            self.avatar_url = avatar_url
            if self.mxid:
                try:
                    await self.main_intent.set_room_avatar(self.mxid, avatar_url)
                    self.avatar_set = True
                except Exception:
                    self.log.exception("Error setting avatar")
                    self.avatar_set = False
                await self.update_bridge_info()
                await self.update()

    async def update_puppet_name(self, name: str) -> None:
        if not self.encrypted and not self.private_chat_portal_meta:
            return

        changed = await self._update_name(name)

        if changed:
            await self.update_bridge_info()
            await self.update()

    async def _update_name(self, name: str, sender: p.Puppet | None = None) -> bool:
        if self.name != name or not self.name_set:
            self.name = name
            if self.mxid:
                try:
                    await self._try_with_puppet(
                        lambda i: i.set_room_name(self.mxid, self.name), puppet=sender
                    )
                    self.name_set = True
                except Exception:
                    self.log.exception("Error setting name")
                    self.name_set = False
            return True
        return False

    async def _try_with_puppet(
        self, action: Callable[[IntentAPI], Awaitable[Any]], puppet: p.Puppet | None = None
    ) -> None:
        if puppet:
            try:
                await action(puppet.intent_for(self))
            except (MForbidden, IntentError):
                await action(self.main_intent)
        else:
            await action(self.main_intent)

    async def _update_avatar(self, info: ChatInfo, sender: p.Puppet | None = None) -> bool:
        path = None
        if isinstance(info, GroupV2):
            path = info.avatar
        elif isinstance(info, Group):
            path = f"group-{self.chat_id}"
        res = await p.Puppet.upload_avatar(self, path, self.main_intent)
        if res is False:
            return False
        self.avatar_hash, self.avatar_url = res
        if not self.mxid:
            return True

        try:
            await self._try_with_puppet(
                lambda i: i.set_room_avatar(self.mxid, self.avatar_url), puppet=sender
            )
            self.avatar_set = True
        except Exception:
            self.log.exception("Error setting avatar")
            self.avatar_set = False
        return True

    async def _update_participants(self, source: u.User, info: ChatInfo) -> None:
        if not self.mxid or not isinstance(info, (Group, GroupV2)):
            return

        pending_members = info.pending_members if isinstance(info, GroupV2) else []
        self._pending_members = {addr.uuid for addr in pending_members}

        for address in info.members:
            user = await u.User.get_by_address(address)
            if user:
                await self.main_intent.invite_user(self.mxid, user.mxid)

            puppet = await p.Puppet.get_by_address(address)
            await source.sync_contact(address)
            await puppet.intent_for(self).ensure_joined(self.mxid)

        for address in pending_members:
            user = await u.User.get_by_address(address)
            if user:
                await self.main_intent.invite_user(self.mxid, user.mxid)

            puppet = await p.Puppet.get_by_address(address)
            await source.sync_contact(address)
            await self.main_intent.invite_user(self.mxid, puppet.intent_for(self).mxid)

    async def _update_power_levels(self, info: ChatInfo) -> None:
        if not self.mxid:
            return

        power_levels = await self.main_intent.get_power_levels(self.mxid)
        power_levels = await self._get_power_levels(power_levels, info=info, is_initial=False)
        await self.main_intent.set_power_levels(self.mxid, power_levels)

    # endregion
    # region Bridge info state event

    @property
    def bridge_info_state_key(self) -> str:
        return f"net.maunium.signal://signal/{self.chat_id}"

    @property
    def bridge_info(self) -> dict[str, Any]:
        return {
            "bridgebot": self.az.bot_mxid,
            "creator": self.main_intent.mxid,
            "protocol": {
                "id": "signal",
                "displayname": "Signal",
                "avatar_url": self.config["appservice.bot_avatar"],
            },
            "channel": {
                "id": str(self.chat_id),
                "displayname": self.name,
                "avatar_url": self.avatar_url,
            },
        }

    async def update_bridge_info(self) -> None:
        if not self.mxid:
            self.log.debug("Not updating bridge info: no Matrix room created")
            return
        try:
            self.log.debug("Updating bridge info...")
            await self.main_intent.send_state_event(
                self.mxid, StateBridge, self.bridge_info, self.bridge_info_state_key
            )
            # TODO remove this once https://github.com/matrix-org/matrix-doc/pull/2346 is in spec
            await self.main_intent.send_state_event(
                self.mxid, StateHalfShotBridge, self.bridge_info, self.bridge_info_state_key
            )
        except Exception:
            self.log.warning("Failed to update bridge info", exc_info=True)

    # endregion
    # region Creating Matrix rooms

    async def update_matrix_room(self, source: u.User, info: ChatInfo) -> None:
        if not self.is_direct and not isinstance(info, (Group, GroupV2, GroupV2ID)):
            raise ValueError(f"Unexpected type for updating group portal: {type(info)}")
        elif self.is_direct and not isinstance(info, (Contact, Profile, Address)):
            raise ValueError(f"Unexpected type for updating direct chat portal: {type(info)}")
        try:
            await self._update_matrix_room(source, info)
        except Exception:
            self.log.exception("Failed to update portal")

    async def create_matrix_room(self, source: u.User, info: ChatInfo) -> RoomID | None:
        if not self.is_direct and not isinstance(info, (Group, GroupV2, GroupV2ID)):
            raise ValueError(f"Unexpected type for creating group portal: {type(info)}")
        elif self.is_direct and not isinstance(info, (Contact, Profile, Address)):
            raise ValueError(f"Unexpected type for creating direct chat portal: {type(info)}")
        if isinstance(info, Group) and not info.members:
            groups = await self.signal.list_groups(source.username)
            info = next(
                (g for g in groups if isinstance(g, Group) and g.group_id == info.group_id), info
            )
        elif isinstance(info, GroupV2ID) and not isinstance(info, GroupV2):
            self.log.debug(
                f"create_matrix_room() called with {info}, fetching full info from signald"
            )
            info = await self.signal.get_group(source.username, info.id, info.revision or -1)
            if not info:
                self.log.warning(f"Full info not found, canceling room creation")
                return None
            else:
                self.log.trace("get_group() returned full info: %s", info)
        if self.mxid:
            await self.update_matrix_room(source, info)
            return self.mxid
        async with self._create_room_lock:
            return await self._create_matrix_room(source, info)

    def _get_invite_content(self, double_puppet: p.Puppet | None) -> dict[str, Any]:
        invite_content = {}
        if double_puppet:
            invite_content["fi.mau.will_auto_accept"] = True
        if self.is_direct:
            invite_content["is_direct"] = True
        return invite_content

    async def _update_matrix_room(self, source: u.User, info: ChatInfo) -> None:
        puppet = await p.Puppet.get_by_custom_mxid(source.mxid)
        await self.main_intent.invite_user(
            self.mxid,
            source.mxid,
            check_cache=True,
            extra_content=self._get_invite_content(puppet),
        )
        if puppet:
            did_join = await puppet.intent.ensure_joined(self.mxid)
            if did_join and self.is_direct:
                await source.update_direct_chats({self.main_intent.mxid: [self.mxid]})

        await self.update_info(source, info)

    async def _get_power_levels(
        self,
        levels: PowerLevelStateEventContent | None = None,
        info: ChatInfo | None = None,
        is_initial: bool = False,
    ) -> PowerLevelStateEventContent:
        levels = levels or PowerLevelStateEventContent()
        if self.is_direct:
            levels.ban = 99
            levels.kick = 99
            levels.invite = 99
            levels.state_default = 0
            meta_edit_level = 0
        else:
            if isinstance(info, GroupV2):
                ac = info.access_control
                for detail in info.member_detail + info.pending_member_detail:
                    puppet = await p.Puppet.get_by_address(Address(uuid=detail.uuid))
                    level = 50 if detail.role == GroupMemberRole.ADMINISTRATOR else 0
                    levels.users[puppet.intent_for(self).mxid] = level
            else:
                ac = GroupAccessControl()
            levels.ban = 50
            levels.kick = 50
            levels.invite = 50 if ac.members == AccessControlMode.ADMINISTRATOR else 0
            levels.state_default = 50
            meta_edit_level = 50 if ac.attributes == AccessControlMode.ADMINISTRATOR else 0
        levels.events[EventType.ROOM_NAME] = meta_edit_level
        levels.events[EventType.ROOM_AVATAR] = meta_edit_level
        levels.events[EventType.ROOM_TOPIC] = meta_edit_level
        levels.events[EventType.ROOM_ENCRYPTION] = 50 if self.matrix.e2ee else 99
        levels.events[EventType.ROOM_TOMBSTONE] = 99
        levels.users_default = 0
        levels.events_default = 0
        # Remote delete is only for your own messages
        levels.redact = 99
        if self.main_intent.mxid not in levels.users:
            levels.users[self.main_intent.mxid] = 9001 if is_initial else 100
        return levels

    async def _create_matrix_room(self, source: u.User, info: ChatInfo) -> RoomID | None:
        if self.mxid:
            await self._update_matrix_room(source, info)
            return self.mxid
        await self.update_info(source, info)
        self.log.debug("Creating Matrix room")
        name: str | None = None
        power_levels = await self._get_power_levels(info=info, is_initial=True)
        initial_state = [
            {
                "type": str(StateBridge),
                "state_key": self.bridge_info_state_key,
                "content": self.bridge_info,
            },
            {
                # TODO remove this once https://github.com/matrix-org/matrix-doc/pull/2346 is in spec
                "type": str(StateHalfShotBridge),
                "state_key": self.bridge_info_state_key,
                "content": self.bridge_info,
            },
            {
                "type": str(EventType.ROOM_POWER_LEVELS),
                "content": power_levels.serialize(),
            },
        ]
        invites = []
        if self.config["bridge.encryption.default"] and self.matrix.e2ee:
            self.encrypted = True
            initial_state.append(
                {
                    "type": str(EventType.ROOM_ENCRYPTION),
                    "content": {"algorithm": "m.megolm.v1.aes-sha2"},
                }
            )
            if self.is_direct:
                invites.append(self.az.bot_mxid)
        if self.is_direct and source.address == self.chat_id:
            name = self.name = "Signal Note to Self"
        elif self.encrypted or self.private_chat_portal_meta or not self.is_direct:
            name = self.name
        if self.avatar_url:
            initial_state.append(
                {
                    "type": str(EventType.ROOM_AVATAR),
                    "content": {"url": self.avatar_url},
                }
            )

        creation_content = {}
        if not self.config["bridge.federate_rooms"]:
            creation_content["m.federate"] = False
        self.mxid = await self.main_intent.create_room(
            name=name,
            is_direct=self.is_direct,
            initial_state=initial_state,
            invitees=invites,
            creation_content=creation_content,
            # Make sure the power level event in initial_state is allowed
            # even if the server sends a default power level event before it.
            # TODO remove this if the spec is changed to require servers to
            #      use the power level event in initial_state
            power_level_override={"users": {self.main_intent.mxid: 9001}},
        )
        if not self.mxid:
            raise Exception("Failed to create room: no mxid returned")
        self.name_set = bool(name)
        self.avatar_set = bool(self.avatar_url)

        if self.encrypted and self.matrix.e2ee and self.is_direct:
            try:
                await self.az.intent.ensure_joined(self.mxid)
            except Exception:
                self.log.warning("Failed to add bridge bot to new private chat {self.mxid}")

        puppet = await p.Puppet.get_by_custom_mxid(source.mxid)
        await self.main_intent.invite_user(
            self.mxid, source.mxid, extra_content=self._get_invite_content(puppet)
        )
        if puppet:
            try:
                await source.update_direct_chats({self.main_intent.mxid: [self.mxid]})
                await puppet.intent.join_room_by_id(self.mxid)
            except MatrixError:
                self.log.debug(
                    "Failed to join custom puppet into newly created portal", exc_info=True
                )

        await self.update()
        self.log.debug(f"Matrix room created: {self.mxid}")
        self.by_mxid[self.mxid] = self
        if not self.is_direct:
            await self._update_participants(source, info)

        return self.mxid

    # endregion
    # region Database getters

    async def _postinit(self) -> None:
        self.by_chat_id[(self.chat_id_str, self.receiver)] = self
        if self.mxid:
            self.by_mxid[self.mxid] = self
        if self.is_direct:
            puppet = await p.Puppet.get_by_address(self.chat_id)
            self._main_intent = puppet.default_mxid_intent
        elif not self.is_direct:
            self._main_intent = self.az.intent

    async def delete(self) -> None:
        await DBMessage.delete_all(self.mxid)
        self.by_mxid.pop(self.mxid, None)
        self.mxid = None
        self.encrypted = False
        await self.update()

    async def save(self) -> None:
        await self.update()

    @classmethod
    def all_with_room(cls) -> AsyncGenerator[Portal, None]:
        return cls._db_to_portals(super().all_with_room())

    @classmethod
    def find_private_chats_with(cls, other_user: Address) -> AsyncGenerator[Portal, None]:
        return cls._db_to_portals(super().find_private_chats_with(other_user))

    @classmethod
    async def _db_to_portals(cls, query: Awaitable[list[Portal]]) -> AsyncGenerator[Portal, None]:
        portals = await query
        for index, portal in enumerate(portals):
            try:
                yield cls.by_chat_id[(portal.chat_id_str, portal.receiver)]
            except KeyError:
                await portal._postinit()
                yield portal

    @classmethod
    @async_getter_lock
    async def get_by_mxid(cls, mxid: RoomID) -> Portal | None:
        try:
            return cls.by_mxid[mxid]
        except KeyError:
            pass

        portal = cast(cls, await super().get_by_mxid(mxid))
        if portal is not None:
            await portal._postinit()
            return portal

        return None

    @classmethod
    async def get_by_chat_id(
        cls, chat_id: GroupID | Address, *, receiver: str = "", create: bool = False
    ) -> Portal | None:
        if isinstance(chat_id, str):
            receiver = ""
        elif not isinstance(chat_id, Address):
            raise ValueError(f"Invalid chat ID type {type(chat_id)}")
        elif not receiver:
            raise ValueError("Direct chats must have a receiver")
        best_id = id_to_str(chat_id)
        portal = await cls._get_by_chat_id(best_id, receiver, create=create, chat_id=chat_id)
        if portal:
            portal.log.debug(f"get_by_chat_id({chat_id}, {receiver}) -> {hex(id(portal))}")
        return portal

    @classmethod
    @async_getter_lock
    async def _get_by_chat_id(
        cls, best_id: str, receiver: str, *, create: bool, chat_id: GroupID | Address
    ) -> Portal | None:
        try:
            return cls.by_chat_id[(best_id, receiver)]
        except KeyError:
            pass

        portal = cast(cls, await super().get_by_chat_id(chat_id, receiver))
        if portal is not None:
            await portal._postinit()
            return portal

        if create:
            portal = cls(chat_id, receiver)
            await portal.insert()
            await portal._postinit()
            return portal

        return None

    # endregion
