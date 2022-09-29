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

from mausignald.errors import (
    AttachmentTooLargeError,
    NotConnected,
    ProfileUnavailableError,
    RPCError,
)
from mausignald.types import (
    AccessControlMode,
    Address,
    AnnouncementsMode,
    Attachment,
    Group,
    GroupAccessControl,
    GroupChange,
    GroupID,
    GroupMember,
    GroupMemberRole,
    GroupV2,
    GroupV2ID,
    LinkPreview,
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
from mautrix.bridge import BasePortal, RejectMatrixInvite, async_getter_lock
from mautrix.errors import IntentError, MatrixError, MBadState, MForbidden
from mautrix.types import (
    AudioInfo,
    BeeperMessageStatusEventContent,
    ContentURI,
    EncryptedEvent,
    EncryptedFile,
    EventID,
    EventType,
    FileInfo,
    ImageInfo,
    JoinRule,
    MediaMessageEventContent,
    Membership,
    MessageEvent,
    MessageEventContent,
    MessageStatus,
    MessageStatusReason,
    MessageType,
    PowerLevelStateEventContent,
    RelatesTo,
    RelationType,
    RoomID,
    TextMessageEventContent,
    UserID,
    VideoInfo,
)
from mautrix.util import ffmpeg, variation_selector
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
ChatInfo = Union[Group, GroupV2, GroupV2ID, Profile, Address]
MAX_MATRIX_MESSAGE_SIZE = 30000
BEEPER_LINK_PREVIEWS_KEY = "com.beeper.linkpreviews"
BEEPER_IMAGE_ENCRYPTION_KEY = "beeper:image:encryption"


class UnknownReactionTarget(Exception):
    pass


class Portal(DBPortal, BasePortal):
    by_mxid: dict[RoomID, Portal] = {}
    by_chat_id: dict[tuple[str, str], Portal] = {}
    _sticker_meta_cache: dict[str, StickerPack] = {}
    disappearing_msg_class = DisappearingMessage
    config: Config
    matrix: m.MatrixHandler
    signal: s.SignalHandler
    az: AppService
    private_chat_portal_meta: bool
    expiration_time: int | None

    _main_intent: IntentAPI | None
    _create_room_lock: asyncio.Lock
    _msgts_dedup: deque[tuple[UUID, int]]
    _reaction_dedup: deque[tuple[UUID, int, str, UUID, bool]]
    _reaction_lock: asyncio.Lock
    _pending_members: set[UUID] | None
    _expiration_lock: asyncio.Lock

    def __init__(
        self,
        chat_id: GroupID | UUID,
        receiver: str,
        mxid: RoomID | None = None,
        name: str | None = None,
        topic: str | None = None,
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
            chat_id=chat_id,
            receiver=receiver,
            mxid=mxid,
            name=name,
            topic=topic,
            avatar_hash=avatar_hash,
            avatar_url=avatar_url,
            name_set=name_set,
            avatar_set=avatar_set,
            revision=revision,
            encrypted=encrypted,
            relay_user_id=relay_user_id,
            expiration_time=expiration_time,
        )
        BasePortal.__init__(self)
        self._create_room_lock = asyncio.Lock()
        self.log = self.log.getChild(str(self.chat_id))
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
        return isinstance(self.chat_id, UUID)

    @property
    def disappearing_enabled(self) -> bool:
        return self.is_direct or self.config["signal.enable_disappearing_messages_in_groups"]

    @classmethod
    def init_cls(cls, bridge: "SignalBridge") -> None:
        cls.config = bridge.config
        cls.matrix = bridge.matrix
        cls.signal = bridge.signal
        cls.az = bridge.az
        cls.loop = bridge.loop
        BasePortal.bridge = bridge
        cls.private_chat_portal_meta = cls.config["bridge.private_chat_portal_meta"]

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
                author=sender.uuid,
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
        # Signal limits files to 100 MB
        if message.info and message.info.size and message.info.size > 100 * 10**6:
            raise AttachmentTooLargeError({"filename": message.body})
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
            status = (
                MessageSendCheckpointStatus.UNSUPPORTED
                if isinstance(e, AttachmentTooLargeError)
                else MessageSendCheckpointStatus.PERM_FAILURE
            )
            sender.send_remote_checkpoint(
                status, event_id, self.mxid, EventType.ROOM_MESSAGE, message.msgtype, error=e
            )
            await sender.handle_auth_failure(e)
            await self._send_error_notice("message", e)
            asyncio.create_task(self._send_message_status(event_id, e))

    async def _send_error_notice(self, type_name: str, err: Exception) -> None:
        if not self.config["bridge.delivery_error_reports"]:
            return
        message = f"{type(err).__name__}: {err}"
        if isinstance(err, NotConnected):
            message = "There was an error connecting to signald."
        elif isinstance(err, UnknownReactionTarget):
            message = "Could not find message to react to on Signal."
        await self._send_message(
            self.main_intent,
            TextMessageEventContent(
                msgtype=MessageType.NOTICE,
                body=f"\u26a0 Your {type_name} was not bridged: {message}",
            ),
        )

    async def _send_message_status(self, event_id: EventID, err: Exception | None) -> None:
        if not self.config["bridge.message_status_events"]:
            return
        intent = self.az.intent if self.encrypted else self.main_intent
        status = BeeperMessageStatusEventContent(
            network=self.bridge_info_state_key,
            relates_to=RelatesTo(
                rel_type=RelationType.REFERENCE,
                event_id=event_id,
            ),
        )
        if err:
            status.reason = MessageStatusReason.GENERIC_ERROR
            status.error = str(err)
            if isinstance(err, AttachmentTooLargeError):
                status.reason = MessageStatusReason.UNSUPPORTED
                status.status = MessageStatus.FAIL
                status.message = "too large file (maximum is 100MB)"
            elif isinstance(err, UnknownReactionTarget):
                status.status = MessageStatus.FAIL
            else:
                status.status = MessageStatus.RETRIABLE
        else:
            status.status = MessageStatus.SUCCESS
        status.fill_legacy_booleans()
        await intent.send_message_event(
            room_id=self.mxid,
            event_type=EventType.BEEPER_MESSAGE_STATUS,
            content=status,
        )

    async def _beeper_link_preview_to_signal(
        self, beeper_link_preview: dict[str, Any]
    ) -> LinkPreview | None:
        link_preview = LinkPreview(
            url=beeper_link_preview["matched_url"],
            title=beeper_link_preview.get("og:title", ""),
            description=beeper_link_preview.get("og:description", ""),
        )
        if BEEPER_IMAGE_ENCRYPTION_KEY in beeper_link_preview or "og:image" in beeper_link_preview:
            if BEEPER_IMAGE_ENCRYPTION_KEY in beeper_link_preview:
                file = EncryptedFile.deserialize(beeper_link_preview[BEEPER_IMAGE_ENCRYPTION_KEY])
                data = await self.main_intent.download_media(file.url)
                data = decrypt_attachment(data, file.key.key, file.hashes.get("sha256"), file.iv)
            else:
                data = await self.main_intent.download_media(beeper_link_preview["og:image"])

            attachment_path = self._write_outgoing_file(data)
            link_preview.attachment = Attachment(
                content_type=beeper_link_preview.get("og:image:type"),
                outgoing_filename=attachment_path,
                width=beeper_link_preview.get("og:image:width", 0),
                height=beeper_link_preview.get("og:image:height", 0),
                size=beeper_link_preview.get("matrix:image:size", 0),
            )
        return link_preview

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
        self._msgts_dedup.appendleft((sender.uuid, request_id))

        quote = None
        if message.get_reply_to():
            reply = await DBMessage.get_by_mxid(message.get_reply_to(), self.mxid)
            # TODO include actual text? either store in db or fetch event from homeserver
            if reply is not None:
                quote = Quote(id=reply.timestamp, author=Address(uuid=reply.sender), text="")
                # TODO only send this when it's actually a reply to an attachment?
                #      Neither Signal Android nor iOS seem to care though, so this works too
                quote.attachments = [QuotedAttachment("", "")]

        attachments: list[Attachment] | None = None
        attachment_path: str | None = None
        mentions: list[Mention] | None = None
        link_previews: list[LinkPreview] | None = None
        if message.msgtype.is_text:
            text, mentions = await matrix_to_signal(message)
            message_previews = message.get(BEEPER_LINK_PREVIEWS_KEY, [])
            potential_link_previews: list[LinkPreview | None] = cast(
                list,
                await asyncio.gather(
                    *(self._beeper_link_preview_to_signal(m) for m in message_previews)
                ),
            )
            link_previews = [p for p in potential_link_previews if p is not None]
        elif message.msgtype.is_media:
            attachment_path = await self._download_matrix_media(message)
            attachment = await self._make_attachment(message, attachment_path)
            attachments = [attachment]
            text = message.body if is_relay else None
            self.log.trace("Formed outgoing attachment %s", attachment)
        elif message.msgtype == MessageType.LOCATION:
            try:
                lat, long = message.geo_uri[len("geo:") :].split(";")[0].split(",")
                text = self.config["bridge.location_format"].format(
                    lat=float(lat), long=float(long)
                )
            except (ValueError, KeyError, IndexError) as e:
                orig_sender.send_remote_checkpoint(
                    status=MessageSendCheckpointStatus.PERM_FAILURE,
                    event_id=event_id,
                    room_id=self.mxid,
                    event_type=EventType.ROOM_MESSAGE,
                    message_type=message.msgtype,
                    error=str(e),
                )
                self.log.warning(f"Malformed geo URI in {event_id}: {e}")
                return
            extev = message.get("org.matrix.msc3488.location", None)
            # TODO support relay mode with extensible event location descriptions
            if extev and not is_relay:
                body = extev.get("description")
            else:
                body = message.body
            if body:
                text = f"{body}\n{text}"
        else:
            self.log.debug(f"Unknown msgtype {message.msgtype} in Matrix message {event_id}")
            return

        self.log.debug(f"Sending Matrix message {event_id} to Signal with timestamp {request_id}")
        retry_count = await self._signal_send_with_retries(
            sender,
            event_id,
            message_type=message.msgtype,
            send_fn=lambda *args, **kwargs: self.signal.send(**kwargs),
            event_type=EventType.ROOM_MESSAGE,
            username=sender.username,
            recipient=self.chat_id,
            body=text,
            mentions=mentions,
            previews=link_previews,
            quote=quote,
            attachments=attachments,
            timestamp=request_id,
        )

        msg = DBMessage(
            mxid=event_id,
            mx_room=self.mxid,
            sender=sender.uuid,
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
        if self.expiration_time and self.disappearing_enabled:
            dm = DisappearingMessage(self.mxid, event_id, self.expiration_time)
            dm.start_timer()
            await dm.insert()
            asyncio.create_task(self._disappear_event(dm))

        sender.send_remote_checkpoint(
            MessageSendCheckpointStatus.SUCCESS,
            event_id,
            self.mxid,
            EventType.ROOM_MESSAGE,
            message.msgtype,
            retry_num=retry_count,
        )
        await self._send_delivery_receipt(event_id)
        asyncio.create_task(self._send_message_status(event_id, err=None))

    async def _signal_send_with_retries(
        self,
        sender: u.User,
        event_id: EventID,
        send_fn: Callable,
        event_type: EventType,
        message_type: MessageType | None = None,
        **send_args,
    ) -> int:
        retry_count = 4
        last_error_type = NotConnected
        for retry_num in range(retry_count):
            try:
                req_id = uuid4()
                self.log.info(
                    f"Send attempt {retry_num}. Attempting to send {event_id} with {req_id}"
                )
                await send_fn(sender, event_id, req_id=req_id, **send_args)
                return retry_num
            except (NotConnected, UnknownReactionTarget) as e:
                if retry_num >= retry_count - 1:
                    break
                last_error_type = type(e)
                # Only handle NotConnected and UnknownReactionTarget exceptions so that other
                # exceptions actually continue to error.
                sleep_seconds = retry_num * 2 + 1
                msg = (
                    f"Not connected to signald. Going to sleep for {sleep_seconds}s. Error: {e}"
                    if isinstance(e, NotConnected)
                    else f"UnknownReactionTarget: Going to sleep for {sleep_seconds}s. Error: {e}"
                )
                self.log.exception(msg)
                sender.send_remote_checkpoint(
                    MessageSendCheckpointStatus.WILL_RETRY,
                    event_id,
                    self.mxid,
                    event_type,
                    message_type=message_type,
                    error=msg,
                    retry_num=retry_num,
                )

                await asyncio.sleep(sleep_seconds)
            except Exception as e:
                await sender.handle_auth_failure(e)
                raise
        event_type_name = {
            EventType.ROOM_MESSAGE: "message",
            EventType.REACTION: "reaction",
        }.get(event_type, str(event_type))
        raise last_error_type(f"Failed to send {event_type_name} after {retry_count} retries.")

    async def handle_matrix_reaction(
        self, sender: u.User, event_id: EventID, reacting_to: EventID, emoji: str
    ) -> None:
        if not await sender.is_logged_in():
            self.log.trace(f"Ignoring reaction by non-logged-in user {sender.mxid}")
            return

        # Signal doesn't seem to use variation selectors at all
        emoji = variation_selector.remove(emoji)
        try:
            retry_count = await self._signal_send_with_retries(
                sender,
                event_id,
                send_fn=self._handle_matrix_reaction,
                event_type=EventType.REACTION,
                reacting_to=reacting_to,
                emoji=emoji,
            )
        except Exception as e:
            self.log.exception(f"Failed to handle Matrix reaction {event_id} to {reacting_to}")
            sender.send_remote_checkpoint(
                MessageSendCheckpointStatus.PERM_FAILURE,
                event_id,
                self.mxid,
                EventType.REACTION,
                error=e,
            )
            await self._send_error_notice("reaction", e)
            await sender.handle_auth_failure(e)
            asyncio.create_task(self._send_message_status(event_id, e))
        else:
            sender.send_remote_checkpoint(
                MessageSendCheckpointStatus.SUCCESS,
                event_id,
                self.mxid,
                EventType.REACTION,
                retry_num=retry_count,
            )
            await self._send_delivery_receipt(event_id)
            asyncio.create_task(self._send_message_status(event_id, err=None))

    async def _handle_matrix_reaction(
        self,
        sender: u.User,
        event_id: EventID,
        reacting_to: EventID,
        emoji: str,
        req_id: UUID | None = None,
    ) -> None:
        message = await DBMessage.get_by_mxid(reacting_to, self.mxid)
        if not message:
            self.log.debug(f"Ignoring reaction to unknown event {reacting_to}")
            raise UnknownReactionTarget(f"Ignoring reaction to unknown event {reacting_to}")

        async with self._reaction_lock:
            existing = await DBReaction.get_by_signal_id(
                self.chat_id, self.receiver, message.sender, message.timestamp, sender.uuid
            )
            if existing and existing.emoji == emoji:
                return

            dedup_id = (message.sender, message.timestamp, emoji, sender.uuid, False)
            self._reaction_dedup.appendleft(dedup_id)

            reaction = Reaction(
                emoji=emoji,
                remove=False,
                target_author=Address(uuid=message.sender),
                target_sent_timestamp=message.timestamp,
            )
            self.log.trace(f"{sender.mxid} reacted to {message.timestamp} with {emoji}")
            await self.signal.react(
                sender.username, recipient=self.chat_id, reaction=reaction, req_id=req_id
            )

            await self._upsert_reaction(
                existing, self.main_intent, event_id, sender, message, emoji
            )

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
                self.log.exception(
                    f"Failed to handle Matrix redaction {redaction_event_id} of "
                    f"message {event_id} ({message.timestamp})"
                )
                sender.send_remote_checkpoint(
                    MessageSendCheckpointStatus.PERM_FAILURE,
                    redaction_event_id,
                    self.mxid,
                    EventType.ROOM_REDACTION,
                    error=e,
                )
                await sender.handle_auth_failure(e)
                asyncio.create_task(self._send_error_notice("message deletion", e))
                asyncio.create_task(self._send_message_status(event_id, e))
            else:
                self.log.trace(f"Removed {message} after Matrix redaction")
                sender.send_remote_checkpoint(
                    MessageSendCheckpointStatus.SUCCESS,
                    redaction_event_id,
                    self.mxid,
                    EventType.ROOM_REDACTION,
                )
                await self._send_delivery_receipt(redaction_event_id)
                asyncio.create_task(self._send_message_status(redaction_event_id, err=None))
            return

        reaction = await DBReaction.get_by_mxid(event_id, self.mxid)
        if reaction:
            try:
                await reaction.delete()
                remove_reaction = Reaction(
                    emoji=reaction.emoji,
                    remove=True,
                    target_author=Address(uuid=reaction.msg_author),
                    target_sent_timestamp=reaction.msg_timestamp,
                )
                await self.signal.react(
                    username=sender.username, recipient=self.chat_id, reaction=remove_reaction
                )
            except Exception as e:
                self.log.exception(
                    f"Failed to handle Matrix redaction {redaction_event_id} of "
                    f"reaction {event_id} to {reaction.msg_timestamp}"
                )
                sender.send_remote_checkpoint(
                    MessageSendCheckpointStatus.PERM_FAILURE,
                    redaction_event_id,
                    self.mxid,
                    EventType.ROOM_REDACTION,
                    error=e,
                )
                await sender.handle_auth_failure(e)
                asyncio.create_task(self._send_error_notice("reaction deletion", e))
                asyncio.create_task(self._send_message_status(event_id, e))
            else:
                self.log.trace(f"Removed {reaction} after Matrix redaction")
                sender.send_remote_checkpoint(
                    MessageSendCheckpointStatus.SUCCESS,
                    redaction_event_id,
                    self.mxid,
                    EventType.ROOM_REDACTION,
                )
                await self._send_delivery_receipt(redaction_event_id)
                asyncio.create_task(self._send_message_status(redaction_event_id, err=None))
            return

        sender.send_remote_checkpoint(
            MessageSendCheckpointStatus.PERM_FAILURE,
            redaction_event_id,
            self.mxid,
            EventType.ROOM_REDACTION,
            error="No message or reaction found for redaction",
        )
        status_err = UnknownReactionTarget("No message or reaction found for redaction")
        asyncio.create_task(self._send_message_status(redaction_event_id, err=status_err))

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
                await user.handle_auth_failure(e)
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
            if self.config["bridge.bridge_matrix_leave"]:
                await self.signal.leave_group(user.username, self.chat_id)
            # TODO cleanup if empty

    async def kick_matrix(self, user: u.User | p.Puppet, source: u.User) -> None:
        try:
            await self.signal.update_group(
                source.username, self.chat_id, remove_members=[user.address]
            )
        except Exception as e:
            self.log.exception(f"Failed to kick Signal user: {e}")
            info = await self.signal.get_group(source.username, self.chat_id)
            if user.address in info.members:
                await self.main_intent.invite_user(
                    self.mxid,
                    user.mxid,
                    check_cache=True,
                    reason=f"Failed to kick Signal user: {e}",
                )
                await user.intent_for(self).ensure_joined(self.mxid)

    async def ban_matrix(self, user: u.User | p.Puppet, source: u.User) -> None:
        try:
            await self.signal.ban_user(source.username, self.chat_id, users=[user.address])
        except Exception as e:
            self.log.exception(f"Failed to ban Signal user: {e}")
            info = await self.signal.get_group(source.username, self.chat_id)
            is_banned = False
            if info.banned_members:
                for member in info.banned_members:
                    is_banned = user.uuid == member.uuid or is_banned
            if not is_banned:
                await self.main_intent.unban_user(
                    self.mxid, user.mxid, reason=f"Failed to ban Signal user: {e}"
                )
            if user.address in info.members:
                await self.main_intent.invite_user(
                    self.mxid,
                    user.mxid,
                    check_cache=True,
                )
                await user.intent_for(self).ensure_joined(self.mxid)

    async def unban_matrix(self, user: u.User | p.Puppet, source: u.User) -> None:
        try:
            await self.signal.unban_user(source.username, self.chat_id, users=[user.address])
        except Exception as e:
            self.log.exception(f"Failed to unban Signal user: {e}")
            info = await self.signal.get_group(source.username, self.chat_id)
            if info.banned_members:
                for member in info.banned_members:
                    if member.uuid == user.uuid:
                        await self.main_intent.ban_user(
                            self.mxid, user.mxid, reason=f"Failed to unban Signal user: {e}"
                        )
                        return

    async def handle_matrix_invite(self, invited_by: u.User, user: u.User | p.Puppet) -> None:
        if self.is_direct:
            raise RejectMatrixInvite("You can't invite additional users to private chats.")

        try:
            await self.signal.update_group(
                invited_by.username, self.chat_id, add_members=[user.address]
            )
        except RPCError as e:
            raise RejectMatrixInvite(str(e)) from e
        if user.mxid == self.config["bridge.relay.relaybot"] != "@relaybot:example.com":
            await self._handle_relaybot_invited(user)
        power_levels = await self.main_intent.get_power_levels(self.mxid)
        invitee_pl = power_levels.get_user_level(user.mxid)
        if invitee_pl >= 50:
            group_member = GroupMember(uuid=user.uuid, role=GroupMemberRole.ADMINISTRATOR)
            try:
                update_meta = await self.signal.update_group(
                    invited_by.username, self.chat_id, update_role=group_member
                )
                self.revision = update_meta.revision
            except Exception as e:
                self.log.exception(f"Failed to update Signal member role: {e}")
                await self._update_power_levels(
                    await self.signal.get_group(invited_by.username, self.chat_id)
                )

    async def _handle_relaybot_invited(self, user: u.User) -> None:
        if not self.config["bridge.relay.enabled"]:
            await self.main_intent.send_notice(
                self.mxid, "Relay mode is not enabled in this instance of the bridge."
            )
        else:
            await self.set_relay_user(user)
            await self.main_intent.send_notice(
                self.mxid,
                "Messages from non-logged-in users in this room will now be bridged "
                "through the relaybot's Signal account.",
            )

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
        except Exception as e:
            self.log.exception("Failed to update Signal group name")
            await user.handle_auth_failure(e)
            self.name = None

    async def handle_matrix_topic(self, user: u.User, topic: str) -> None:
        if self.topic == topic or self.is_direct or not topic:
            return
        sender, is_relay = await self.get_relay_sender(user, "topic change")
        if not sender:
            return
        self.topic = topic
        self.log.debug(
            f"{user.mxid} changed the group topic, sending to Signal through {sender.username}"
        )
        try:
            await self.signal.update_group(sender.username, self.chat_id, description=topic)
        except Exception:
            self.log.exception("Failed to update Signal group description")
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
        except Exception as e:
            self.log.exception("Failed to update Signal group avatar")
            await user.handle_auth_failure(e)
            self.avatar_set = False
        if self.config["signal.remove_file_after_handling"]:
            try:
                os.remove(path)
            except FileNotFoundError:
                pass

    async def handle_matrix_power_level(
        self,
        sender: u.User,
        levels: PowerLevelStateEventContent,
        prev_content: PowerLevelStateEventContent | None = None,
    ) -> None:
        old_users = prev_content.users if prev_content else None
        new_users = levels.users
        changes = {}
        sender, is_relay = await self.get_relay_sender(sender, "power level change")
        if not sender:
            return

        if not old_users:
            changes = new_users
        else:
            for user, level in new_users.items():
                if (
                    user
                    and user != self.main_intent.mxid
                    and (user not in old_users or level != old_users[user])
                ):
                    changes[user] = level
            for user, level in old_users.items():
                if user and user != self.main_intent.mxid and user not in new_users:
                    changes[user] = levels.users_default
        if changes:
            for user, level in changes.items():
                uuid = p.Puppet.get_id_from_mxid(user)
                if not uuid:
                    mx_user = await u.User.get_by_mxid(user, create=False)
                    if not mx_user or not mx_user.is_logged_in:
                        continue
                    uuid = mx_user.uuid
                if not uuid:
                    continue
                signal_role = (
                    GroupMemberRole.DEFAULT if level < 50 else GroupMemberRole.ADMINISTRATOR
                )
                group_member = GroupMember(uuid=uuid, role=signal_role)
                try:
                    update_meta = await self.signal.update_group(
                        sender.username, self.chat_id, update_role=group_member
                    )
                    self.revision = update_meta.revision
                except Exception as e:
                    self.log.exception(f"Failed to update Signal member role: {e}")
                    await self._update_power_levels(
                        await self.signal.get_group(sender.username, self.chat_id)
                    )
                    return
        if not prev_content or levels.invite != prev_content.invite:
            try:
                update_meta = await self.signal.update_group(
                    username=sender.username,
                    group_id=self.chat_id,
                    update_access_control=GroupAccessControl(
                        members=(
                            AccessControlMode.MEMBER
                            if levels.invite == 0
                            else AccessControlMode.ADMINISTRATOR
                        ),
                        attributes=None,
                        link=None,
                    ),
                )
                self.revision = update_meta.revision
            except Exception as e:
                self.log.exception(f"Failed to update Signal member add permission: {e}")
                await self._update_power_levels(
                    await self.signal.get_group(sender.username, self.chat_id)
                )
                return
        if not prev_content or levels.state_default != prev_content.state_default:
            try:
                update_meta = await self.signal.update_group(
                    username=sender.username,
                    group_id=self.chat_id,
                    update_access_control=GroupAccessControl(
                        attributes=(
                            AccessControlMode.MEMBER
                            if levels.state_default == 0
                            else AccessControlMode.ADMINISTRATOR
                        ),
                        members=None,
                        link=None,
                    ),
                )
                self.revision = update_meta.revision
            except Exception as e:
                self.log.exception(f"Failed to update Signal metadata change permission: {e}")
                await self._update_power_levels(
                    await self.signal.get_group(sender.username, self.chat_id)
                )

    async def handle_matrix_join_rules(self, sender: u.User, join_rule: JoinRule) -> None:
        if join_rule == JoinRule.PUBLIC:
            link_access = AccessControlMode.ANY
        elif join_rule == JoinRule.INVITE:
            link_access = AccessControlMode.UNSATISFIABLE
        else:
            link_access = AccessControlMode.ADMINISTRATOR
        sender, is_relay = await self.get_relay_sender(sender, "join_rule change")
        if not sender:
            return

        try:
            update_meta = await self.signal.update_group(
                sender.username,
                self.chat_id,
                update_access_control=GroupAccessControl(
                    attributes=None, members=None, link=link_access
                ),
            )
            self.revision = update_meta.revision
        except Exception as e:
            self.log.exception(f"Failed to update Signal link access control: {e}")
            await self._update_join_rules(
                await self.signal.get_group(sender.username, self.chat_id)
            )

    # endregion
    # region Signal event handling

    async def _find_quote_event_id(self, quote: Quote | None) -> MessageEvent | EventID | None:
        if not quote:
            return None

        puppet = await p.Puppet.get_by_address(quote.author, create=False)
        if not puppet:
            return None
        reply_msg = await DBMessage.get_by_signal_id(
            puppet.uuid, quote.id, self.chat_id, self.receiver
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

    async def _signal_link_preview_to_beeper(
        self, link_preview: LinkPreview, intent: IntentAPI
    ) -> dict[str, Any]:
        beeper_link_preview: dict[str, Any] = {
            "matched_url": link_preview.url,
            "og:title": link_preview.title,
            "og:url": link_preview.url,
            "og:description": link_preview.description,
        }

        # Upload an image corresponding to the link preview if it exists.
        if link_preview.attachment and link_preview.attachment.incoming_filename:
            beeper_link_preview["og:image:type"] = link_preview.attachment.content_type
            beeper_link_preview["og:image:height"] = link_preview.attachment.height
            beeper_link_preview["og:image:width"] = link_preview.attachment.width
            beeper_link_preview["matrix:image:size"] = link_preview.attachment.size

            with open(link_preview.attachment.incoming_filename, "rb") as file:
                data = file.read()
            if self.config["signal.remove_file_after_handling"]:
                os.remove(link_preview.attachment.incoming_filename)

            upload_mime_type = link_preview.attachment.content_type
            if self.encrypted and encrypt_attachment:
                data, beeper_link_preview[BEEPER_IMAGE_ENCRYPTION_KEY] = encrypt_attachment(data)
                upload_mime_type = "application/octet-stream"

            upload_uri = await intent.upload_media(
                data,
                mime_type=upload_mime_type,
                filename=link_preview.attachment.id,
                async_upload=self.config["homeserver.async_media"],
            )
            if BEEPER_IMAGE_ENCRYPTION_KEY in beeper_link_preview:
                beeper_link_preview[BEEPER_IMAGE_ENCRYPTION_KEY].url = upload_uri
                beeper_link_preview[BEEPER_IMAGE_ENCRYPTION_KEY] = beeper_link_preview[
                    BEEPER_IMAGE_ENCRYPTION_KEY
                ].serialize()
            else:
                beeper_link_preview["og:image"] = upload_uri
        return beeper_link_preview

    async def handle_signal_message(
        self, source: u.User, sender: p.Puppet, message: MessageData
    ) -> None:
        if (sender.uuid, message.timestamp) in self._msgts_dedup:
            self.log.debug(
                f"Ignoring message {message.timestamp} by {sender.uuid} as it was already handled "
                "(message.timestamp in dedup queue)"
            )
            await self.signal.send_receipt(
                source.username, sender.address, timestamps=[message.timestamp]
            )
            return
        self._msgts_dedup.appendleft((sender.uuid, message.timestamp))
        old_message = await DBMessage.get_by_signal_id(
            sender.uuid, message.timestamp, self.chat_id, self.receiver
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
                content.msgtype = None
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

            file_size = attachment.size or os.path.getsize(attachment.incoming_filename)
            if file_size > self.matrix.media_config.upload_size:
                self.log.warning(
                    "Failed to bridge attachment %s in %s: file too large",
                    attachment.id,
                    message.timestamp,
                )
                continue

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
            if message.previews:
                content[BEEPER_LINK_PREVIEWS_KEY] = await asyncio.gather(
                    *(self._signal_link_preview_to_beeper(p, intent) for p in message.previews)
                )

            if reply_to:
                content.set_reply(reply_to)
            event_id = await self._send_message(intent, content, timestamp=message.timestamp)

        if event_id:
            msg = DBMessage(
                mxid=event_id,
                mx_room=self.mxid,
                sender=sender.uuid,
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

            if message.expires_in_seconds and self.disappearing_enabled:
                dm = DisappearingMessage(self.mxid, event_id, message.expires_in_seconds)
                # Start the timer immediately for own messages
                if sender.uuid == source.uuid:
                    dm.start_timer()
                    await dm.insert()
                    asyncio.create_task(self._disappear_event(dm))
                    self.log.debug(
                        f"{event_id} set to be redacted in {message.expires_in_seconds} seconds"
                    )
                else:
                    await dm.insert()
                    self.log.debug(
                        f"{event_id} set to be redacted {message.expires_in_seconds} seconds"
                        " after room is read"
                    )
        else:
            self.log.debug(f"Didn't get event ID for {message.timestamp}")

    async def handle_signal_kicked(self, user: u.User, sender: p.Puppet) -> None:
        self.log.debug(f"{user.mxid} was kicked by {sender.number} from {self.mxid}")
        await self._kick_with_puppet(user, sender)

    async def handle_signal_group_change(self, group_change: GroupChange, source: u.User) -> None:
        if self.revision < group_change.revision:
            self.revision = group_change.revision
        else:
            return
        editor = await p.Puppet.get_by_address(group_change.editor)
        if not editor:
            self.log.warning(f"Didn't get puppet for group change editor {group_change.editor}")
            return
        editor_intent = editor.intent_for(self)
        if (
            group_change.delete_members
            or group_change.delete_pending_members
            or group_change.delete_requesting_members
        ):
            for address in (
                (group_change.delete_members or [])
                + (group_change.delete_pending_members or [])
                + (group_change.delete_requesting_members or [])
            ):
                users = [
                    await p.Puppet.get_by_address(address),
                    await u.User.get_by_address(address),
                ]
                for user in users:
                    if not user:
                        continue
                    if user == editor:
                        await editor_intent.leave_room(self.mxid)
                    else:
                        await self._kick_with_puppet(user, editor)

        if group_change.modify_member_roles:
            levels = await editor.intent_for(self).get_power_levels(self.mxid)
            for group_member in group_change.modify_member_roles:
                users = [
                    await p.Puppet.get_by_uuid(group_member.uuid),
                    await u.User.get_by_uuid(group_member.uuid),
                ]
                for user in users:
                    if not user:
                        continue
                    if (
                        group_member.role == GroupMemberRole.ADMINISTRATOR
                        and levels.users.get(user.mxid, 0) < 50
                    ):
                        levels.users[user.mxid] = 50
                        levels.users = {k: v for k, v in sorted(list(levels.users.items()))}
                    elif levels.users.get(user.mxid, 0) >= 50:
                        levels.users.pop(user.mxid, 0)
            await self._try_with_puppet(
                lambda i: i.set_power_levels(self.mxid, levels), puppet=editor
            )

        if group_change.new_banned_members:
            for banned_member in group_change.new_banned_members:
                users = [
                    await p.Puppet.get_by_uuid(banned_member.uuid),
                    await u.User.get_by_uuid(banned_member.uuid),
                ]
                for user in users:
                    if not user:
                        continue
                    try:
                        await editor_intent.ban_user(self.mxid, user.mxid)
                    except MForbidden:
                        try:
                            await self.main_intent.ban_user(
                                self.mxid, user.mxid, reason=f"banned by {editor.name}"
                            )
                        except MForbidden as e:
                            self.log.debug(f"Could not ban {user.mxid}: {e}")
                    except MBadState as e:
                        self.log.debug(f"Could not ban {user.mxid}: {e}")

        if group_change.new_unbanned_members:
            for banned_member in group_change.new_unbanned_members:
                users = [
                    await p.Puppet.get_by_uuid(banned_member.uuid),
                    await u.User.get_by_uuid(banned_member.uuid),
                ]
                for user in users:
                    if not user:
                        continue
                    try:
                        await editor_intent.unban_user(self.mxid, user.mxid)
                    except MForbidden:
                        try:
                            await self.main_intent.unban_user(
                                self.mxid, user.mxid, reason=f"unbanned by {editor.name}"
                            )
                        except MForbidden as e:
                            self.log.debug(f"Could not unban {user.mxid}: {e}")
                    except MBadState as e:
                        self.log.debug(f"Could not unban {user.mxid}: {e}")

        if (
            group_change.new_members
            or group_change.new_pending_members
            or group_change.promote_requesting_members
        ):
            banned_users = await self.az.intent.get_room_members(self.mxid, (Membership.BAN,))
            for group_member in (
                (group_change.new_members or [])
                + (group_change.new_pending_members or [])
                + (group_change.promote_requesting_members or [])
            ):
                puppet = await p.Puppet.get_by_uuid(group_member.uuid)
                await source.sync_contact(group_member.address)
                users = [puppet, await u.User.get_by_uuid(group_member.uuid)]
                for user in users:
                    if not user:
                        continue
                    if user.mxid in banned_users:
                        await self._try_with_puppet(
                            lambda i: i.unban_user(self.mxid, user.mxid), puppet=editor
                        )
                    try:
                        await editor_intent.invite_user(self.mxid, user.mxid, check_cache=True)
                    except (MForbidden, IntentError):
                        try:
                            await self.main_intent.invite_user(
                                self.mxid,
                                user.mxid,
                                reason=f"invited by {editor.name}",
                                check_cache=True,
                            )
                        except (MForbidden, IntentError) as e:
                            self.log.debug(f"{editor.name} could not invite {user.mxid}: {e}")
                    except MBadState as e:
                        self.log.debug(f"{editor.name} could not invite {user.mxid}: {e}")
                    if group_member in (group_change.new_members or []) + (
                        group_change.promote_requesting_members or []
                    ) and isinstance(user, p.Puppet):
                        try:
                            await user.intent_for(self).ensure_joined(self.mxid)
                        except IntentError as e:
                            self.log.debug(f"{user.name} could not join group: {e}")

        if group_change.promote_pending_members:
            for group_member in group_change.promote_pending_members:
                await source.sync_contact(group_member.address)
                user = await p.Puppet.get_by_uuid(group_member.uuid)
                if not user:
                    continue
                try:
                    await user.intent_for(self).ensure_joined(self.mxid)
                except IntentError as e:
                    self.log.debug(f"{user.name} could not join group: {e}")

        if group_change.new_requesting_members:
            for group_member in group_change.new_requesting_members:
                try:
                    await source.sync_contact(group_member.address)
                except ProfileUnavailableError:
                    self.log.debug(
                        f"Profile of puppet with uuid {group_member.uuid} is unavailable"
                    )
                user = await p.Puppet.get_by_uuid(group_member.uuid)
                try:
                    await user.intent_for(self).knock_room(self.mxid, reason="via invite link")
                except (MForbidden, MBadState) as e:
                    self.log.debug(f"{user.name} failed knock: {e}")

        if group_change.new_access_control:
            ac = group_change.new_access_control
            if ac.attributes or ac.members:
                levels = await editor.intent_for(self).get_power_levels(self.mxid)
                if ac.attributes:
                    meta_edit_level = 50 if ac.attributes == AccessControlMode.ADMINISTRATOR else 0
                    levels.events[EventType.ROOM_NAME] = meta_edit_level
                    levels.events[EventType.ROOM_AVATAR] = meta_edit_level
                    levels.events[EventType.ROOM_TOPIC] = meta_edit_level
                if ac.members:
                    levels.invite = 50 if ac.members == AccessControlMode.ADMINISTRATOR else 0
                await self._try_with_puppet(
                    lambda i: i.set_power_levels(self.mxid, levels), puppet=editor
                )
            if ac.link:
                new_join_rule = await self._get_new_join_rule(ac.link)
                if new_join_rule:
                    await self._try_with_puppet(
                        lambda i: i.set_join_rule(self.mxid, new_join_rule), puppet=editor
                    )

        if group_change.new_is_announcement_group:
            levels = await editor.intent_for(self).get_power_levels(self.mxid)
            if group_change.new_is_announcement_group == AnnouncementsMode.ENABLED:
                levels.events_default = 50
            elif group_change.new_is_announcement_group == AnnouncementsMode.DISABLED:
                levels.events_default = 0
            await self._try_with_puppet(
                lambda i: i.set_power_levels(self.mxid, levels), puppet=editor
            )

        changed = False
        if group_change.new_description:
            changed = await self._update_topic(group_change.new_description, editor)
        if group_change.new_title:
            changed = await self._update_name(group_change.new_title, editor) or changed
        if group_change.new_avatar:
            changed = (
                await self._update_avatar(
                    await self.signal.get_group(
                        source.username, self.chat_id, group_change.revision
                    ),
                    editor,
                )
                or changed
            )

        if changed:
            await self.update_bridge_info()
            await self.update()

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
        info.size = attachment.size or len(data)
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
            info.size = len(data)

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

        content.url = await intent.upload_media(
            data,
            mime_type=upload_mime_type,
            filename=id,
            async_upload=self.config["homeserver.async_media"],
        )
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
        author_puppet = await p.Puppet.get_by_address(reaction.target_author, create=False)
        if not author_puppet:
            return None
        target_id = reaction.target_sent_timestamp
        async with self._reaction_lock:
            dedup_id = (
                author_puppet.uuid,
                target_id,
                reaction.emoji,
                sender.uuid,
                reaction.remove,
            )
            if dedup_id in self._reaction_dedup:
                return
            self._reaction_dedup.appendleft(dedup_id)

        existing = await DBReaction.get_by_signal_id(
            self.chat_id, self.receiver, author_puppet.uuid, target_id, sender.uuid
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
            author_puppet.uuid, target_id, self.chat_id, self.receiver
        )
        if not message:
            self.log.debug(f"Ignoring reaction to unknown message {target_id}")
            return

        intent = sender.intent_for(self)
        matrix_emoji = variation_selector.add(reaction.emoji)
        mxid = await intent.react(message.mx_room, message.mxid, matrix_emoji, timestamp=timestamp)
        self.log.debug(f"{sender.uuid} reacted to {message.mxid} -> {mxid}")
        await self._upsert_reaction(existing, intent, mxid, sender, message, reaction.emoji)

    async def handle_signal_delete(self, sender: p.Puppet, message_ts: int) -> None:
        message = await DBMessage.get_by_signal_id(
            sender.uuid, message_ts, self.chat_id, self.receiver
        )
        if not message:
            return
        await message.delete()
        try:
            await sender.intent_for(self).redact(message.mx_room, message.mxid)
        except MForbidden:
            await self.main_intent.redact(message.mx_room, message.mxid)

    # endregion
    # region Matrix -> Signal metadata

    async def create_signal_group(
        self, source: u.User, levels: PowerLevelStateEventContent, join_rule: JoinRule
    ) -> None:
        user_mxids = await self.az.intent.get_room_members(
            self.mxid, (Membership.JOIN, Membership.INVITE)
        )
        invitee_addresses = []
        relaybot_mxid = self.config["bridge.relay.relaybot"]
        relaybot = None
        for mxid in user_mxids:
            mx_user = await u.User.get_by_mxid(mxid, create=False)
            if mx_user and mx_user.address and mx_user.username != source.username:
                invitee_addresses.append(mx_user.address)
                if mxid == relaybot_mxid != "@relaybot:example.com":
                    relaybot = mx_user
            puppet = await p.Puppet.get_by_mxid(mxid, create=False)
            if puppet:
                invitee_addresses.append(puppet.address)
        avatar_path: str | None = None
        if self.avatar_url:
            avatar_data = await self.az.intent.download_media(self.avatar_url)
            self.avatar_hash = hashlib.sha256(avatar_data).hexdigest()
            avatar_path = self._write_outgoing_file(avatar_data)
        signal_chat = await self.signal.create_group(
            source.username, title=self.name, members=invitee_addresses, avatar_path=avatar_path
        )
        self.name_set = bool(self.name and signal_chat.title)
        self.avatar_set = bool(self.avatar_url and self.avatar_hash and signal_chat.avatar)
        self.chat_id = signal_chat.id
        await self._postinit()
        await self.insert()
        if avatar_path and self.config["signal.remove_file_after_handling"]:
            try:
                os.remove(avatar_path)
            except FileNotFoundError:
                pass
        if self.topic:
            await self.signal.update_group(source.username, self.chat_id, description=self.topic)
        await self.handle_matrix_power_level(source, levels)
        await self.handle_matrix_join_rules(source, join_rule)
        await self.update()
        await self.update_bridge_info()
        if relaybot:
            await self._handle_relaybot_invited(relaybot)

    async def bridge_signal_group(
        self, source: u.User, levels: PowerLevelStateEventContent
    ) -> None:
        await self._postinit()
        await self.insert()
        await self.handle_matrix_power_level(source, levels)
        await self.update()
        await self.update_bridge_info()

    # endregion
    # region Updating portal info

    async def update_info(self, source: u.User, info: ChatInfo) -> None:
        if self.is_direct:
            if not isinstance(info, (Profile, Address)):
                raise ValueError(f"Unexpected type for direct chat update_info: {type(info)}")
            if not self.name or not self.topic:
                puppet = await self.get_dm_puppet()
                if not puppet.name:
                    await puppet.update_info(info, source)
                self.name = puppet.name
                if puppet.number and not self.topic:
                    self.topic = puppet.fmt_phone(puppet.number)
                    if self.mxid:
                        # This is only for automatically updating the topic in existing portals
                        await self.update_puppet_number(self.topic)
            return

        if isinstance(info, GroupV2ID):
            try:
                info = await self.signal.get_group(source.username, info.id, info.revision or -1)
            except Exception as e:
                await source.handle_auth_failure(e)
                raise
            if not info:
                self.log.debug(
                    f"Failed to get full group v2 info through {source.username}, "
                    "cancelling update"
                )
                return

        changed = False
        if isinstance(info, Group):
            changed = await self._update_name(info.name) or changed
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
            changed = await self._update_name(info.title) or changed
            changed = await self._update_topic(info.description) or changed
        elif isinstance(info, GroupV2ID):
            return
        else:
            raise ValueError(f"Unexpected type for group update_info: {type(info)}")
        changed = await self._update_avatar(info) or changed
        await self._update_participants(source, info)
        try:
            await self._update_power_levels(info)
        except Exception:
            self.log.warning("Error updating power levels", exc_info=True)
        try:
            await self._update_join_rules(info)
        except:
            self.log.warning("Error updating join rules", exc_info=True)
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

    async def get_dm_puppet(self) -> p.Puppet | None:
        if not self.is_direct:
            return None
        return await p.Puppet.get_by_uuid(self.chat_id)

    async def update_info_from_puppet(self, puppet: p.Puppet | None = None) -> None:
        if not self.is_direct:
            return
        if not puppet:
            puppet = await self.get_dm_puppet()
        await self.update_puppet_name(puppet.name, save=False)
        await self.update_puppet_avatar(puppet.avatar_hash, puppet.avatar_url, save=False)
        if puppet.number:
            await self.update_puppet_number(puppet.fmt_phone(puppet.number), save=False)

    async def update_puppet_number(self, number: str, save: bool = True) -> None:
        if not self.encrypted and not self.private_chat_portal_meta:
            return

        changed = await self._update_topic(number)
        if changed and save:
            await self.update_bridge_info()
            await self.update()

    async def update_puppet_avatar(
        self, new_hash: str, avatar_url: ContentURI, save: bool = True
    ) -> None:
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
                if save:
                    await self.update_bridge_info()
                    await self.update()

    async def update_puppet_name(self, name: str, save: bool = True) -> None:
        if not self.encrypted and not self.private_chat_portal_meta:
            return

        changed = await self._update_name(name)

        if changed and save:
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

    async def _update_topic(self, topic: str, sender: p.Puppet | None = None) -> bool:
        if self.topic != topic:
            self.topic = topic
            if self.mxid:
                try:
                    await self._try_with_puppet(
                        lambda i: i.set_room_topic(self.mxid, self.topic), puppet=sender
                    )
                except Exception:
                    self.log.exception("Error setting topic")
                    self.topic = None
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

        member_events = await self.main_intent.get_members(self.mxid)
        remove_users: set[UserID] = {
            UserID(evt.state_key)
            for evt in member_events
            if evt.content.membership == Membership.JOIN and evt.state_key != self.az.bot_mxid
        }

        pending_members = info.pending_members if isinstance(info, GroupV2) else []
        self._pending_members = {addr.uuid for addr in pending_members}

        for address in info.members + pending_members:
            user = await u.User.get_by_address(address)
            if user:
                remove_users.discard(user.mxid)
                try:
                    await self.main_intent.invite_user(self.mxid, user.mxid, check_cache=True)
                except (MForbidden, IntentError, MBadState) as e:
                    self.log.debug(f"Failed to invite {user.mxid}: {e}")

            puppet = await p.Puppet.get_by_address(address)
            if not puppet:
                self.log.warning(f"Didn't find puppet for member {address}")
                continue
            try:
                await source.sync_contact(address)
            except ProfileUnavailableError:
                self.log.debug(f"Profile of puppet with {address} is unavailable")
            try:
                await self.main_intent.invite_user(
                    self.mxid, puppet.intent_for(self).mxid, check_cache=True
                )
            except (MForbidden, IntentError, MBadState) as e:
                self.log.debug(f"could not invite {user.mxid}: {e}")
            if address.uuid not in self._pending_members:
                await puppet.intent_for(self).ensure_joined(self.mxid)
            remove_users.discard(puppet.default_mxid)

        for mxid in remove_users:
            user = await u.User.get_by_mxid(mxid, create=False)
            if user and await user.is_logged_in():
                try:
                    await self.main_intent.kick_user(
                        self.mxid, user.mxid, reason="not a member of this Signal group"
                    )
                except (MForbidden, MBadState) as e:
                    self.log.debug(f"could not kick {user.mxid}: {e}")
            puppet = await p.Puppet.get_by_mxid(mxid, create=False)
            if puppet:
                try:
                    await self.main_intent.kick_user(
                        self.mxid,
                        puppet.intent_for(self).mxid,
                        reason="not a member of this Signal group",
                    )
                except (MForbidden, MBadState) as e:
                    self.log.debug(f"could not kick {user.mxid}: {e}")

    async def _kick_with_puppet(self, user: p.Puppet | u.User, sender: p.Puppet) -> None:
        try:
            await sender.intent_for(self).kick_user(self.mxid, user.mxid)
        except MForbidden:
            try:
                await self.main_intent.kick_user(
                    self.mxid, user.mxid, reason=f"removed by {sender.name}"
                )
            except MForbidden as e:
                self.log.debug(f"Could not remove {user.mxid}: {e}")
        except MBadState as e:
            self.log.debug(f"Could not remove {user.mxid}: {e}")

    async def _update_power_levels(self, info: ChatInfo) -> None:
        if not self.mxid:
            return

        power_levels = await self.main_intent.get_power_levels(self.mxid)
        power_levels = await self._get_power_levels(power_levels, info=info, is_initial=False)
        await self.main_intent.set_power_levels(self.mxid, power_levels)

    async def _get_new_join_rule(self, link_access: AccessControlMode) -> JoinRule | None:
        if not self.mxid:
            return None
        old_join_rule = await self._get_join_rule()
        if link_access == AccessControlMode.ANY:
            # Default to invite since chat that don't require admin approval don't allow knocks
            join_rule = (
                JoinRule.PUBLIC if self.config["bridge.public_portals"] else JoinRule.INVITE
            )
            allowed_join_rules = (JoinRule.PUBLIC, JoinRule.INVITE)
        elif link_access == AccessControlMode.ADMINISTRATOR:
            join_rule = JoinRule.KNOCK
            # TODO remove getattr once mautrix-python is updated
            allowed_join_rules = (
                JoinRule.KNOCK,
                getattr(JoinRule, "KNOCK_RESTRICTED", "knock_restricted"),
            )
        else:
            join_rule = JoinRule.INVITE
            allowed_join_rules = (JoinRule.INVITE,)
        if old_join_rule in allowed_join_rules:
            return None
        return join_rule

    async def _update_join_rules(self, info: ChatInfo) -> None:
        if not self.mxid:
            return
        new_join_rule = await self._get_new_join_rule(info.access_control.link)
        if new_join_rule:
            await self.main_intent.set_join_rule(self.mxid, new_join_rule)

    async def _get_join_rule(self) -> JoinRule | None:
        evt = await self.main_intent.get_state_event(self.mxid, EventType.ROOM_JOIN_RULES)
        return evt.join_rule if evt else None

    # endregion
    # region Bridge info state event

    @property
    def bridge_info_state_key(self) -> str:
        return f"net.maunium.signal://signal/{self.chat_id!s}"

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
        elif self.is_direct and not isinstance(info, (Profile, Address)):
            raise ValueError(f"Unexpected type for updating direct chat portal: {type(info)}")
        try:
            await self._update_matrix_room(source, info)
        except Exception:
            self.log.exception("Failed to update portal")

    async def create_matrix_room(self, source: u.User, info: ChatInfo) -> RoomID | None:
        if not self.is_direct and not isinstance(info, (Group, GroupV2, GroupV2ID)):
            raise ValueError(f"Unexpected type for creating group portal: {type(info)}")
        elif self.is_direct and not isinstance(info, (Profile, Address)):
            raise ValueError(f"Unexpected type for creating direct chat portal: {type(info)}")
        if isinstance(info, Group) and not info.members:
            try:
                groups = await self.signal.list_groups(source.username)
            except Exception as e:
                await source.handle_auth_failure(e)
                raise
            info = next(
                (g for g in groups if isinstance(g, Group) and g.group_id == info.group_id), info
            )
        elif isinstance(info, GroupV2ID) and not isinstance(info, GroupV2):
            self.log.debug(
                f"create_matrix_room() called with {info}, fetching full info from signald"
            )
            try:
                info = await self.signal.get_group(source.username, info.id, info.revision or -1)
            except Exception as e:
                await source.handle_auth_failure(e)
                raise
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
        bot_pl = levels.get_user_level(self.az.bot_mxid)
        levels.events_default = 0
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
                    puppet = await p.Puppet.get_by_uuid(detail.uuid)
                    puppet_mxid = puppet.intent_for(self).mxid
                    current_level = levels.get_user_level(puppet_mxid)
                    if bot_pl > current_level and bot_pl >= 50:
                        level = current_level
                        if puppet.is_real_user:
                            if current_level >= 50 and detail.role == GroupMemberRole.DEFAULT:
                                level = 0
                            elif (
                                current_level < 50 and detail.role == GroupMemberRole.ADMINISTRATOR
                            ):
                                level = 50
                        else:
                            level = 50 if detail.role == GroupMemberRole.ADMINISTRATOR else 0
                        if level == 0:
                            levels.users.pop(puppet_mxid, None)
                        else:
                            levels.users[puppet_mxid] = level
                announcements = info.announcements
            else:
                ac = GroupAccessControl()
                announcements = AnnouncementsMode.UNKNOWN
            levels.ban = 50
            levels.kick = 50
            levels.invite = 50 if ac.members == AccessControlMode.ADMINISTRATOR else 0
            levels.state_default = 50
            meta_edit_level = 50 if ac.attributes == AccessControlMode.ADMINISTRATOR else 0
            if announcements == AnnouncementsMode.ENABLED:
                levels.events_default = 50
        levels.events[EventType.REACTION] = 0
        levels.events[EventType.ROOM_NAME] = meta_edit_level
        levels.events[EventType.ROOM_AVATAR] = meta_edit_level
        levels.events[EventType.ROOM_TOPIC] = meta_edit_level
        levels.events[EventType.ROOM_ENCRYPTION] = 50 if self.matrix.e2ee else 99
        levels.events[EventType.ROOM_TOMBSTONE] = 99
        levels.users_default = 0
        # Remote delete is only for your own messages
        levels.redact = 99
        if self.main_intent.mxid not in levels.users:
            levels.users[self.main_intent.mxid] = 9001 if is_initial else 100
        levels.users = {k: v for k, v in sorted(list(levels.users.items()))}
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
                    "content": self.get_encryption_state_event_json(),
                }
            )
            if self.is_direct:
                invites.append(self.az.bot_mxid)
        if self.is_direct and source.uuid == self.chat_id:
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
            topic=self.topic,
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
        self.by_chat_id[(str(self.chat_id), self.receiver)] = self
        if self.mxid:
            self.by_mxid[self.mxid] = self
        if self.is_direct:
            puppet = await self.get_dm_puppet()
            self._main_intent = puppet.default_mxid_intent
        elif not self.is_direct:
            self._main_intent = self.az.intent

    async def delete(self) -> None:
        await DBMessage.delete_all(self.mxid)
        self.by_mxid.pop(self.mxid, None)
        self.mxid = None
        self.name_set = False
        self.avatar_set = False
        self.relay_user_id = None
        self.topic = None
        self.encrypted = False
        await self.update()

    async def save(self) -> None:
        await self.update()

    @classmethod
    def all_with_room(cls) -> AsyncGenerator[Portal, None]:
        return cls._db_to_portals(super().all_with_room())

    @classmethod
    def find_private_chats_with(cls, other_user: UUID) -> AsyncGenerator[Portal, None]:
        return cls._db_to_portals(super().find_private_chats_with(other_user))

    @classmethod
    async def _db_to_portals(cls, query: Awaitable[list[Portal]]) -> AsyncGenerator[Portal, None]:
        portals = await query
        for index, portal in enumerate(portals):
            try:
                yield cls.by_chat_id[(str(portal.chat_id), portal.receiver)]
            except KeyError:
                await portal._postinit()
                yield portal

    @classmethod
    @async_getter_lock
    async def get_by_mxid(cls, mxid: RoomID, /) -> Portal | None:
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
    @async_getter_lock
    async def get_by_chat_id(
        cls, chat_id: GroupID | UUID, /, *, receiver: str = "", create: bool = False
    ) -> Portal | None:
        if isinstance(chat_id, str):
            receiver = ""
        elif not isinstance(chat_id, UUID):
            raise ValueError(f"Invalid chat ID type {type(chat_id)}")
        elif not receiver:
            raise ValueError("Direct chats must have a receiver")

        try:
            return cls.by_chat_id[(str(chat_id), receiver)]
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
