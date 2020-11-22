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
from typing import (Dict, Tuple, Optional, List, Deque, Any, Union, AsyncGenerator, Awaitable,
                    TYPE_CHECKING, cast)
from collections import deque
from uuid import UUID, uuid4
import mimetypes
import hashlib
import asyncio
import os.path
import time
import os

from mausignald.types import (Address, MessageData, Reaction, Quote, Group, Contact, Profile,
                              Attachment, GroupID)
from mautrix.appservice import AppService, IntentAPI
from mautrix.bridge import BasePortal
from mautrix.types import (EventID, MessageEventContent, RoomID, EventType, MessageType,
                           TextMessageEventContent, MessageEvent, EncryptedEvent, ContentURI,
                           MediaMessageEventContent, ImageInfo, VideoInfo, FileInfo, AudioInfo)
from mautrix.errors import MatrixError, MForbidden

from .db import Portal as DBPortal, Message as DBMessage, Reaction as DBReaction
from .config import Config
from . import user as u, puppet as p, matrix as m, signal as s

if TYPE_CHECKING:
    from .__main__ import SignalBridge

try:
    from mautrix.crypto.attachments import encrypt_attachment, decrypt_attachment
except ImportError:
    encrypt_attachment = decrypt_attachment = None

try:
    import magic
except ImportError:
    magic = None

StateBridge = EventType.find("m.bridge", EventType.Class.STATE)
StateHalfShotBridge = EventType.find("uk.half-shot.bridge", EventType.Class.STATE)
ChatInfo = Union[Group, Contact, Profile, Address]


class Portal(DBPortal, BasePortal):
    by_mxid: Dict[RoomID, 'Portal'] = {}
    by_chat_id: Dict[Tuple[str, str], 'Portal'] = {}
    config: Config
    matrix: 'm.MatrixHandler'
    signal: 's.SignalHandler'
    az: AppService
    private_chat_portal_meta: bool

    _main_intent: Optional[IntentAPI]
    _create_room_lock: asyncio.Lock
    _msgts_dedup: Deque[Tuple[Address, int]]
    _reaction_dedup: Deque[Tuple[Address, int, str]]
    _reaction_lock: asyncio.Lock

    def __init__(self, chat_id: Union[GroupID, Address], receiver: str, mxid: Optional[RoomID] = None,
                 name: Optional[str] = None, avatar_hash: Optional[str] = None,
                 avatar_url: Optional[ContentURI] = None, encrypted: bool = False) -> None:
        super().__init__(chat_id, receiver, mxid, name, avatar_hash, avatar_url, encrypted)
        self._create_room_lock = asyncio.Lock()
        self.log = self.log.getChild(self.chat_id_str)
        self._main_intent = None
        self._msgts_dedup = deque(maxlen=100)
        self._reaction_dedup = deque(maxlen=100)
        self._last_participant_update = set()
        self._reaction_lock = asyncio.Lock()

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
            raise ValueError("handle_uuid_receive can only be used for private chat portals with "
                             "a phone number chat_id")
        del self.by_chat_id[(self.chat_id_str, self.receiver)]
        self.chat_id = Address(uuid=uuid)
        self.by_chat_id[(self.chat_id_str, self.receiver)] = self

    @classmethod
    def init_cls(cls, bridge: 'SignalBridge') -> None:
        cls.config = bridge.config
        cls.matrix = bridge.matrix
        cls.signal = bridge.signal
        cls.az = bridge.az
        cls.loop = bridge.loop
        cls.bridge = bridge
        cls.private_chat_portal_meta = cls.config["bridge.private_chat_portal_meta"]

    # region Misc

    async def _send_delivery_receipt(self, event_id: EventID) -> None:
        if event_id and self.config["bridge.delivery_receipts"]:
            try:
                await self.az.intent.mark_read(self.mxid, event_id)
            except Exception:
                self.log.exception("Failed to send delivery receipt for %s", event_id)

    async def _upsert_reaction(self, existing: DBReaction, intent: IntentAPI, mxid: EventID,
                               sender: Union['p.Puppet', 'u.User'], message: DBMessage, emoji: str
                               ) -> None:
        if existing:
            self.log.debug(f"_upsert_reaction redacting {existing.mxid} and inserting {mxid}"
                           f" (message: {message.mxid})")
            try:
                await intent.redact(existing.mx_room, existing.mxid)
            except MForbidden:
                self.log.debug("Unexpected MForbidden redacting reaction", exc_info=True)
            await existing.edit(emoji=emoji, mxid=mxid, mx_room=message.mx_room)
        else:
            self.log.debug(f"_upsert_reaction inserting {mxid} (message: {message.mxid})")
            await DBReaction(mxid=mxid, mx_room=message.mx_room, emoji=emoji,
                             signal_chat_id=self.chat_id, signal_receiver=self.receiver,
                             msg_author=message.sender, msg_timestamp=message.timestamp,
                             author=sender.address).insert()

    # endregion
    # region Matrix event handling

    @staticmethod
    def _make_attachment(message: MediaMessageEventContent, path: str) -> Attachment:
        attachment = Attachment(custom_filename=message.body, content_type=message.info.mimetype,
                                outgoing_filename=path)
        info = message.info
        attachment.width = info.get("w", info.get("width", 0))
        attachment.height = info.get("h", info.get("height", 0))
        attachment.voice_note = message.msgtype == MessageType.AUDIO
        return attachment

    async def _download_matrix_media(self, message: MediaMessageEventContent) -> str:
        if message.file:
            data = await self.main_intent.download_media(message.file.url)
            data = decrypt_attachment(data, message.file.key.key,
                                      message.file.hashes.get("sha256"), message.file.iv)
        else:
            data = await self.main_intent.download_media(message.url)

        filename = f"mautrix-signal-{str(uuid4())}"
        attachment_dir = self.config["signal.outgoing_attachment_dir"]
        path = os.path.join(attachment_dir, filename)
        with open(path, "wb") as file:
            file.write(data)

        # The bridge and signald can share files but have different filepaths. This can happen in
        # a Docker deployment when signald and this bridge are in different containers. In this
        # case, convert the file path from one context to another
        signald_relative_attachment_dir = self.config["signal.incoming_attachment_dir"]
        if signald_relative_attachment_dir is None:
            # Return the path in the context of the bridge
            return path

        self.log.debug(f"Changing attachment directory from {attachment_dir} to {signald_relative_attachment_dir}")
        # Return the path in the context of signald
        return os.path.join(signald_relative_attachment_dir, filename)

    async def handle_matrix_message(self, sender: 'u.User', message: MessageEventContent,
                                    event_id: EventID) -> None:
        if ((message.get(self.bridge.real_user_content_key, False)
             and await p.Puppet.get_by_custom_mxid(sender.mxid))):
            self.log.debug(f"Ignoring puppet-sent message by confirmed puppet user {sender.mxid}")
            return
        request_id = int(time.time() * 1000)
        self._msgts_dedup.appendleft((sender.address, request_id))

        quote = None
        if message.get_reply_to():
            reply = await DBMessage.get_by_mxid(message.get_reply_to(), self.mxid)
            # TODO include actual text? either store in db or fetch event from homeserver
            if reply is not None:
                quote = Quote(id=reply.timestamp, author=reply.sender, text="")

        text = message.body
        attachments: Optional[List[Attachment]] = None
        attachment_path: Optional[str] = None
        if message.msgtype == MessageType.EMOTE:
            text = f"/me {text}"
        elif message.msgtype.is_media:
            attachment_path = await self._download_matrix_media(message)
            attachment = self._make_attachment(message, attachment_path)
            attachments = [attachment]
            text = None
            self.log.trace("Formed outgoing attachment %s", attachment)
        await self.signal.send(username=sender.username, recipient=self.chat_id, body=text,
                               quote=quote, attachments=attachments, timestamp=request_id)
        msg = DBMessage(mxid=event_id, mx_room=self.mxid, sender=sender.address, timestamp=request_id,
                        signal_chat_id=self.chat_id, signal_receiver=self.receiver)
        await msg.insert()
        await self._send_delivery_receipt(event_id)
        self.log.debug(f"Handled Matrix message {event_id} -> {request_id}")
        if attachment_path and self.config["signal.remove_file_after_handling"]:
            try:
                os.remove(attachment_path)
            except FileNotFoundError:
                pass

    async def handle_matrix_reaction(self, sender: 'u.User', event_id: EventID,
                                     reacting_to: EventID, emoji: str) -> None:
        # Signal doesn't seem to use variation selectors at all
        emoji = emoji.rstrip("\ufe0f")

        message = await DBMessage.get_by_mxid(reacting_to, self.mxid)
        if not message:
            self.log.debug(f"Ignoring reaction to unknown event {reacting_to}")
            return

        existing = await DBReaction.get_by_signal_id(self.chat_id, self.receiver, message.sender,
                                                     message.timestamp, sender.address)
        if existing and existing.emoji == emoji:
            return

        dedup_id = (message.sender, message.timestamp, emoji)
        self._reaction_dedup.appendleft(dedup_id)
        async with self._reaction_lock:
            reaction = Reaction(emoji=emoji, remove=False,
                                target_author=message.sender,
                                target_sent_timestamp=message.timestamp)
            await self.signal.react(username=sender.username, recipient=self.chat_id,
                                    reaction=reaction)
            await self._upsert_reaction(existing, self.main_intent, event_id, sender, message,
                                        emoji)
            self.log.trace(f"{sender.mxid} reacted to {message.timestamp} with {emoji}")
        await self._send_delivery_receipt(event_id)

    async def handle_matrix_redaction(self, sender: 'u.User', event_id: EventID,
                                      redaction_event_id: EventID) -> None:
        if not self.mxid:
            return

        reaction = await DBReaction.get_by_mxid(event_id, self.mxid)
        if reaction:
            try:
                await reaction.delete()
                remove_reaction = Reaction(emoji=reaction.emoji, remove=True,
                                           target_author=reaction.msg_author,
                                           target_sent_timestamp=reaction.msg_timestamp)
                await self.signal.react(username=sender.username, recipient=self.chat_id,
                                        reaction=remove_reaction)
                await self._send_delivery_receipt(redaction_event_id)
                self.log.trace(f"Removed {reaction} after Matrix redaction")
            except Exception:
                self.log.exception("Removing reaction failed")

    async def handle_matrix_leave(self, user: 'u.User') -> None:
        if self.is_direct:
            self.log.info(f"{user.mxid} left private chat portal with {self.chat_id}")
            if user.username == self.receiver:
                self.log.info(f"{user.mxid} was the recipient of this portal. "
                              "Cleaning up and deleting...")
                await self.cleanup_and_delete()
        else:
            self.log.debug(f"{user.mxid} left portal to {self.chat_id}")
            # TODO cleanup if empty

    # endregion
    # region Signal event handling

    @staticmethod
    async def _resolve_address(address: Address) -> Address:
        puppet = await p.Puppet.get_by_address(address, create=False)
        return puppet.address

    async def _find_quote_event_id(self, quote: Optional[Quote]
                                   ) -> Optional[Union[MessageEvent, EventID]]:
        if not quote:
            return None

        author_address = await self._resolve_address(quote.author)
        reply_msg = await DBMessage.get_by_signal_id(author_address, quote.id,
                                                     self.chat_id, self.receiver)
        if not reply_msg:
            return None
        try:
            evt = await self.main_intent.get_event(self.mxid, reply_msg.mxid)
            if isinstance(evt, EncryptedEvent):
                return await self.matrix.e2ee.decrypt(evt, wait_session_timeout=0)
            return evt
        except MatrixError:
            return reply_msg.mxid

    async def handle_signal_message(self, source: 'u.User', sender: 'p.Puppet',
                                    message: MessageData) -> None:
        if (sender.address, message.timestamp) in self._msgts_dedup:
            self.log.debug(f"Ignoring message {message.timestamp} by {sender.uuid}"
                           " as it was already handled (message.timestamp in dedup queue)")
            await self.signal.send_receipt(source.username, sender.address,
                                           timestamps=[message.timestamp])
            return
        old_message = await DBMessage.get_by_signal_id(sender.address, message.timestamp,
                                                       self.chat_id, self.receiver)
        if old_message is not None:
            self.log.debug(f"Ignoring message {message.timestamp} by {sender.uuid}"
                           " as it was already handled (message.id found in database)")
            await self.signal.send_receipt(source.username, sender.address,
                                           timestamps=[message.timestamp])
            return
        self.log.debug(f"Started handling message {message.timestamp} by {sender.uuid}")
        self.log.trace(f"Message content: {message}")
        self._msgts_dedup.appendleft((sender.address, message.timestamp))
        intent = sender.intent_for(self)
        await intent.set_typing(self.mxid, False)
        event_id = None
        reply_to = await self._find_quote_event_id(message.quote)

        if message.sticker:
            if not message.sticker.attachment.incoming_filename:
                self.log.warning("Failed to bridge sticker, no incoming filename: %s",
                                 message.sticker.attachment)
            else:
                content = await self._handle_signal_attachment(intent, message.sticker.attachment)
                if reply_to:
                    content.set_reply(reply_to)
                    reply_to = None
                event_id = await self._send_message(intent, content, timestamp=message.timestamp,
                                                    event_type=EventType.STICKER)

        for attachment in message.attachments:
            if not attachment.incoming_filename:
                self.log.warning("Failed to bridge attachment, no incoming filename: %s",
                                 attachment)
                continue
            content = await self._handle_signal_attachment(intent, attachment)
            if reply_to and not message.body:
                # If there's no text, set the first image as the reply
                content.set_reply(reply_to)
                reply_to = None
            event_id = await self._send_message(intent, content, timestamp=message.timestamp)

        if message.body:
            content = TextMessageEventContent(msgtype=MessageType.TEXT, body=message.body)
            if reply_to:
                content.set_reply(reply_to)
            event_id = await self._send_message(intent, content, timestamp=message.timestamp)

        if event_id:
            msg = DBMessage(mxid=event_id, mx_room=self.mxid,
                            sender=sender.address, timestamp=message.timestamp,
                            signal_chat_id=self.chat_id, signal_receiver=self.receiver)
            await msg.insert()
            await self.signal.send_receipt(source.username, sender.address,
                                           timestamps=[message.timestamp])
            await self._send_delivery_receipt(event_id)
            self.log.debug(f"Handled Signal message {message.timestamp} -> {event_id}")
        else:
            self.log.debug(f"Didn't get event ID for {message.timestamp}")

    @staticmethod
    def _make_media_content(attachment: Attachment) -> MediaMessageEventContent:
        if attachment.content_type.startswith("image/"):
            msgtype = MessageType.IMAGE
            info = ImageInfo(mimetype=attachment.content_type,
                             width=attachment.width, height=attachment.height)
        elif attachment.content_type.startswith("video/"):
            msgtype = MessageType.VIDEO
            info = VideoInfo(mimetype=attachment.content_type,
                             width=attachment.width, height=attachment.height)
        elif attachment.voice_note or attachment.content_type.startswith("audio/"):
            msgtype = MessageType.AUDIO
            info = AudioInfo(mimetype=attachment.content_type)
        else:
            msgtype = MessageType.FILE
            info = FileInfo(mimetype=attachment.content_type)
        if not attachment.custom_filename:
            ext = mimetypes.guess_extension(attachment.content_type) or ""
            attachment.custom_filename = attachment.id + ext
        return MediaMessageEventContent(msgtype=msgtype, info=info,
                                        body=attachment.custom_filename)

    async def _handle_signal_attachment(self, intent: IntentAPI, attachment: Attachment
                                        ) -> MediaMessageEventContent:
        self.log.trace(f"Reuploading attachment {attachment}")
        if not attachment.content_type:
            attachment.content_type = (magic.from_file(attachment.incoming_filename, mime=True)
                                       if magic is not None else "application/octet-stream")

        content = self._make_media_content(attachment)

        # The bridge and signald can share files but have different filepaths. This can happen in
        # a Docker deployment when signald and this bridge are in different containers. In this
        # case, convert the file path from one context to another
        incoming_attachment_dir = self.config["signal.incoming_attachment_dir"]
        if incoming_attachment_dir is None:
            path = attachment.incoming_filename
        else:
            filename = os.path.basename(attachment.incoming_filename)
            path = os.path.join(self.config["signal.outgoing_attachment_dir"], filename)
            self.log.debug(f"Changing attachment from {attachment.incoming_filename} to {path}")

        with open(path, "rb") as file:
            data = file.read()
        if self.config["signal.remove_file_after_handling"]:
            os.remove(path)

        upload_mime_type = attachment.content_type
        if self.encrypted and encrypt_attachment:
            data, content.file = encrypt_attachment(data)
            upload_mime_type = "application/octet-stream"

        content.url = await intent.upload_media(data, mime_type=upload_mime_type,
                                                filename=attachment.id)
        if content.file:
            content.file.url = content.url
            content.url = None
        return content

    async def handle_signal_reaction(self, sender: 'p.Puppet', reaction: Reaction) -> None:
        author_address = await self._resolve_address(reaction.target_author)
        target_id = reaction.target_sent_timestamp
        async with self._reaction_lock:
            dedup_id = (author_address, target_id, reaction.emoji)
            if dedup_id in self._reaction_dedup:
                return
            self._reaction_dedup.appendleft(dedup_id)

        existing = await DBReaction.get_by_signal_id(self.chat_id, self.receiver,
                                                     author_address, target_id, sender.address)

        if reaction.remove:
            if existing:
                try:
                    await sender.intent_for(self).redact(existing.mx_room, existing.mxid)
                except MForbidden:
                    await self.main_intent.redact(existing.mx_room, existing.mxid)
                await existing.delete()
                self.log.trace(f"Removed {existing} after Signal removal")
            return
        elif existing and existing.emoji == reaction.emoji:
            return

        message = await DBMessage.get_by_signal_id(author_address, target_id,
                                                   self.chat_id, self.receiver)
        if not message:
            self.log.debug(f"Ignoring reaction to unknown message {target_id}")
            return

        intent = sender.intent_for(self)
        # TODO add variation selectors to emoji before sending to Matrix
        mxid = await intent.react(message.mx_room, message.mxid, reaction.emoji)
        self.log.debug(f"{sender.address} reacted to {message.mxid} -> {mxid}")
        await self._upsert_reaction(existing, intent, mxid, sender, message, reaction.emoji)

    # endregion
    # region Updating portal info

    async def update_info(self, info: ChatInfo) -> None:
        if self.is_direct:
            if not isinstance(info, (Contact, Profile, Address)):
                raise ValueError(f"Unexpected type for direct chat update_info: {type(info)}")
            if not self.name:
                puppet = await p.Puppet.get_by_address(self.chat_id)
                if not puppet.name:
                    await puppet.update_info(info)
                self.name = puppet.name
            return

        if not isinstance(info, Group):
            raise ValueError(f"Unexpected type for group update_info: {type(info)}")
        changed = await self._update_name(info.name)
        changed = await self._update_avatar()
        await self._update_participants(info.members)
        if changed:
            await self.update_bridge_info()
            await self.update()

    async def update_puppet_name(self, name: str) -> None:
        if not self.encrypted and not self.private_chat_portal_meta:
            return

        changed = await self._update_name(name)

        if changed:
            await self.update_bridge_info()
            await self.update()

    async def _update_name(self, name: str) -> bool:
        if self.name != name:
            self.name = name
            if self.mxid:
                await self.main_intent.set_room_name(self.mxid, name)
            return True
        return False

    async def _update_avatar(self) -> bool:
        if self.is_direct:
            return False
        path = os.path.join(self.config["signal.avatar_dir"], f"group-{self.chat_id}")
        try:
            with open(path, "rb") as file:
                data = file.read()
        except FileNotFoundError:
            return False
        new_hash = hashlib.sha256(data).hexdigest()
        if self.avatar_hash and new_hash == self.avatar_hash:
            return False
        mxc = await self.main_intent.upload_media(data)
        if self.mxid:
            await self.main_intent.set_room_avatar(self.mxid, mxc)
        self.avatar_url = mxc
        self.avatar_hash = new_hash
        return True

    async def _update_participants(self, participants: List[Address]) -> None:
        if not self.mxid or not participants:
            return

        for address in participants:
            puppet = await p.Puppet.get_by_address(address)
            if not puppet.name:
                await puppet._update_name(None)
            await puppet.intent_for(self).ensure_joined(self.mxid)

    # endregion
    # region Bridge info state event

    @property
    def bridge_info_state_key(self) -> str:
        return f"net.maunium.signal://signal/{self.chat_id}"

    @property
    def bridge_info(self) -> Dict[str, Any]:
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
            }
        }

    async def update_bridge_info(self) -> None:
        if not self.mxid:
            self.log.debug("Not updating bridge info: no Matrix room created")
            return
        try:
            self.log.debug("Updating bridge info...")
            await self.main_intent.send_state_event(self.mxid, StateBridge,
                                                    self.bridge_info, self.bridge_info_state_key)
            # TODO remove this once https://github.com/matrix-org/matrix-doc/pull/2346 is in spec
            await self.main_intent.send_state_event(self.mxid, StateHalfShotBridge,
                                                    self.bridge_info, self.bridge_info_state_key)
        except Exception:
            self.log.warning("Failed to update bridge info", exc_info=True)

    # endregion
    # region Creating Matrix rooms

    async def update_matrix_room(self, source: 'u.User', info: ChatInfo) -> None:
        if not self.is_direct and not isinstance(info, Group):
            raise ValueError(f"Unexpected type for updating group portal: {type(info)}")
        elif self.is_direct and not isinstance(info, (Contact, Profile, Address)):
            raise ValueError(f"Unexpected type for updating direct chat portal: {type(info)}")
        try:
            await self._update_matrix_room(source, info)
        except Exception:
            self.log.exception("Failed to update portal")

    async def create_matrix_room(self, source: 'u.User', info: ChatInfo) -> Optional[RoomID]:
        if not self.is_direct and not isinstance(info, Group):
            raise ValueError(f"Unexpected type for creating group portal: {type(info)}")
        elif self.is_direct and not isinstance(info, (Contact, Profile, Address)):
            raise ValueError(f"Unexpected type for creating direct chat portal: {type(info)}")
        if isinstance(info, Group):
            groups = await self.signal.list_groups(source.username)
            info = next((g for g in groups if g.group_id == info.group_id), info)
        if self.mxid:
            await self.update_matrix_room(source, info)
            return self.mxid
        async with self._create_room_lock:
            return await self._create_matrix_room(source, info)

    async def _update_matrix_room(self, source: 'u.User', info: ChatInfo) -> None:
        await self.main_intent.invite_user(self.mxid, source.mxid, check_cache=True)
        puppet = await p.Puppet.get_by_custom_mxid(source.mxid)
        if puppet:
            did_join = await puppet.intent.ensure_joined(self.mxid)
            if did_join and self.is_direct:
                await source.update_direct_chats({self.main_intent.mxid: [self.mxid]})

        await self.update_info(info)

        # TODO
        # up = DBUserPortal.get(source.fbid, self.fbid, self.fb_receiver)
        # if not up:
        #     in_community = await source._community_helper.add_room(source._community_id, self.mxid)
        #     DBUserPortal(user=source.fbid, portal=self.fbid, portal_receiver=self.fb_receiver,
        #                  in_community=in_community).insert()
        # elif not up.in_community:
        #     in_community = await source._community_helper.add_room(source._community_id, self.mxid)
        #     up.edit(in_community=in_community)

    async def _create_matrix_room(self, source: 'u.User', info: ChatInfo) -> Optional[RoomID]:
        if self.mxid:
            await self._update_matrix_room(source, info)
            return self.mxid
        await self.update_info(info)
        self.log.debug("Creating Matrix room")
        name: Optional[str] = None
        initial_state = [{
            "type": str(StateBridge),
            "state_key": self.bridge_info_state_key,
            "content": self.bridge_info,
        }, {
            # TODO remove this once https://github.com/matrix-org/matrix-doc/pull/2346 is in spec
            "type": str(StateHalfShotBridge),
            "state_key": self.bridge_info_state_key,
            "content": self.bridge_info,
        }]
        invites = [source.mxid]
        if self.config["bridge.encryption.default"] and self.matrix.e2ee:
            self.encrypted = True
            initial_state.append({
                "type": str(EventType.ROOM_ENCRYPTION),
                "content": {"algorithm": "m.megolm.v1.aes-sha2"},
            })
            if self.is_direct:
                invites.append(self.az.bot_mxid)
        if self.is_direct and source.address == self.chat_id:
            name = self.name = "Signal Note to Self"
        elif self.encrypted or self.private_chat_portal_meta or not self.is_direct:
            name = self.name
        if self.avatar_url:
            initial_state.append({
                "type": str(EventType.ROOM_AVATAR),
                "content": {"url": self.avatar_url},
            })
        if self.config["appservice.community_id"]:
            initial_state.append({
                "type": "m.room.related_groups",
                "content": {"groups": [self.config["appservice.community_id"]]},
            })
        if self.is_direct:
            initial_state.append({
                "type": str(EventType.ROOM_POWER_LEVELS),
                "content": {"users": {self.main_intent.mxid: 100},
                            "events": {"m.room.avatar": 0, "m.room.name": 0}}
            })

        self.mxid = await self.main_intent.create_room(name=name, is_direct=self.is_direct,
                                                       initial_state=initial_state,
                                                       invitees=invites)
        if not self.mxid:
            raise Exception("Failed to create room: no mxid returned")

        if self.encrypted and self.matrix.e2ee and self.is_direct:
            try:
                await self.az.intent.ensure_joined(self.mxid)
            except Exception:
                self.log.warning("Failed to add bridge bot "
                                 f"to new private chat {self.mxid}")

        await self.update()
        self.log.debug(f"Matrix room created: {self.mxid}")
        self.by_mxid[self.mxid] = self
        if not self.is_direct:
            await self._update_participants(info.members)
        else:
            puppet = await p.Puppet.get_by_custom_mxid(source.mxid)
            if puppet:
                try:
                    await puppet.intent.join_room_by_id(self.mxid)
                    await source.update_direct_chats({self.main_intent.mxid: [self.mxid]})
                except MatrixError:
                    self.log.debug("Failed to join custom puppet into newly created portal",
                                   exc_info=True)

        # TODO
        # in_community = await source._community_helper.add_room(source._community_id, self.mxid)
        # DBUserPortal(user=source.fbid, portal=self.fbid, portal_receiver=self.fb_receiver,
        #              in_community=in_community).upsert()

        return self.mxid

    # endregion
    # region Database getters

    async def _postinit(self) -> None:
        self.by_chat_id[(self.chat_id, self.receiver)] = self
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
    def all_with_room(cls) -> AsyncGenerator['Portal', None]:
        return cls._db_to_portals(super().all_with_room())

    @classmethod
    def find_private_chats_with(cls, other_user: Address) -> AsyncGenerator['Portal', None]:
        return cls._db_to_portals(super().find_private_chats_with(other_user))

    @classmethod
    async def _db_to_portals(cls, query: Awaitable[List['Portal']]
                             ) -> AsyncGenerator['Portal', None]:
        portals = await query
        for index, portal in enumerate(portals):
            try:
                yield cls.by_chat_id[(portal.chat_id_str, portal.receiver)]
            except KeyError:
                await portal._postinit()
                yield portal

    @classmethod
    async def get_by_mxid(cls, mxid: RoomID) -> Optional['Portal']:
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
    async def get_by_chat_id(cls, chat_id: Union[GroupID, Address], receiver: str = "",
                             create: bool = False) -> Optional['Portal']:
        if isinstance(chat_id, str):
            receiver = ""
        elif not isinstance(chat_id, Address):
            raise ValueError(f"Invalid chat ID type {type(chat_id)}")
        elif not receiver:
            raise ValueError("Direct chats must have a receiver")
        try:
            best_id = chat_id.best_identifier if isinstance(chat_id, Address) else chat_id
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
