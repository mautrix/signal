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

from typing import TYPE_CHECKING, Awaitable
from uuid import UUID
import asyncio
import logging

from mausignald import SignaldClient
from mausignald.types import (
    Address,
    ErrorMessage,
    IncomingMessage,
    MessageData,
    OfferMessageType,
    OwnReadReceipt,
    ReceiptMessage,
    ReceiptType,
    StorageChange,
    TypingAction,
    TypingMessage,
    WebsocketConnectionStateChangeEvent,
)
from mautrix.types import EventID, Format, MessageType, TextMessageEventContent
from mautrix.util.logging import TraceLogger

from . import portal as po, puppet as pu, user as u
from .db import Message as DBMessage

if TYPE_CHECKING:
    from .__main__ import SignalBridge

# Typing notifications seem to get resent every 10 seconds and the timeout is around 15 seconds
SIGNAL_TYPING_TIMEOUT = 15000


class SignalHandler(SignaldClient):
    log: TraceLogger = logging.getLogger("mau.signal")
    loop: asyncio.AbstractEventLoop
    data_dir: str
    delete_unknown_accounts: bool
    error_message_events: dict[tuple[UUID, str, int], Awaitable[EventID] | None]

    def __init__(self, bridge: "SignalBridge") -> None:
        super().__init__(bridge.config["signal.socket_path"], loop=bridge.loop)
        self.data_dir = bridge.config["signal.data_dir"]
        self.delete_unknown_accounts = bridge.config["signal.delete_unknown_accounts_on_start"]
        self.error_message_events = {}
        self.add_event_handler(IncomingMessage, self.on_message)
        self.add_event_handler(ErrorMessage, self.on_error_message)
        self.add_event_handler(StorageChange, self.on_storage_change)
        self.add_event_handler(
            WebsocketConnectionStateChangeEvent, self.on_websocket_connection_state_change
        )

    async def on_message(self, evt: IncomingMessage) -> None:
        sender = await pu.Puppet.get_by_address(evt.source, resolve_via=evt.account)
        if not sender:
            self.log.warning(f"Didn't find puppet for incoming message {evt.source}")
            return
        user = await u.User.get_by_username(evt.account)
        # TODO add lots of logging

        if evt.data_message:
            await self.handle_message(user, sender, evt.data_message)
        if evt.typing_message:
            await self.handle_typing(user, sender, evt.typing_message)
        if evt.receipt_message:
            await self.handle_receipt(sender, evt.receipt_message)
        if evt.call_message:
            await self.handle_call_message(user, sender, evt)
        if evt.sync_message:
            if evt.sync_message.read_messages:
                await self.handle_own_receipts(sender, evt.sync_message.read_messages)
            if evt.sync_message.sent:
                if (
                    evt.sync_message.sent.destination
                    and not evt.sync_message.sent.destination.uuid
                ):
                    self.log.warning(
                        "Got sent message without destination UUID "
                        f"{evt.sync_message.sent.destination}"
                    )
                await self.handle_message(
                    user,
                    sender,
                    evt.sync_message.sent.message,
                    addr_override=evt.sync_message.sent.destination,
                )
            if evt.sync_message.contacts or evt.sync_message.contacts_complete:
                self.log.debug("Sync message includes contacts meta, syncing contacts...")
                await user.sync_contacts()
            if evt.sync_message.groups:
                self.log.debug("Sync message includes groups meta, syncing groups...")
                await user.sync_groups()

        try:
            event_id_future = self.error_message_events.pop(
                (sender.uuid, user.username, evt.timestamp)
            )
        except KeyError:
            pass
        else:
            self.log.debug(f"Got previously errored message {evt.timestamp} from {sender.address}")
            event_id = await event_id_future if event_id_future is not None else None
            if event_id is not None:
                portal = await po.Portal.get_by_chat_id(sender.uuid, receiver=user.username)
                if portal and portal.mxid:
                    await sender.intent_for(portal).redact(portal.mxid, event_id)

    async def on_error_message(self, err: ErrorMessage) -> None:
        self.log.warning(
            f"Error reading message from {err.data.sender}/{err.data.sender_device} "
            f"(timestamp: {err.data.timestamp}, content hint: {err.data.content_hint}): "
            f"{err.data.message}"
        )

        if err.data.content_hint == 2:
            return

        sender = await pu.Puppet.get_by_address(
            Address.parse(err.data.sender), resolve_via=err.account
        )
        if not sender:
            return
        user = await u.User.get_by_username(err.account)
        portal = await po.Portal.get_by_chat_id(sender.uuid, receiver=user.username)
        if not portal or not portal.mxid:
            return

        # Add the error to the error_message_events dictionary, then wait for 10 seconds until
        # sending an error. If a success for the timestamp comes in before the 10 seconds is up,
        # don't send the error message.
        error_message_event_key = (sender.uuid, user.username, err.data.timestamp)
        self.error_message_events[error_message_event_key] = None

        await asyncio.sleep(10)

        err_text = (
            "There was an error receiving a message. Check your Signal app for missing messages."
        )
        if error_message_event_key in self.error_message_events:
            fut = self.error_message_events[error_message_event_key] = self.loop.create_future()
            event_id = None
            try:
                event_id = await portal._send_message(
                    intent=sender.intent_for(portal),
                    content=TextMessageEventContent(body=err_text, msgtype=MessageType.NOTICE),
                )
            finally:
                fut.set_result(event_id)

    async def on_storage_change(self, storage_change: StorageChange) -> None:
        self.log.info("Handling StorageChange %s", str(storage_change))
        if user := await u.User.get_by_username(storage_change.account):
            await user.sync()

    @staticmethod
    async def on_websocket_connection_state_change(
        evt: WebsocketConnectionStateChangeEvent,
    ) -> None:
        user = await u.User.get_by_username(evt.account)
        user.on_websocket_connection_state_change(evt)

    async def handle_message(
        self,
        user: u.User,
        sender: pu.Puppet,
        msg: MessageData,
        addr_override: Address | None = None,
    ) -> None:
        try:
            await self._handle_message(user, sender, msg, addr_override)
        except Exception as e:
            await user.handle_auth_failure(e)
            raise

    async def _handle_message(
        self,
        user: u.User,
        sender: pu.Puppet,
        msg: MessageData,
        addr_override: Address | None = None,
    ) -> None:
        if msg.profile_key_update:
            asyncio.create_task(user.sync_contact(sender.address, use_cache=False))
            return
        if msg.group_v2:
            portal = await po.Portal.get_by_chat_id(msg.group_v2.id, create=True)
        elif msg.group:
            portal = await po.Portal.get_by_chat_id(msg.group.group_id, create=True)
        else:
            if addr_override and not addr_override.uuid:
                target = await pu.Puppet.get_by_address(addr_override, resolve_via=user.username)
                if not target:
                    self.log.warning(
                        f"Didn't find puppet for recipient of incoming message {addr_override}"
                    )
                    return
            portal = await po.Portal.get_by_chat_id(
                addr_override.uuid if addr_override else sender.uuid,
                receiver=user.username,
                create=True,
            )
            if addr_override and not sender.is_real_user:
                portal.log.debug(
                    f"Ignoring own message {msg.timestamp} as user doesn't have double puppeting "
                    "enabled"
                )
                return
        assert portal

        # Handle the user being removed from the group.
        if msg.group_v2 and msg.group_v2.removed:
            if portal.mxid:
                await portal.handle_signal_kicked(user, sender)
            return

        if not portal.mxid:
            if not msg.is_message and not msg.group_v2:
                user.log.debug(
                    f"Ignoring message {msg.timestamp},"
                    " probably not bridgeable as there's no portal yet"
                )
                return
            await portal.create_matrix_room(
                user, msg.group_v2 or msg.group or addr_override or sender.address
            )
            if not portal.mxid:
                user.log.warning(
                    f"Failed to create room for incoming message {msg.timestamp}, dropping message"
                )
                return
        elif (
            msg.group_v2
            and msg.group_v2.group_change
            and msg.group_v2.revision == portal.revision + 1
        ):
            self.log.debug(
                f"Got update for {msg.group_v2.id} ({portal.revision} -> "
                f"{msg.group_v2.revision}), applying diff"
            )
            await portal.handle_signal_group_change(msg.group_v2.group_change, user)
        elif msg.group_v2 and msg.group_v2.revision > portal.revision:
            self.log.debug(
                f"Got update with multiple revisions for {msg.group_v2.id} ({portal.revision} -> "
                f"{msg.group_v2.revision}), resyncing info"
            )
            await portal.update_info(user, msg.group_v2)
        if msg.expires_in_seconds is not None and (msg.is_message or msg.is_expiration_update):
            await portal.update_expires_in_seconds(sender, msg.expires_in_seconds)
        if msg.reaction:
            await portal.handle_signal_reaction(sender, msg.reaction, msg.timestamp)
        if msg.is_message:
            await portal.handle_signal_message(user, sender, msg)
        if msg.group and msg.group.type == "UPDATE":
            await portal.update_info(user, msg.group)
        if msg.remote_delete:
            await portal.handle_signal_delete(sender, msg.remote_delete.target_sent_timestamp)

    @staticmethod
    async def handle_call_message(user: u.User, sender: pu.Puppet, msg: IncomingMessage) -> None:
        assert msg.call_message
        portal = await po.Portal.get_by_chat_id(sender.uuid, receiver=user.username, create=True)
        if not portal.mxid:
            # FIXME
            # await portal.create_matrix_room(
            #     user, (msg.group_v2 or msg.group or addr_override or sender.address)
            # )
            # if not portal.mxid:
            #     user.log.debug(
            #         f"Failed to create room for incoming message {msg.timestamp},"
            #         " dropping message"
            #     )
            return

        msg_prefix_html = f'<a href="https://matrix.to/#/{sender.mxid}">{sender.name}</a>'
        msg_prefix_text = f"{sender.name}"
        msg_suffix = ""
        if msg.call_message.offer_message:
            call_type = {
                OfferMessageType.AUDIO_CALL: "voice call",
                OfferMessageType.VIDEO_CALL: "video call",
            }.get(msg.call_message.offer_message.type, "call")
            msg_suffix = (
                f" started a {call_type} on Signal. Use the native app to answer the call."
            )
            msg_type = MessageType.TEXT
        elif msg.call_message.hangup_message:
            msg_suffix = " ended a call on Signal."
            msg_type = MessageType.NOTICE
        else:
            portal.log.debug(f"Unhandled call message. Likely an ICE message. {msg.call_message}")
            return

        await portal._send_message(
            intent=sender.intent_for(portal),
            content=TextMessageEventContent(
                format=Format.HTML,
                formatted_body=msg_prefix_html + msg_suffix,
                body=msg_prefix_text + msg_suffix,
                msgtype=msg_type,
            ),
        )

    @staticmethod
    async def handle_own_receipts(sender: pu.Puppet, receipts: list[OwnReadReceipt]) -> None:
        for receipt in receipts:
            puppet = await pu.Puppet.get_by_address(receipt.sender, create=False)
            if not puppet:
                continue
            message = await DBMessage.find_by_sender_timestamp(puppet.uuid, receipt.timestamp)
            if not message:
                continue
            portal = await po.Portal.get_by_mxid(message.mx_room)
            if not portal or (portal.is_direct and not sender.is_real_user):
                continue
            await sender.intent_for(portal).mark_read(portal.mxid, message.mxid)

    @staticmethod
    async def handle_typing(user: u.User, sender: pu.Puppet, typing: TypingMessage) -> None:
        if typing.group_id:
            portal = await po.Portal.get_by_chat_id(typing.group_id)
        else:
            portal = await po.Portal.get_by_chat_id(sender.uuid, receiver=user.username)
        if not portal or not portal.mxid:
            return
        is_typing = typing.action == TypingAction.STARTED
        await sender.intent_for(portal).set_typing(
            portal.mxid, is_typing, ignore_cache=True, timeout=SIGNAL_TYPING_TIMEOUT
        )

    @staticmethod
    async def handle_receipt(sender: pu.Puppet, receipt: ReceiptMessage) -> None:
        if receipt.type != ReceiptType.READ:
            return
        messages = await DBMessage.find_by_timestamps(receipt.timestamps)
        for message in messages:
            portal = await po.Portal.get_by_mxid(message.mx_room)
            await sender.intent_for(portal).mark_read(portal.mxid, message.mxid)

    async def start(self) -> None:
        await self.connect()
        known_usernames = set()
        async for user in u.User.all_logged_in():
            # TODO report errors to user?
            known_usernames.add(user.username)
            if await self.subscribe(user.username):
                self.log.info(
                    f"Successfully subscribed {user.username}, running sync in background"
                )
                asyncio.create_task(user.sync())
        if self.delete_unknown_accounts:
            self.log.debug("Checking for unknown accounts to delete")
            for account in await self.list_accounts():
                if account.account_id not in known_usernames:
                    self.log.warning(f"Unknown account ID {account.account_id}, deleting...")
                    await self.delete_account(account.account_id)
            else:
                self.log.debug("No unknown accounts found")

    async def stop(self) -> None:
        await self.disconnect()
