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
from typing import Optional, List, TYPE_CHECKING
import asyncio
import logging

from mausignald import SignaldClient
from mausignald.types import (Message, MessageData, Address, TypingNotification, TypingAction,
                              OwnReadReceipt, Receipt, ReceiptType, ListenEvent)
from mautrix.util.logging import TraceLogger

from .db import Message as DBMessage
from . import user as u, portal as po, puppet as pu

if TYPE_CHECKING:
    from .__main__ import SignalBridge

# Typing notifications seem to get resent every 10 seconds and the timeout is around 15 seconds
SIGNAL_TYPING_TIMEOUT = 15000


class SignalHandler(SignaldClient):
    log: TraceLogger = logging.getLogger("mau.signal")
    loop: asyncio.AbstractEventLoop

    def __init__(self, bridge: 'SignalBridge') -> None:
        super().__init__(bridge.config["signal.socket_path"], loop=bridge.loop)
        self.add_event_handler(Message, self.on_message)
        self.add_event_handler(ListenEvent, self.on_listen)

    async def on_message(self, evt: Message) -> None:
        sender = await pu.Puppet.get_by_address(evt.source)
        user = await u.User.get_by_username(evt.username)
        # TODO add lots of logging

        if evt.data_message:
            await self.handle_message(user, sender, evt.data_message)
        if evt.typing:
            await self.handle_typing(user, sender, evt.typing)
        if evt.receipt:
            await self.handle_receipt(sender, evt.receipt)
        if evt.sync_message:
            if evt.sync_message.read_messages:
                await self.handle_own_receipts(sender, evt.sync_message.read_messages)
            if evt.sync_message.contacts:
                # Contact list update?
                pass
            if evt.sync_message.sent:
                await self.handle_message(user, sender, evt.sync_message.sent.message,
                                          addr_override=evt.sync_message.sent.destination)
            if evt.sync_message.typing:
                # Typing notification from own device
                pass

    @staticmethod
    async def on_listen(evt: ListenEvent) -> None:
        user = await u.User.get_by_username(evt.username)
        user.on_listen(evt)

    async def handle_message(self, user: 'u.User', sender: 'pu.Puppet', msg: MessageData,
                             addr_override: Optional[Address] = None) -> None:
        group_v2_info = None
        if msg.group_v2:
            portal = await po.Portal.get_by_chat_id(msg.group_v2.id, create=True)
            if not portal.mxid:
                group_v2_info = await self.get_group(user.username, msg.group_v2.id,
                                                     msg.group_v2.revision or -1)
                if not group_v2_info:
                    user.log.debug(f"Dropping message in unknown v2 group {msg.group_v2.id}")
                    return
        elif msg.group:
            portal = await po.Portal.get_by_chat_id(msg.group.group_id, create=True)
        else:
            portal = await po.Portal.get_by_chat_id(addr_override or sender.address,
                                                    receiver=user.username, create=True)
            if addr_override and not sender.is_real_user:
                portal.log.debug(f"Ignoring own message {msg.timestamp} as user doesn't have"
                                 " double puppeting enabled")
                return
        if not portal.mxid:
            await portal.create_matrix_room(user, (group_v2_info or msg.group
                                                   or addr_override or sender.address))
        if msg.reaction:
            await portal.handle_signal_reaction(sender, msg.reaction)
        if msg.body or msg.attachments or msg.sticker:
            await portal.handle_signal_message(user, sender, msg)
        if msg.group and msg.group.type == "UPDATE":
            await portal.update_info(user, msg.group)
        if msg.remote_delete:
            await portal.handle_signal_delete(sender, msg.remote_delete.target_sent_timestamp)

    @staticmethod
    async def handle_own_receipts(sender: 'pu.Puppet', receipts: List[OwnReadReceipt]) -> None:
        for receipt in receipts:
            puppet = await pu.Puppet.get_by_address(receipt.sender, create=False)
            if not puppet:
                continue
            message = await DBMessage.find_by_sender_timestamp(puppet.address, receipt.timestamp)
            if not message:
                continue
            portal = await po.Portal.get_by_mxid(message.mx_room)
            if not portal or (portal.is_direct and not sender.is_real_user):
                continue
            await sender.intent_for(portal).mark_read(portal.mxid, message.mxid)

    @staticmethod
    async def handle_typing(user: 'u.User', sender: 'pu.Puppet',
                            typing: TypingNotification) -> None:
        if typing.group_id:
            portal = await po.Portal.get_by_chat_id(typing.group_id)
        else:
            portal = await po.Portal.get_by_chat_id(sender.address, receiver=user.username)
        if not portal or not portal.mxid:
            return
        is_typing = typing.action == TypingAction.STARTED
        await sender.intent_for(portal).set_typing(portal.mxid, is_typing, ignore_cache=True,
                                                   timeout=SIGNAL_TYPING_TIMEOUT)

    @staticmethod
    async def handle_receipt(sender: 'pu.Puppet', receipt: Receipt) -> None:
        if receipt.type != ReceiptType.READ:
            pass
        messages = await DBMessage.find_by_timestamps(receipt.timestamps)
        for message in messages:
            portal = await po.Portal.get_by_mxid(message.mx_room)
            await sender.intent_for(portal).mark_read(portal.mxid, message.mxid)

    async def start(self) -> None:
        await self.connect()
        async for user in u.User.all_logged_in():
            # TODO report errors to user?
            if await self.subscribe(user.username):
                self.loop.create_task(user.sync())

    async def stop(self) -> None:
        await self.disconnect()
