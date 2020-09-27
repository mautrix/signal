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
from typing import List, Union, TYPE_CHECKING

from mautrix.bridge import BaseMatrixHandler
from mautrix.types import (Event, ReactionEvent, MessageEvent, StateEvent, EncryptedEvent, RoomID,
                           EventID, UserID, ReactionEventContent, RelationType, EventType,
                           ReceiptEvent, TypingEvent, PresenceEvent, RedactionEvent)

from .db import Message as DBMessage
from . import commands as com, puppet as pu, portal as po, user as u

if TYPE_CHECKING:
    from .__main__ import SignalBridge


class MatrixHandler(BaseMatrixHandler):
    commands: 'com.CommandProcessor'

    def __init__(self, bridge: 'SignalBridge') -> None:
        prefix, suffix = bridge.config["bridge.username_template"].format(userid=":").split(":")
        homeserver = bridge.config["homeserver.domain"]
        self.user_id_prefix = f"@{prefix}"
        self.user_id_suffix = f"{suffix}:{homeserver}"

        super().__init__(command_processor=com.CommandProcessor(bridge), bridge=bridge)

    def filter_matrix_event(self, evt: Event) -> bool:
        if not isinstance(evt, (ReactionEvent, MessageEvent, StateEvent, EncryptedEvent,
                                RedactionEvent)):
            return True
        return (evt.sender == self.az.bot_mxid
                or pu.Puppet.get_id_from_mxid(evt.sender) is not None)

    async def send_welcome_message(self, room_id: RoomID, inviter: 'u.User') -> None:
        await super().send_welcome_message(room_id, inviter)
        if not inviter.notice_room:
            inviter.notice_room = room_id
            await inviter.update()
            await self.az.intent.send_notice(room_id, "This room has been marked as your "
                                                      "Signal bridge notice room.")

    async def handle_leave(self, room_id: RoomID, user_id: UserID, event_id: EventID) -> None:
        portal = await po.Portal.get_by_mxid(room_id)
        if not portal:
            return

        user = await u.User.get_by_mxid(user_id, create=False)
        if not user:
            return

        await portal.handle_matrix_leave(user)

    @staticmethod
    async def allow_bridging_message(user: 'u.User', portal: 'po.Portal') -> bool:
        return user.is_whitelisted and bool(user.username)

    # @staticmethod
    # async def handle_redaction(room_id: RoomID, user_id: UserID, event_id: EventID,
    #                            redaction_event_id: EventID) -> None:
    #     user = await u.User.get_by_mxid(user_id)
    #     if not user:
    #         return
    #
    #     portal = await po.Portal.get_by_mxid(room_id)
    #     if not portal:
    #         return
    #
    #     await portal.handle_matrix_redaction(user, event_id, redaction_event_id)

    @classmethod
    async def handle_reaction(cls, room_id: RoomID, user_id: UserID, event_id: EventID,
                              content: ReactionEventContent) -> None:
        if content.relates_to.rel_type != RelationType.ANNOTATION:
            cls.log.debug(f"Ignoring m.reaction event in {room_id} from {user_id} with unexpected "
                          f"relation type {content.relates_to.rel_type}")
            return
        user = await u.User.get_by_mxid(user_id)
        if not user:
            return

        portal = await po.Portal.get_by_mxid(room_id)
        if not portal:
            return

        await portal.handle_matrix_reaction(user, event_id, content.relates_to.event_id,
                                            content.relates_to.key)

    @staticmethod
    async def handle_receipt(evt: ReceiptEvent) -> None:
        # These events come from custom puppet syncing, so there's always only one user.
        event_id, receipts = evt.content.popitem()
        receipt_type, users = receipts.popitem()
        user_id, data = users.popitem()

        user = await u.User.get_by_mxid(user_id, create=False)
        if not user or not user.client:
            return

        portal = await po.Portal.get_by_mxid(evt.room_id)
        if not portal:
            return

        message = await DBMessage.get_by_mxid(event_id, portal.mxid)
        if not message:
            return

        # user.log.debug(f"Marking messages in {portal.twid} read up to {message.twid}")
        # await user.client.conversation(portal.twid).mark_read(message.twid)

    @staticmethod
    async def handle_typing(room_id: RoomID, typing: List[UserID]) -> None:
        # TODO implement
        pass

    async def handle_event(self, evt: Event) -> None:
        if evt.type == EventType.ROOM_REDACTION:
            evt: RedactionEvent
            # await self.handle_redaction(evt.room_id, evt.sender, evt.redacts, evt.event_id)
        elif evt.type == EventType.REACTION:
            evt: ReactionEvent
            await self.handle_reaction(evt.room_id, evt.sender, evt.event_id, evt.content)

    async def handle_ephemeral_event(self, evt: Union[ReceiptEvent, PresenceEvent, TypingEvent]
                                     ) -> None:
        if evt.type == EventType.TYPING:
            await self.handle_typing(evt.room_id, evt.content.user_ids)
        elif evt.type == EventType.RECEIPT:
            await self.handle_receipt(evt)
