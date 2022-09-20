# mautrix-signal - A Matrix-Signal puppeting bridge
# Copyright (C) 2021 Tulir Asokan
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

from typing import TYPE_CHECKING

from mausignald.types import Address
from mautrix.bridge import BaseMatrixHandler, RejectMatrixInvite
from mautrix.types import (
    Event,
    EventID,
    EventType,
    PresenceEvent,
    ReactionEvent,
    ReactionEventContent,
    ReceiptEvent,
    RedactionEvent,
    RelationType,
    RoomID,
    SingleReceiptEventContent,
    StateEvent,
    TypingEvent,
    UserID,
)

from . import portal as po, puppet as pu, signal as s, user as u
from .db import Message as DBMessage

if TYPE_CHECKING:
    from .__main__ import SignalBridge


class MatrixHandler(BaseMatrixHandler):
    signal: s.SignalHandler

    def __init__(self, bridge: "SignalBridge") -> None:
        prefix, suffix = bridge.config["bridge.username_template"].format(userid=":").split(":")
        homeserver = bridge.config["homeserver.domain"]
        self.user_id_prefix = f"@{prefix}"
        self.user_id_suffix = f"{suffix}:{homeserver}"
        self.signal = bridge.signal

        super().__init__(bridge=bridge)

    async def handle_invite(
        self, room_id: RoomID, user_id: UserID, inviter: u.User, event_id: EventID
    ) -> None:
        user = await u.User.get_by_mxid(user_id, create=False)
        if not user or not await user.is_logged_in():
            return
        portal = await po.Portal.get_by_mxid(room_id)
        if portal and not portal.is_direct:
            try:
                await portal.handle_matrix_invite(inviter, user)
            except RejectMatrixInvite as e:
                await portal.main_intent.send_notice(
                    portal.mxid, f"Failed to invite {user.mxid} on Signal: {e}"
                )

    async def send_welcome_message(self, room_id: RoomID, inviter: u.User) -> None:
        await super().send_welcome_message(room_id, inviter)
        if not inviter.notice_room:
            inviter.notice_room = room_id
            await inviter.update()
            await self.az.intent.send_notice(
                room_id, "This room has been marked as your Signal bridge notice room."
            )

    async def handle_leave(self, room_id: RoomID, user_id: UserID, event_id: EventID) -> None:
        portal = await po.Portal.get_by_mxid(room_id)
        if not portal:
            return

        user = await u.User.get_by_mxid(user_id, create=False)
        if not user:
            return

        await portal.handle_matrix_leave(user)

    async def handle_join(self, room_id: RoomID, user_id: UserID, event_id: EventID) -> None:
        portal = await po.Portal.get_by_mxid(room_id)
        if not portal:
            return

        user = await u.User.get_by_mxid(user_id, create=False)
        if not user:
            return

        await portal.handle_matrix_join(user)

    async def handle_kick_ban(
        self,
        action: str,
        room_id: RoomID,
        user_id: UserID,
        sender: UserID,
        reason: str,
        event_id: EventID,
    ) -> None:
        self.log.debug(f"{user_id} was {action} from {room_id} by {sender} for {reason}")
        portal = await po.Portal.get_by_mxid(room_id)
        if not portal:
            return

        if user_id == self.az.bot_mxid:
            if portal.is_direct:
                await portal.unbridge()
            return

        sender = await u.User.get_by_mxid(sender)
        sender, is_relay = await portal.get_relay_sender(sender, "kick/ban")
        if not sender:
            return

        user = await pu.Puppet.get_by_mxid(user_id)
        if not user:
            user = await u.User.get_by_mxid(user_id, create=False)
            if not user or not await user.is_logged_in():
                return
        if action == "banned":
            await portal.ban_matrix(user, sender)
        elif action == "kicked":
            await portal.kick_matrix(user, sender)
        else:
            await portal.unban_matrix(user, sender)

    async def handle_kick(
        self, room_id: RoomID, user_id: UserID, kicked_by: UserID, reason: str, event_id: EventID
    ) -> None:
        await self.handle_kick_ban("kicked", room_id, user_id, kicked_by, reason, event_id)

    async def handle_unban(
        self, room_id: RoomID, user_id: UserID, unbanned_by: UserID, reason: str, event_id: EventID
    ) -> None:
        await self.handle_kick_ban("unbanned", room_id, user_id, unbanned_by, reason, event_id)

    async def handle_ban(
        self, room_id: RoomID, user_id: UserID, banned_by: UserID, reason: str, event_id: EventID
    ) -> None:
        await self.handle_kick_ban("banned", room_id, user_id, banned_by, reason, event_id)

    @classmethod
    async def handle_reaction(
        cls, room_id: RoomID, user_id: UserID, event_id: EventID, content: ReactionEventContent
    ) -> None:
        if content.relates_to.rel_type != RelationType.ANNOTATION:
            cls.log.debug(
                f"Ignoring m.reaction event in {room_id} from {user_id} with unexpected "
                f"relation type {content.relates_to.rel_type}"
            )
            return
        user = await u.User.get_by_mxid(user_id)
        if not user:
            return

        portal = await po.Portal.get_by_mxid(room_id)
        if not portal:
            return

        await portal.handle_matrix_reaction(
            user, event_id, content.relates_to.event_id, content.relates_to.key
        )

    @staticmethod
    async def handle_redaction(
        room_id: RoomID, user_id: UserID, event_id: EventID, redaction_event_id: EventID
    ) -> None:
        user = await u.User.get_by_mxid(user_id)
        if not user:
            return

        portal = await po.Portal.get_by_mxid(room_id)
        if not portal:
            return

        await portal.handle_matrix_redaction(user, event_id, redaction_event_id)

    async def handle_read_receipt(
        self,
        user: u.User,
        portal: po.Portal,
        event_id: EventID,
        data: SingleReceiptEventContent,
    ) -> None:
        message = await DBMessage.get_by_mxid(
            event_id, portal.mxid
        ) or await DBMessage.get_first_before(portal.mxid, data.ts)
        if not message:
            user.log.warning("Skipping sending read receipt for event ID: %s", event_id)
            return

        user.log.trace(f"Sending read receipt for {message.timestamp} to {message.sender}")
        try:
            await self.signal.send_receipt(
                user.username,
                Address(uuid=message.sender),
                timestamps=[message.timestamp],
                when=data.ts,
                read=True,
            )
        except Exception as e:
            await user.handle_auth_failure(e)

    async def handle_typing(self, room_id: RoomID, typing: list[UserID]) -> None:
        pass
        # portal = await po.Portal.get_by_mxid(room_id)
        # if not portal:
        #     return
        #
        # for user_id in typing:
        #     user = await u.User.get_by_mxid(user_id, create=False)
        #     if not user or not user.username:
        #         continue
        #     # TODO

    async def handle_event(self, evt: Event) -> None:
        if evt.type == EventType.REACTION:
            evt: ReactionEvent
            await self.handle_reaction(evt.room_id, evt.sender, evt.event_id, evt.content)
        elif evt.type == EventType.ROOM_REDACTION:
            evt: RedactionEvent
            await self.handle_redaction(evt.room_id, evt.sender, evt.redacts, evt.event_id)

    async def handle_ephemeral_event(
        self, evt: ReceiptEvent | PresenceEvent | TypingEvent
    ) -> None:
        if evt.type == EventType.TYPING:
            await self.handle_typing(evt.room_id, evt.content.user_ids)
        else:
            await super().handle_ephemeral_event(evt)

    async def handle_state_event(self, evt: StateEvent) -> None:
        if evt.type not in (
            EventType.ROOM_NAME,
            EventType.ROOM_TOPIC,
            EventType.ROOM_AVATAR,
            EventType.ROOM_POWER_LEVELS,
            EventType.ROOM_JOIN_RULES,
        ):
            return

        user = await u.User.get_by_mxid(evt.sender)
        if not user:
            return
        portal = await po.Portal.get_by_mxid(evt.room_id)
        if not portal:
            return

        if evt.type == EventType.ROOM_NAME:
            await portal.handle_matrix_name(user, evt.content.name)
        elif evt.type == EventType.ROOM_AVATAR:
            await portal.handle_matrix_avatar(user, evt.content.url)
        elif evt.type == EventType.ROOM_TOPIC:
            await portal.handle_matrix_topic(user, evt.content.topic)
        elif evt.type == EventType.ROOM_POWER_LEVELS:
            await portal.handle_matrix_power_level(user, evt.content, evt.unsigned.prev_content)
        elif evt.type == EventType.ROOM_JOIN_RULES:
            await portal.handle_matrix_join_rules(user, evt.content.join_rule)

    async def allow_message(self, user: u.User) -> bool:
        return user.relay_whitelisted

    async def allow_bridging_message(self, user: u.User, portal: po.Portal) -> bool:
        return portal.has_relay or await user.is_logged_in()
