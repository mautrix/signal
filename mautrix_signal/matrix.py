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
from typing import Dict, List, Optional, Union, TYPE_CHECKING

from mautrix.bridge import BaseMatrixHandler
from mautrix.errors import MatrixError
from mautrix.types import (Event, ReactionEvent, MessageEvent, StateEvent, EncryptedEvent, RoomID,
                           EventID, UserID, ReactionEventContent, RelationType, EventType,
                           ReceiptEvent, TypingEvent, PresenceEvent, RedactionEvent,
                           SingleReceiptEventContent)

from .db import Message as DBMessage
from . import puppet as pu, portal as po, user as u, signal as s

if TYPE_CHECKING:
    from .__main__ import SignalBridge


class MatrixHandler(BaseMatrixHandler):
    signal: 's.SignalHandler'
    management_room_text: Dict[str, Dict[str, str]]
    management_room_multiple_messages: bool

    def __init__(self, bridge: 'SignalBridge') -> None:
        prefix, suffix = bridge.config["bridge.username_template"].format(userid=":").split(":")
        homeserver = bridge.config["homeserver.domain"]
        self.user_id_prefix = f"@{prefix}"
        self.user_id_suffix = f"{suffix}:{homeserver}"
        self.signal = bridge.signal
        self.management_room_text = bridge.config["bridge.management_room_text"]
        self.management_room_multiple_messages = bridge.config["bridge.management_room_multiple_messages"]

        super().__init__(bridge=bridge)

    def filter_matrix_event(self, evt: Event) -> bool:
        if isinstance(evt, (ReceiptEvent, TypingEvent)):
            return False
        elif not isinstance(evt, (ReactionEvent, MessageEvent, StateEvent, EncryptedEvent,
                                  RedactionEvent)):
            return True
        return (evt.sender == self.az.bot_mxid
                or pu.Puppet.get_id_from_mxid(evt.sender) is not None)

    def _get_welcome_message(self, statement_name: str, default_plain: str, default_html: Optional[str] = None) -> (str, str):
        plain = self.management_room_text.get(statement_name, {}).get("plain", None)
        html = self.management_room_text.get(statement_name, {}).get("html", None)
        return plain or default_plain, html or plain or default_html or default_plain

    async def send_welcome_message(self, room_id: RoomID, inviter: 'u.User') -> None:
        try:
            is_management = len(await self.az.intent.get_room_members(room_id)) == 2
        except MatrixError:
            # The AS bot is not in the room.
            return

        cmd_prefix = self.commands.command_prefix
        plain = html = ""

        welcome_plain, welcome_html = self._get_welcome_message(
            "welcome",
            "Hello, I'm a Signal bridge bot.",
        )
        if self.management_room_multiple_messages:
            await self.az.intent.send_notice(room_id, text=welcome_plain, html=welcome_html)
        else:
            plain += welcome_plain + "\n"
            html += welcome_html + "<br/>"

        if not is_management:
            plain += f"Use `{cmd_prefix} help` for help."
            html += f"Use <code>{cmd_prefix} help</code> for help."
            await self.az.intent.send_notice(room_id, text=plain, html=html)
            return

        if await inviter.is_logged_in():
            logged_in_plain, logged_in_html = self._get_welcome_message(
                "welcome_connected",
                default_plain="Use `help` for help.",
                default_html="Use <code>help</code> for help."
            )
            if self.management_room_multiple_messages:
                await self.az.intent.send_notice(room_id, text=logged_in_plain, html=logged_in_html)
            else:
                plain += logged_in_plain + "\n"
                html += logged_in_html + "<br/>"
        else:
            unconnected_plain, unconnected_html = self._get_welcome_message(
                "welcome_unconnected",
                default_plain="Use `help` for help or `register` to log in.",
                default_html="Use <code>help</code> for help or <code>register</code> to log in.",
            )
            if self.management_room_multiple_messages:
                await self.az.intent.send_notice(room_id, text=unconnected_plain, html=unconnected_html)
            else:
                plain += unconnected_plain + "\n"
                html += unconnected_html + "<br/>"

        additional_help_plain, additional_help_html = self._get_welcome_message(
            "additional_help",
            default_plain="",
        )
        if additional_help_plain:
            if self.management_room_multiple_messages:
                await self.az.intent.send_notice(room_id, text=additional_help_plain, html=additional_help_html)
            else:
                plain += additional_help_plain + "\n"
                html += additional_help_html + "<br/>"

        if not inviter.notice_room:
            notice_plain = "This room has been marked as your Signal bridge notice room."
            inviter.notice_room = room_id
            await inviter.update()
            if self.management_room_multiple_messages:
                await self.az.intent.send_notice(room_id, text=notice_plain)
            else:
                plain += notice_plain + "\n"
                html += notice_plain + "<br/>"

        # If we're not using multiple messages
        if not self.management_room_multiple_messages:
            await self.az.intent.send_notice(room_id, text=plain, html=html)

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
    async def handle_redaction(room_id: RoomID, user_id: UserID, event_id: EventID,
                               redaction_event_id: EventID) -> None:
        user = await u.User.get_by_mxid(user_id)
        if not user:
            return

        portal = await po.Portal.get_by_mxid(room_id)
        if not portal:
            return

        await portal.handle_matrix_redaction(user, event_id, redaction_event_id)

    async def handle_read_receipt(self, user: 'u.User', portal: 'po.Portal', event_id: EventID,
                                  data: SingleReceiptEventContent) -> None:
        message = await DBMessage.get_by_mxid(event_id, portal.mxid)
        if not message:
            return

        user.log.trace(f"Sending read receipt for {message.timestamp} to {message.sender}")
        await self.signal.send_receipt(user.username, message.sender,
                                       timestamps=[message.timestamp], when=data.ts, read=True)

    async def handle_typing(self, room_id: RoomID, typing: List[UserID]) -> None:
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

    async def handle_ephemeral_event(self, evt: Union[ReceiptEvent, PresenceEvent, TypingEvent]
                                     ) -> None:
        if evt.type == EventType.TYPING:
            await self.handle_typing(evt.room_id, evt.content.user_ids)
        else:
            await super().handle_ephemeral_event(evt)

    async def handle_state_event(self, evt: StateEvent) -> None:
        if evt.type not in (EventType.ROOM_NAME, EventType.ROOM_AVATAR):
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

    async def allow_message(self, user: 'u.User') -> bool:
        return user.relay_whitelisted

    async def allow_bridging_message(self, user: 'u.User', portal: 'po.Portal') -> bool:
        return portal.has_relay or await user.is_logged_in()
