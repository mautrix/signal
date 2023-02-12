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

from mautrix.appservice import IntentAPI
from mautrix.types import ContentURI, EventType, JoinRule, PowerLevelStateEventContent, RoomID


async def get_initial_state(
    intent: IntentAPI, room_id: RoomID
) -> tuple[
    str | None,
    str | None,
    PowerLevelStateEventContent | None,
    bool,
    ContentURI | None,
    JoinRule | None,
]:
    state = await intent.get_state(room_id)
    title: str | None = None
    about: str | None = None
    levels: PowerLevelStateEventContent | None = None
    encrypted: bool = False
    avatar_url: ContentURI | None = None
    join_rule: JoinRule | None = None
    for event in state:
        try:
            if event.type == EventType.ROOM_NAME:
                title = event.content.name
            elif event.type == EventType.ROOM_TOPIC:
                about = event.content.topic
            elif event.type == EventType.ROOM_POWER_LEVELS:
                levels = event.content
            elif event.type == EventType.ROOM_CANONICAL_ALIAS:
                title = title or event.content.canonical_alias
            elif event.type == EventType.ROOM_ENCRYPTION:
                encrypted = True
            elif event.type == EventType.ROOM_AVATAR:
                avatar_url = event.content.url
            elif event.type == EventType.ROOM_JOIN_RULES:
                join_rule = event.content.join_rule
        except KeyError:
            # Some state event probably has empty content
            pass
    return title, about, levels, encrypted, avatar_url, join_rule
