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
from __future__ import annotations

from mautrix.appservice import IntentAPI
from mautrix.errors import MatrixRequestError
from mautrix.types import EventType, RoomID

from .. import user as u


async def user_has_power_level(
    room_id: RoomID, intent: IntentAPI, sender: u.User, event: str
) -> bool:
    if sender.is_admin:
        return True
    # Make sure the state store contains the power levels.
    try:
        await intent.get_power_levels(room_id)
    except MatrixRequestError:
        return False
    event_type = EventType.find(f"net.maunium.signal.{event}", t_class=EventType.Class.STATE)
    return await intent.state_store.has_power_level(room_id, sender.mxid, event_type)
