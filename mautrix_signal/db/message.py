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

from typing import TYPE_CHECKING, ClassVar
from uuid import UUID

from attr import dataclass
import asyncpg

from mausignald.types import GroupID
from mautrix.types import EventID, RoomID
from mautrix.util.async_db import Database, Scheme

from .util import ensure_uuid

fake_db = Database.create("") if TYPE_CHECKING else None


@dataclass
class Message:
    db: ClassVar[Database] = fake_db

    mxid: EventID
    mx_room: RoomID
    sender: UUID
    timestamp: int
    signal_chat_id: GroupID | UUID
    signal_receiver: str

    async def insert(self) -> None:
        q = """
        INSERT INTO message (mxid, mx_room, sender, timestamp, signal_chat_id, signal_receiver)
        VALUES ($1, $2, $3, $4, $5, $6)
        """
        await self.db.execute(
            q,
            self.mxid,
            self.mx_room,
            self.sender,
            self.timestamp,
            str(self.signal_chat_id),
            self.signal_receiver,
        )

    async def delete(self) -> None:
        q = """
        DELETE FROM message
        WHERE sender=$1 AND timestamp=$2 AND signal_chat_id=$3 AND signal_receiver=$4
        """
        await self.db.execute(
            q,
            self.sender,
            self.timestamp,
            str(self.signal_chat_id),
            self.signal_receiver,
        )

    @classmethod
    async def delete_all(cls, room_id: RoomID) -> None:
        await cls.db.execute("DELETE FROM message WHERE mx_room=$1", room_id)

    @classmethod
    def _from_row(cls, row: asyncpg.Record | None) -> Message | None:
        if row is None:
            return None
        data = {**row}
        chat_id = data.pop("signal_chat_id")
        if data["signal_receiver"]:
            chat_id = ensure_uuid(chat_id)
        sender = ensure_uuid(data.pop("sender"))
        return cls(signal_chat_id=chat_id, sender=sender, **data)

    @classmethod
    async def get_by_mxid(cls, mxid: EventID, mx_room: RoomID) -> Message | None:
        q = """
        SELECT mxid, mx_room, sender, timestamp, signal_chat_id, signal_receiver FROM message
        WHERE mxid=$1 AND mx_room=$2
        """
        return cls._from_row(await cls.db.fetchrow(q, mxid, mx_room))

    @classmethod
    async def get_by_signal_id(
        cls,
        sender: UUID,
        timestamp: int,
        signal_chat_id: GroupID | UUID,
        signal_receiver: str = "",
    ) -> Message | None:
        q = """
        SELECT mxid, mx_room, sender, timestamp, signal_chat_id, signal_receiver FROM message
        WHERE sender=$1 AND timestamp=$2 AND signal_chat_id=$3 AND signal_receiver=$4
        """
        return cls._from_row(
            await cls.db.fetchrow(q, sender, timestamp, str(signal_chat_id), signal_receiver)
        )

    @classmethod
    async def find_by_timestamps(cls, timestamps: list[int]) -> list[Message]:
        if cls.db.scheme in (Scheme.POSTGRES, Scheme.COCKROACH):
            q = """
            SELECT mxid, mx_room, sender, timestamp, signal_chat_id, signal_receiver FROM message
            WHERE timestamp=ANY($1)
            """
            rows = await cls.db.fetch(q, timestamps)
        else:
            placeholders = ", ".join("?" for _ in range(len(timestamps)))
            q = f"""
            SELECT mxid, mx_room, sender, timestamp, signal_chat_id, signal_receiver FROM message
            WHERE timestamp IN ({placeholders})
            """
            rows = await cls.db.fetch(q, *timestamps)
        return [cls._from_row(row) for row in rows]

    @classmethod
    async def find_by_sender_timestamp(cls, sender: UUID, timestamp: int) -> Message | None:
        q = """
        SELECT mxid, mx_room, sender, timestamp, signal_chat_id, signal_receiver FROM message
        WHERE sender=$1 AND timestamp=$2
        """
        return cls._from_row(await cls.db.fetchrow(q, sender, timestamp))

    @classmethod
    async def get_first_before(cls, mx_room: RoomID, timestamp: int) -> Message | None:
        q = """
        SELECT mxid, mx_room, sender, timestamp, signal_chat_id, signal_receiver FROM message
        WHERE mx_room=$1 AND timestamp <= $2
        ORDER BY timestamp DESC
        LIMIT 1
        """
        return cls._from_row(await cls.db.fetchrow(q, mx_room, timestamp))
