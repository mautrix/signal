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
from mautrix.util.async_db import Database

from .util import ensure_uuid

fake_db = Database.create("") if TYPE_CHECKING else None


@dataclass
class Reaction:
    db: ClassVar[Database] = fake_db

    mxid: EventID
    mx_room: RoomID
    signal_chat_id: GroupID | UUID
    signal_receiver: str
    msg_author: UUID
    msg_timestamp: int
    author: UUID
    emoji: str

    async def insert(self) -> None:
        q = (
            "INSERT INTO reaction (mxid, mx_room, signal_chat_id, signal_receiver, msg_author,"
            "                      msg_timestamp, author, emoji) "
            "VALUES ($1, $2, $3, $4, $5, $6, $7, $8)"
        )
        await self.db.execute(
            q,
            self.mxid,
            self.mx_room,
            str(self.signal_chat_id),
            self.signal_receiver,
            self.msg_author,
            self.msg_timestamp,
            self.author,
            self.emoji,
        )

    async def edit(self, mx_room: RoomID, mxid: EventID, emoji: str) -> None:
        await self.db.execute(
            "UPDATE reaction SET mxid=$1, mx_room=$2, emoji=$3 "
            "WHERE signal_chat_id=$4 AND signal_receiver=$5"
            "      AND msg_author=$6 AND msg_timestamp=$7 AND author=$8",
            mxid,
            mx_room,
            emoji,
            str(self.signal_chat_id),
            self.signal_receiver,
            self.msg_author,
            self.msg_timestamp,
            self.author,
        )

    async def delete(self) -> None:
        q = (
            "DELETE FROM reaction WHERE signal_chat_id=$1 AND signal_receiver=$2"
            "                           AND msg_author=$3 AND msg_timestamp=$4 AND author=$5"
        )
        await self.db.execute(
            q,
            str(self.signal_chat_id),
            self.signal_receiver,
            self.msg_author,
            self.msg_timestamp,
            self.author,
        )

    @classmethod
    def _from_row(cls, row: asyncpg.Record | None) -> Reaction | None:
        if row is None:
            return None
        data = {**row}
        chat_id = data.pop("signal_chat_id")
        if data["signal_receiver"]:
            chat_id = ensure_uuid(chat_id)
        msg_author = ensure_uuid(data.pop("msg_author"))
        author = ensure_uuid(data.pop("author"))
        return cls(signal_chat_id=chat_id, msg_author=msg_author, author=author, **data)

    @classmethod
    async def get_by_mxid(cls, mxid: EventID, mx_room: RoomID) -> Reaction | None:
        q = (
            "SELECT mxid, mx_room, signal_chat_id, signal_receiver,"
            "       msg_author, msg_timestamp, author, emoji "
            "FROM reaction WHERE mxid=$1 AND mx_room=$2"
        )
        return cls._from_row(await cls.db.fetchrow(q, mxid, mx_room))

    @classmethod
    async def get_by_signal_id(
        cls,
        chat_id: GroupID | UUID,
        receiver: str,
        msg_author: UUID,
        msg_timestamp: int,
        author: UUID,
    ) -> Reaction | None:
        q = (
            "SELECT mxid, mx_room, signal_chat_id, signal_receiver,"
            "       msg_author, msg_timestamp, author, emoji "
            "FROM reaction WHERE signal_chat_id=$1 AND signal_receiver=$2"
            "                    AND msg_author=$3 AND msg_timestamp=$4 AND author=$5"
        )
        return cls._from_row(
            await cls.db.fetchrow(
                q,
                str(chat_id),
                receiver,
                msg_author,
                msg_timestamp,
                author,
            )
        )
