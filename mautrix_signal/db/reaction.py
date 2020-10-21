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
from typing import Optional, ClassVar, Union, TYPE_CHECKING
from uuid import UUID

from attr import dataclass
import asyncpg

from mausignald.types import Address, GroupID
from mautrix.types import RoomID, EventID
from mautrix.util.async_db import Database

from ..util import id_to_str

fake_db = Database("") if TYPE_CHECKING else None


@dataclass
class Reaction:
    db: ClassVar[Database] = fake_db

    mxid: EventID
    mx_room: RoomID
    signal_chat_id: Union[GroupID, Address]
    signal_receiver: str
    msg_author: Address
    msg_timestamp: int
    author: Address
    emoji: str

    async def insert(self) -> None:
        q = ("INSERT INTO reaction (mxid, mx_room, signal_chat_id, signal_receiver, msg_author,"
             "                      msg_timestamp, author, emoji) "
             "VALUES ($1, $2, $3, $4, $5, $6, $7, $8)")
        await self.db.execute(q, self.mxid, self.mx_room, id_to_str(self.signal_chat_id),
                              self.signal_receiver, self.msg_author.best_identifier,
                              self.msg_timestamp, self.author.best_identifier, self.emoji)

    async def edit(self, mx_room: RoomID, mxid: EventID, emoji: str) -> None:
        await self.db.execute("UPDATE reaction SET mxid=$1, mx_room=$2, emoji=$3 "
                              "WHERE signal_chat_id=$4 AND signal_receiver=$5"
                              "      AND msg_author=$6 AND msg_timestamp=$7 AND author=$8",
                              mxid, mx_room, emoji, id_to_str(self.signal_chat_id),
                              self.signal_receiver, self.msg_author.best_identifier,
                              self.msg_timestamp, self.author.best_identifier)

    async def delete(self) -> None:
        q = ("DELETE FROM reaction WHERE signal_chat_id=$1 AND signal_receiver=$2"
             "                           AND msg_author=$3 AND msg_timestamp=$4 AND author=$5")
        await self.db.execute(q, id_to_str(self.signal_chat_id), self.signal_receiver,
                              self.msg_author.best_identifier, self.msg_timestamp,
                              self.author.best_identifier)

    @classmethod
    def _from_row(cls, row: asyncpg.Record) -> 'Reaction':
        data = {**row}
        chat_id = data.pop("signal_chat_id")
        if data["signal_receiver"]:
            chat_id = Address.parse(chat_id)
        msg_author = Address.parse(data.pop("msg_author"))
        author = Address.parse(data.pop("author"))
        return cls(signal_chat_id=chat_id, msg_author=msg_author, author=author, **data)

    @classmethod
    async def get_by_mxid(cls, mxid: EventID, mx_room: RoomID) -> Optional['Reaction']:
        q = ("SELECT mxid, mx_room, signal_chat_id, signal_receiver,"
             "       msg_author, msg_timestamp, author, emoji "
             "FROM reaction WHERE mxid=$1 AND mx_room=$2")
        row = await cls.db.fetchrow(q, mxid, mx_room)
        if not row:
            return None
        return cls._from_row(row)

    @classmethod
    async def get_by_signal_id(cls, chat_id: Union[GroupID, Address], receiver: str,
                               msg_author: Address, msg_timestamp: int, author: Address
                               ) -> Optional['Reaction']:
        q = ("SELECT mxid, mx_room, signal_chat_id, signal_receiver,"
             "       msg_author, msg_timestamp, author, emoji "
             "FROM reaction WHERE signal_chat_id=$1 AND signal_receiver=$2"
             "                    AND msg_author=$3 AND msg_timestamp=$4 AND author=$5")
        row = await cls.db.fetchrow(q, id_to_str(chat_id), receiver, msg_author.best_identifier,
                                    msg_timestamp, author.best_identifier)
        if not row:
            return None
        return cls._from_row(row)
