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
from typing import Optional, ClassVar, List, Union, TYPE_CHECKING

from attr import dataclass
import asyncpg

from mausignald.types import Address, GroupID
from mautrix.types import RoomID, ContentURI, UserID
from mautrix.util.async_db import Database

from ..util import id_to_str

fake_db = Database("") if TYPE_CHECKING else None


@dataclass
class Portal:
    db: ClassVar[Database] = fake_db

    chat_id: Union[GroupID, Address]
    receiver: str
    mxid: Optional[RoomID]
    name: Optional[str]
    avatar_hash: Optional[str]
    avatar_url: Optional[ContentURI]
    name_set: bool
    avatar_set: bool
    revision: int
    encrypted: bool
    relay_user_id: Optional[UserID]

    @property
    def chat_id_str(self) -> str:
        return id_to_str(self.chat_id)

    async def insert(self) -> None:
        q = ("INSERT INTO portal (chat_id, receiver, mxid, name, avatar_hash, avatar_url, "
             "                    name_set, avatar_set, revision, encrypted, relay_user_id) "
             "VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11)")
        await self.db.execute(q, self.chat_id_str, self.receiver, self.mxid, self.name,
                              self.avatar_hash, self.avatar_url, self.name_set, self.avatar_set,
                              self.revision, self.encrypted, self.relay_user_id)

    async def update(self) -> None:
        q = ("UPDATE portal SET mxid=$3, name=$4, avatar_hash=$5, avatar_url=$6, name_set=$7, "
             "                  avatar_set=$8, revision=$9, encrypted=$10, relay_user_id=$11 "
             "WHERE chat_id=$1 AND receiver=$2")
        await self.db.execute(q, self.chat_id_str, self.receiver, self.mxid, self.name,
                              self.avatar_hash, self.avatar_url, self.name_set, self.avatar_set,
                              self.revision, self.encrypted, self.relay_user_id)

    @classmethod
    def _from_row(cls, row: asyncpg.Record) -> 'Portal':
        data = {**row}
        chat_id = data.pop("chat_id")
        if data["receiver"]:
            chat_id = Address.parse(chat_id)
        return cls(chat_id=chat_id, **data)

    @classmethod
    async def get_by_mxid(cls, mxid: RoomID) -> Optional['Portal']:
        q = ("SELECT chat_id, receiver, mxid, name, avatar_hash, avatar_url, name_set, avatar_set,"
             "       revision, encrypted, relay_user_id "
             "FROM portal WHERE mxid=$1")
        row = await cls.db.fetchrow(q, mxid)
        if not row:
            return None
        return cls._from_row(row)

    @classmethod
    async def get_by_chat_id(cls, chat_id: Union[GroupID, Address], receiver: str = ""
                             ) -> Optional['Portal']:
        q = ("SELECT chat_id, receiver, mxid, name, avatar_hash, avatar_url, name_set, avatar_set,"
             "       revision, encrypted, relay_user_id "
             "FROM portal WHERE chat_id=$1 AND receiver=$2")
        row = await cls.db.fetchrow(q, id_to_str(chat_id), receiver)
        if not row:
            return None
        return cls._from_row(row)

    @classmethod
    async def find_private_chats_of(cls, receiver: str) -> List['Portal']:
        q = ("SELECT chat_id, receiver, mxid, name, avatar_hash, avatar_url, name_set, avatar_set,"
             "       revision, encrypted, relay_user_id "
             "FROM portal WHERE receiver=$1")
        rows = await cls.db.fetch(q, receiver)
        return [cls._from_row(row) for row in rows]

    @classmethod
    async def find_private_chats_with(cls, other_user: Address) -> List['Portal']:
        q = ("SELECT chat_id, receiver, mxid, name, avatar_hash, avatar_url, name_set, avatar_set,"
             "       revision, encrypted, relay_user_id "
             "FROM portal WHERE chat_id=$1 AND receiver<>''")
        rows = await cls.db.fetch(q, other_user.best_identifier)
        return [cls._from_row(row) for row in rows]

    @classmethod
    async def all_with_room(cls) -> List['Portal']:
        q = ("SELECT chat_id, receiver, mxid, name, avatar_hash, avatar_url, name_set, avatar_set,"
             "       revision, encrypted, relay_user_id "
             "FROM portal WHERE mxid IS NOT NULL")
        rows = await cls.db.fetch(q)
        return [cls._from_row(row) for row in rows]
