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

from typing import TYPE_CHECKING, ClassVar
from uuid import UUID

from attr import dataclass
import asyncpg

from mausignald.types import GroupID
from mautrix.types import ContentURI, RoomID, UserID
from mautrix.util.async_db import Database

from .util import ensure_uuid

fake_db = Database.create("") if TYPE_CHECKING else None


@dataclass
class Portal:
    db: ClassVar[Database] = fake_db

    chat_id: GroupID | UUID
    receiver: str
    mxid: RoomID | None
    name: str | None
    topic: str | None
    avatar_hash: str | None
    avatar_url: ContentURI | None
    name_set: bool
    avatar_set: bool
    revision: int
    encrypted: bool
    relay_user_id: UserID | None
    expiration_time: int | None

    @property
    def _values(self):
        return (
            str(self.chat_id),
            self.receiver,
            self.mxid,
            self.name,
            self.topic,
            self.avatar_hash,
            self.avatar_url,
            self.name_set,
            self.avatar_set,
            self.revision,
            self.encrypted,
            self.relay_user_id,
            self.expiration_time,
        )

    async def insert(self) -> None:
        q = """
        INSERT INTO portal (
            chat_id, receiver, mxid, name, topic, avatar_hash, avatar_url, name_set, avatar_set,
            revision, encrypted, relay_user_id, expiration_time
        ) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13)
        """
        await self.db.execute(q, *self._values)

    async def update(self) -> None:
        q = """
        UPDATE portal SET mxid=$3, name=$4, topic=$5, avatar_hash=$6, avatar_url=$7, name_set=$8,
                          avatar_set=$9, revision=$10, encrypted=$11, relay_user_id=$12,
                          expiration_time=$13
        WHERE chat_id=$1 AND receiver=$2
        """
        await self.db.execute(q, *self._values)

    @classmethod
    def _from_row(cls, row: asyncpg.Record | None) -> Portal | None:
        if row is None:
            return None
        data = {**row}
        chat_id = data.pop("chat_id")
        if data["receiver"]:
            chat_id = ensure_uuid(chat_id)
        return cls(chat_id=chat_id, **data)

    _columns = (
        "chat_id, receiver, mxid, name, topic, avatar_hash, avatar_url, name_set, avatar_set, "
        "revision, encrypted, relay_user_id, expiration_time"
    )

    @classmethod
    async def get_by_mxid(cls, mxid: RoomID) -> Portal | None:
        q = f"SELECT {cls._columns} FROM portal WHERE mxid=$1"
        return cls._from_row(await cls.db.fetchrow(q, mxid))

    @classmethod
    async def get_by_chat_id(cls, chat_id: GroupID | UUID, receiver: str = "") -> Portal | None:
        q = f"SELECT {cls._columns} FROM portal WHERE chat_id=$1 AND receiver=$2"
        return cls._from_row(await cls.db.fetchrow(q, str(chat_id), receiver))

    @classmethod
    async def find_private_chats_of(cls, receiver: str) -> list[Portal]:
        q = f"SELECT {cls._columns} FROM portal WHERE receiver=$1"
        rows = await cls.db.fetch(q, receiver)
        return [cls._from_row(row) for row in rows]

    @classmethod
    async def find_private_chats_with(cls, other_user: UUID) -> list[Portal]:
        q = f"SELECT {cls._columns} FROM portal WHERE chat_id=$1 AND receiver<>''"
        rows = await cls.db.fetch(q, str(other_user))
        return [cls._from_row(row) for row in rows]

    @classmethod
    async def all_with_room(cls) -> list[Portal]:
        q = f"SELECT {cls._columns} FROM portal WHERE mxid IS NOT NULL"
        rows = await cls.db.fetch(q)
        return [cls._from_row(row) for row in rows]
