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

from mautrix.types import RoomID, UserID
from mautrix.util.async_db import Database

fake_db = Database.create("") if TYPE_CHECKING else None


@dataclass
class User:
    db: ClassVar[Database] = fake_db

    mxid: UserID
    username: str | None
    uuid: UUID | None
    notice_room: RoomID | None

    async def insert(self) -> None:
        q = 'INSERT INTO "user" (mxid, username, uuid, notice_room) VALUES ($1, $2, $3, $4)'
        await self.db.execute(q, self.mxid, self.username, self.uuid, self.notice_room)

    async def update(self) -> None:
        q = 'UPDATE "user" SET username=$1, uuid=$2, notice_room=$3 WHERE mxid=$4'
        await self.db.execute(q, self.username, self.uuid, self.notice_room, self.mxid)

    @classmethod
    async def get_by_mxid(cls, mxid: UserID) -> User | None:
        q = 'SELECT mxid, username, uuid, notice_room FROM "user" WHERE mxid=$1'
        row = await cls.db.fetchrow(q, mxid)
        if not row:
            return None
        return cls(**row)

    @classmethod
    async def get_by_username(cls, username: str) -> User | None:
        q = 'SELECT mxid, username, uuid, notice_room FROM "user" WHERE username=$1'
        row = await cls.db.fetchrow(q, username)
        if not row:
            return None
        return cls(**row)

    @classmethod
    async def get_by_uuid(cls, uuid: UUID) -> User | None:
        q = 'SELECT mxid, username, uuid, notice_room FROM "user" WHERE uuid=$1'
        row = await cls.db.fetchrow(q, uuid)
        if not row:
            return None
        return cls(**row)

    @classmethod
    async def all_logged_in(cls) -> list[User]:
        q = 'SELECT mxid, username, uuid, notice_room FROM "user" WHERE username IS NOT NULL'
        rows = await cls.db.fetch(q)
        return [cls(**row) for row in rows]
