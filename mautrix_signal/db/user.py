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
from typing import Optional, ClassVar, List, TYPE_CHECKING
from uuid import UUID

from attr import dataclass

from mautrix.types import UserID, RoomID
from mautrix.util.async_db import Database

fake_db = Database("") if TYPE_CHECKING else None


@dataclass
class User:
    db: ClassVar[Database] = fake_db

    mxid: UserID
    username: Optional[str]
    uuid: Optional[UUID]
    notice_room: Optional[RoomID]

    async def insert(self) -> None:
        q = ('INSERT INTO "user" (mxid, username, uuid, notice_room) '
             'VALUES ($1, $2, $3, $4)')
        await self.db.execute(q, self.mxid, self.username, self.uuid, self.notice_room)

    async def update(self) -> None:
        await self.db.execute('UPDATE "user" SET username=$2, uuid=$3, notice_room=$4 '
                              'WHERE mxid=$1', self.mxid, self.username, self.uuid, self.notice_room)

    @classmethod
    async def get_by_mxid(cls, mxid: UserID) -> Optional['User']:
        q = 'SELECT mxid, username, uuid, notice_room FROM "user" WHERE mxid=$1'
        row = await cls.db.fetchrow(q, mxid)
        if not row:
            return None
        return cls(**row)

    @classmethod
    async def get_by_username(cls, username: str) -> Optional['User']:
        q = 'SELECT mxid, username, uuid, notice_room FROM "user" WHERE username=$1'
        row = await cls.db.fetchrow(q, username)
        if not row:
            return None
        return cls(**row)

    @classmethod
    async def get_by_uuid(cls, uuid: UUID) -> Optional['User']:
        q = 'SELECT mxid, username, uuid, notice_room FROM "user" WHERE uuid=$1'
        row = await cls.db.fetchrow(q, uuid)
        if not row:
            return None
        return cls(**row)

    @classmethod
    async def all_logged_in(cls) -> List['User']:
        q = 'SELECT mxid, username, uuid, notice_room FROM "user" WHERE username IS NOT NULL'
        rows = await cls.db.fetch(q)
        return [cls(**row) for row in rows]
