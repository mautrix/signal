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
from yarl import URL
import asyncpg

from mautrix.types import ContentURI, SyncToken, UserID
from mautrix.util.async_db import Connection, Database

fake_db = Database.create("") if TYPE_CHECKING else None


@dataclass
class Puppet:
    db: ClassVar[Database] = fake_db

    uuid: UUID
    number: str | None
    name: str | None
    name_quality: int
    avatar_hash: str | None
    avatar_url: ContentURI | None
    name_set: bool
    avatar_set: bool
    is_registered: bool

    custom_mxid: UserID | None
    access_token: str | None
    next_batch: SyncToken | None
    base_url: URL | None

    @property
    def _base_url_str(self) -> str | None:
        return str(self.base_url) if self.base_url else None

    @property
    def _values(self):
        return (
            self.uuid,
            self.number,
            self.name,
            self.name_quality,
            self.avatar_hash,
            self.avatar_url,
            self.name_set,
            self.avatar_set,
            self.is_registered,
            self.custom_mxid,
            self.access_token,
            self.next_batch,
            self._base_url_str,
        )

    async def _delete_existing_number(self, conn: Connection) -> None:
        if not self.number:
            return
        await conn.execute(
            "UPDATE puppet SET number=null WHERE number=$1 AND uuid<>$2", self.number, self.uuid
        )

    async def insert(self) -> None:
        q = """
        INSERT INTO puppet (uuid, number, name, name_quality, avatar_hash, avatar_url,
                            name_set, avatar_set, is_registered,
                            custom_mxid, access_token, next_batch, base_url)
        VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13)
        """
        async with self.db.acquire() as conn, conn.transaction():
            await self._delete_existing_number(conn)
            await conn.execute(q, *self._values)

    async def _update_number(self) -> None:
        async with self.db.acquire() as conn, conn.transaction():
            await self._delete_existing_number(conn)
            await conn.execute("UPDATE puppet SET number=$1 WHERE uuid=$2", self.number, self.uuid)

    async def update(self) -> None:
        q = """
        UPDATE puppet
        SET number=$2, name=$3, name_quality=$4, avatar_hash=$5, avatar_url=$6,
            name_set=$7, avatar_set=$8, is_registered=$9,
            custom_mxid=$10, access_token=$11, next_batch=$12, base_url=$13
        WHERE uuid=$1
        """
        await self.db.execute(q, *self._values)

    @classmethod
    def _from_row(cls, row: asyncpg.Record | None) -> Puppet | None:
        if not row:
            return None
        data = {**row}
        base_url_str = data.pop("base_url")
        base_url = URL(base_url_str) if base_url_str is not None else None
        return cls(base_url=base_url, **data)

    _select_base = (
        "SELECT uuid, number, name, name_quality, avatar_hash, avatar_url, name_set, avatar_set, "
        "       is_registered, custom_mxid, access_token, next_batch, base_url "
        "FROM puppet"
    )

    @classmethod
    async def get_by_uuid(cls, uuid: UUID) -> Puppet | None:
        return cls._from_row(await cls.db.fetchrow(f"{cls._select_base} WHERE uuid=$1", uuid))

    @classmethod
    async def get_by_number(cls, number: str) -> Puppet | None:
        return cls._from_row(await cls.db.fetchrow(f"{cls._select_base} WHERE number=$1", number))

    @classmethod
    async def get_by_custom_mxid(cls, mxid: UserID) -> Puppet | None:
        return cls._from_row(
            await cls.db.fetchrow(f"{cls._select_base} WHERE custom_mxid=$1", mxid)
        )

    @classmethod
    async def all_with_custom_mxid(cls) -> list[Puppet]:
        return [
            cls._from_row(row)
            for row in await cls.db.fetch(f"{cls._select_base} WHERE custom_mxid IS NOT NULL")
        ]
