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
from yarl import URL
import asyncpg

from mausignald.types import Address
from mautrix.types import UserID, SyncToken
from mautrix.util.async_db import Database

fake_db = Database("") if TYPE_CHECKING else None


@dataclass
class Puppet:
    db: ClassVar[Database] = fake_db

    uuid: Optional[UUID]
    number: Optional[str]
    name: Optional[str]

    uuid_registered: bool
    number_registered: bool

    custom_mxid: Optional[UserID]
    access_token: Optional[str]
    next_batch: Optional[SyncToken]
    base_url: Optional[URL]

    async def insert(self) -> None:
        q = ("INSERT INTO puppet (uuid, number, name, uuid_registered, number_registered, "
             "                    custom_mxid, access_token, next_batch, base_url) "
             "VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9)")
        await self.db.execute(q, self.uuid, self.number, self.name, self.uuid_registered,
                              self.number_registered, self.custom_mxid, self.access_token,
                              self.next_batch, str(self.base_url))

    async def _set_uuid(self, uuid: UUID) -> None:
        if self.uuid:
            raise ValueError("Can't re-set UUID for puppet")
        self.uuid = uuid
        await self.db.execute("UPDATE puppet SET uuid=$1 WHERE number=$2", uuid, self.number)

    async def update(self) -> None:
        if self.uuid is None:
            q = ("UPDATE puppet SET uuid=$1, name=$3, uuid_registered=$4, number_registered=$5, "
                 "                  custom_mxid=$6, access_token=$7, next_batch=$8, base_url=$9 "
                 "WHERE number=$2")
        else:
            q = ("UPDATE puppet SET number=$2, name=$3, uuid_registered=$4, number_registered=$5, "
                 "                  custom_mxid=$6, access_token=$7, next_batch=$8, base_url=$9 "
                 "WHERE uuid=$1")
        await self.db.execute(q, self.uuid, self.number, self.name, self.uuid_registered,
                              self.number_registered, self.custom_mxid, self.access_token,
                              self.next_batch, str(self.base_url))

    @classmethod
    def _from_row(cls, row: asyncpg.Record) -> 'Puppet':
        data = {**row}
        base_url_str = data.pop("base_url")
        base_url = URL(base_url_str) if base_url_str is not None else None
        return cls(base_url=base_url, **data)

    @classmethod
    async def get_by_address(cls, address: Address) -> Optional['Puppet']:
        select = ("SELECT uuid, number, name, uuid_registered, "
                  "       number_registered, custom_mxid, access_token, next_batch, base_url "
                  "FROM puppet")
        if address.uuid:
            if address.number:
                row = await cls.db.fetchrow(f"{select} WHERE uuid=$1 OR number=$2",
                                            address.uuid, address.number)
            else:
                row = await cls.db.fetchrow(f"{select} WHERE uuid=$1", address.uuid)
        elif address.number:
            row = await cls.db.fetchrow(f"{select} WHERE number=$1", address.number)
        else:
            raise ValueError("Invalid address")
        if not row:
            return None
        return cls._from_row(row)

    @classmethod
    async def get_by_custom_mxid(cls, mxid: UserID) -> Optional['Puppet']:
        q = ("SELECT uuid, number, name, uuid_registered, number_registered,"
             "       custom_mxid, access_token, next_batch, base_url "
             "FROM puppet WHERE custom_mxid=$1")
        row = await cls.db.fetchrow(q, mxid)
        if not row:
            return None
        return cls._from_row(row)

    @classmethod
    async def all_with_custom_mxid(cls) -> List['Puppet']:
        q = ("SELECT uuid, number, name, uuid_registered, number_registered,"
             "       custom_mxid, access_token, next_batch, base_url "
             "FROM puppet WHERE custom_mxid IS NOT NULL")
        rows = await cls.db.fetch(q)
        return [cls._from_row(row) for row in rows]
