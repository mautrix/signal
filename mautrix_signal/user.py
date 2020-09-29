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
from typing import Dict, Optional, AsyncGenerator, TYPE_CHECKING, cast
from uuid import UUID
import asyncio

from mausignald.types import Account, Address
from mautrix.bridge import BaseUser
from mautrix.types import UserID, RoomID
from mautrix.appservice import AppService

from .db import User as DBUser
from .config import Config
from . import puppet as pu, portal as po

if TYPE_CHECKING:
    from .__main__ import SignalBridge


class User(DBUser, BaseUser):
    by_mxid: Dict[UserID, 'User'] = {}
    by_username: Dict[str, 'User'] = {}
    config: Config
    az: AppService
    loop: asyncio.AbstractEventLoop
    bridge: 'SignalBridge'

    is_admin: bool
    permission_level: str

    _notice_room_lock: asyncio.Lock

    def __init__(self, mxid: UserID, username: Optional[str] = None, uuid: Optional[UUID] = None,
                 notice_room: Optional[RoomID] = None) -> None:
        super().__init__(mxid=mxid, username=username, uuid=uuid, notice_room=notice_room)
        self._notice_room_lock = asyncio.Lock()
        perms = self.config.get_permissions(mxid)
        self.is_whitelisted, self.is_admin, self.permission_level = perms
        self.log = self.log.getChild(self.mxid)
        self.dm_update_lock = asyncio.Lock()

    @classmethod
    def init_cls(cls, bridge: 'SignalBridge') -> None:
        cls.bridge = bridge
        cls.config = bridge.config
        cls.az = bridge.az
        cls.loop = bridge.loop

    @property
    def address(self) -> Optional[Address]:
        if not self.username:
            return None
        return Address(uuid=self.uuid, number=self.username)

    async def on_signin(self, account: Account) -> None:
        self.username = account.username
        self.uuid = account.uuid
        await self.update()
        await self.bridge.signal.subscribe(self.username)
        self.loop.create_task(self.sync())

    async def _sync_puppet(self) -> None:
        puppet = await pu.Puppet.get_by_address(self.address)
        if puppet.custom_mxid != self.mxid and puppet.can_auto_login(self.mxid):
            self.log.info(f"Automatically enabling custom puppet")
            await puppet.switch_mxid(access_token="auto", mxid=self.mxid)

    async def sync(self) -> None:
        try:
            await self._sync_puppet()
        except Exception:
            self.log.exception("Error while syncing own puppet")
        try:
            await self._sync()
        except Exception:
            self.log.exception("Error while syncing")

    async def _sync(self) -> None:
        create_contact_portal = self.config["bridge.autocreate_contact_portal"]
        for contact in await self.bridge.signal.list_contacts(self.username):
            self.log.trace("Syncing contact %s", contact)
            puppet = await pu.Puppet.get_by_address(contact.address)
            if not puppet.name:
                profile = await self.bridge.signal.get_profile(self.username, contact.address)
                if profile:
                    self.log.trace("Got profile for %s: %s", contact.address, profile)
            else:
                # get_profile probably does a request to the servers, so let's not do that unless
                # necessary, but maybe we could listen for updates?
                profile = None
            await puppet.update_info(profile or contact)
            if puppet.uuid and create_contact_portal:
                portal = await po.Portal.get_by_chat_id(puppet.uuid, self.username, create=True)
                await portal.create_matrix_room(self, profile or contact)

        create_group_portal = self.config["bridge.autocreate_group_portal"]
        for group in await self.bridge.signal.list_groups(self.username):
            self.log.trace("Syncing group %s", group)
            portal = await po.Portal.get_by_chat_id(group.group_id, create=True)
            if create_group_portal:
                await portal.create_matrix_room(self, group)
            elif portal.mxid:
                await portal.update_matrix_room(self, group)

    # region Database getters

    def _add_to_cache(self) -> None:
        self.by_mxid[self.mxid] = self
        if self.username:
            self.by_username[self.username] = self

    @classmethod
    async def get_by_mxid(cls, mxid: UserID, create: bool = True) -> Optional['User']:
        try:
            return cls.by_mxid[mxid]
        except KeyError:
            pass

        user = cast(cls, await super().get_by_mxid(mxid))
        if user is not None:
            user._add_to_cache()
            return user

        if create:
            user = cls(mxid)
            await user.insert()
            user._add_to_cache()
            return user

        return None

    @classmethod
    async def get_by_username(cls, username: str) -> Optional['User']:
        try:
            return cls.by_username[username]
        except KeyError:
            pass

        user = cast(cls, await super().get_by_username(username))
        if user is not None:
            user._add_to_cache()
            return user

        return None

    @classmethod
    async def all_logged_in(cls) -> AsyncGenerator['User', None]:
        users = await super().all_logged_in()
        user: cls
        for user in users:
            try:
                yield cls.by_mxid[user.mxid]
            except KeyError:
                user._add_to_cache()
                yield user

    # endregion
