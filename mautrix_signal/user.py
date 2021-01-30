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
from typing import Union, Dict, Optional, AsyncGenerator, TYPE_CHECKING, cast
from collections import defaultdict
from uuid import UUID
import asyncio
import os.path
import shutil

from mausignald.types import Account, Address, Contact, Group, GroupV2, ListenEvent, ListenAction
from mautrix.bridge import BaseUser
from mautrix.types import UserID, RoomID
from mautrix.appservice import AppService
from mautrix.util.opt_prometheus import Gauge

from .db import User as DBUser
from .config import Config
from . import puppet as pu, portal as po

if TYPE_CHECKING:
    from .__main__ import SignalBridge

METRIC_CONNECTED = Gauge('bridge_connected', 'Bridge users connected to Signal')


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
        self.command_status = None
        self._metric_value = defaultdict(lambda: False)

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

    async def is_logged_in(self) -> bool:
        return bool(self.username)

    async def logout(self) -> None:
        if not self.username:
            return
        username = self.username
        self.username = None
        self.uuid = None
        await self.update()
        await self.bridge.signal.unsubscribe(username)
        # Wait a while for signald to finish disconnecting
        await asyncio.sleep(1)
        path = os.path.join(self.config["signal.data_dir"], username)
        extra_dir = f"{path}.d/"
        try:
            self.log.debug("Removing %s", path)
            os.remove(path)
        except FileNotFoundError as e:
            self.log.warning(f"Failed to remove signald data file: {e}")
        self.log.debug("Removing %s", extra_dir)
        shutil.rmtree(extra_dir, ignore_errors=True)

    async def on_signin(self, account: Account) -> None:
        self.username = account.username
        self.uuid = account.uuid
        await self.update()
        await self.bridge.signal.subscribe(self.username)
        self.loop.create_task(self.sync())

    def on_listen(self, evt: ListenEvent) -> None:
        if evt.action == ListenAction.STARTED:
            self.log.info("Connected to Signal")
            self._track_metric(METRIC_CONNECTED, True)
        elif evt.action == ListenAction.STOPPED:
            if evt.exception:
                self.log.warning(f"Disconnected from Signal: {evt.exception}")
            else:
                self.log.info("Disconnected from Signal")
            self._track_metric(METRIC_CONNECTED, False)
        else:
            self.log.warning(f"Unrecognized listen action {evt.action}")

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
            await self._sync_contacts()
        except Exception:
            self.log.exception("Error while syncing contacts")
        try:
            await self._sync_groups()
        except Exception:
            self.log.exception("Error while syncing groups")

    async def sync_contact(self, contact: Union[Contact, Address], create_portals: bool = False
                           ) -> None:
        self.log.trace("Syncing contact %s", contact)
        address = contact.address if isinstance(contact, Contact) else contact
        puppet = await pu.Puppet.get_by_address(address)
        profile = await self.bridge.signal.get_profile(self.username, address)
        if profile and profile.name:
            self.log.trace("Got profile for %s: %s", address, profile)
        else:
            profile = None
        await puppet.update_info(profile or contact)
        if create_portals:
            portal = await po.Portal.get_by_chat_id(puppet.address, self.username, create=True)
            await portal.create_matrix_room(self, profile or contact)

    async def _sync_group(self, group: Group, create_portals: bool) -> None:
        self.log.trace("Syncing group %s", group)
        portal = await po.Portal.get_by_chat_id(group.group_id, create=True)
        if create_portals:
            await portal.create_matrix_room(self, group)
        elif portal.mxid:
            await portal.update_matrix_room(self, group)

    async def _sync_group_v2(self, group: GroupV2, create_portals: bool) -> None:
        self.log.trace("Syncing group %s", group.id)
        portal = await po.Portal.get_by_chat_id(group.id, create=True)
        if create_portals:
            await portal.create_matrix_room(self, group)
        elif portal.mxid:
            await portal.update_matrix_room(self, group)

    async def _sync_contacts(self) -> None:
        create_contact_portal = self.config["bridge.autocreate_contact_portal"]
        for contact in await self.bridge.signal.list_contacts(self.username):
            try:
                await self.sync_contact(contact, create_contact_portal)
            except Exception:
                self.log.exception(f"Failed to sync contact {contact.address}")

    async def _sync_groups(self) -> None:
        create_group_portal = self.config["bridge.autocreate_group_portal"]
        for group in await self.bridge.signal.list_groups(self.username):
            try:
                if isinstance(group, Group):
                    await self._sync_group(group, create_group_portal)
                elif isinstance(group, GroupV2):
                    await self._sync_group_v2(group, create_group_portal)
                else:
                    self.log.warning("Unknown return type in list_groups: %s", type(group))
            except Exception:
                self.log.exception(f"Failed to sync group {group.group_id}")

    # region Database getters

    def _add_to_cache(self) -> None:
        self.by_mxid[self.mxid] = self
        if self.username:
            self.by_username[self.username] = self

    @classmethod
    async def get_by_mxid(cls, mxid: UserID, create: bool = True) -> Optional['User']:
        # Never allow ghosts to be users
        if pu.Puppet.get_id_from_mxid(mxid):
            return None
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
