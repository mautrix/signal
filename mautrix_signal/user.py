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
from typing import Union, Dict, Optional, AsyncGenerator, TYPE_CHECKING, cast
from uuid import UUID
import asyncio

from mausignald.types import Account, Address, Profile, Group, GroupV2, ListenEvent, ListenAction
from mautrix.bridge import BaseUser, BridgeState, AutologinError, async_getter_lock
from mautrix.types import UserID, RoomID
from mautrix.util.bridge_state import BridgeStateEvent
from mautrix.appservice import AppService
from mautrix.util.opt_prometheus import Gauge

from .db import User as DBUser
from .config import Config
from . import puppet as pu, portal as po

if TYPE_CHECKING:
    from .__main__ import SignalBridge

METRIC_CONNECTED = Gauge('bridge_connected', 'Bridge users connected to Signal')
METRIC_LOGGED_IN = Gauge('bridge_logged_in', 'Bridge users logged into Signal')

BridgeState.human_readable_errors.update({
    "logged-out": "You're not logged into Signal",
    "signal-not-connected": None,
})


class User(DBUser, BaseUser):
    by_mxid: Dict[UserID, 'User'] = {}
    by_username: Dict[str, 'User'] = {}
    by_uuid: Dict[UUID, 'User'] = {}
    config: Config
    az: AppService
    loop: asyncio.AbstractEventLoop
    bridge: 'SignalBridge'

    relay_whitelisted: bool
    is_admin: bool
    permission_level: str

    _sync_lock: asyncio.Lock
    _notice_room_lock: asyncio.Lock
    _connected: bool

    def __init__(self, mxid: UserID, username: Optional[str] = None, uuid: Optional[UUID] = None,
                 notice_room: Optional[RoomID] = None) -> None:
        super().__init__(mxid=mxid, username=username, uuid=uuid, notice_room=notice_room)
        BaseUser.__init__(self)
        self._notice_room_lock = asyncio.Lock()
        self._sync_lock = asyncio.Lock()
        self._connected = False
        perms = self.config.get_permissions(mxid)
        self.relay_whitelisted, self.is_whitelisted, self.is_admin, self.permission_level = perms

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
        if self.uuid and self.by_uuid.get(self.uuid) == self:
            del self.by_uuid[self.uuid]
        if self.username and self.by_username.get(self.username) == self:
            del self.by_username[self.username]
        self.username = None
        self.uuid = None
        await self.update()
        await self.bridge.signal.unsubscribe(username)
        # Wait a while for signald to finish disconnecting
        await asyncio.sleep(1)
        await self.bridge.signal.delete_account(username)
        self._track_metric(METRIC_LOGGED_IN, False)
        await self.push_bridge_state(BridgeStateEvent.LOGGED_OUT)

    async def fill_bridge_state(self, state: BridgeState) -> None:
        await super().fill_bridge_state(state)
        if not state.remote_id:
            state.remote_id = self.username
        if self.address:
            puppet = await self.get_puppet()
            state.remote_name = puppet.name or self.username

    async def get_puppet(self) -> Optional['pu.Puppet']:
        if not self.address:
            return None
        return await pu.Puppet.get_by_address(self.address)

    async def on_signin(self, account: Account) -> None:
        self.username = account.account_id
        self.uuid = account.address.uuid
        self._add_to_cache()
        await self.update()
        await self.bridge.signal.subscribe(self.username)
        asyncio.create_task(self.sync())
        self._track_metric(METRIC_LOGGED_IN, True)

    def on_listen(self, evt: ListenEvent) -> None:
        if evt.action == ListenAction.STARTED:
            self.log.info("Connected to Signal")
            self._track_metric(METRIC_CONNECTED, True)
            self._track_metric(METRIC_LOGGED_IN, True)
            self._connected = True
            asyncio.create_task(self.push_bridge_state(BridgeStateEvent.CONNECTED))
        elif evt.action == ListenAction.STOPPED:
            if evt.exception:
                self.log.warning(f"Disconnected from Signal: {evt.exception}")
            else:
                self.log.info("Disconnected from Signal")
            self._track_metric(METRIC_CONNECTED, False)
            asyncio.create_task(self.push_bridge_state(BridgeStateEvent.UNKNOWN_ERROR))
            self._connected = False
        else:
            self.log.warning(f"Unrecognized listen action {evt.action}")

    async def _sync_puppet(self) -> None:
        puppet = await pu.Puppet.get_by_address(self.address)
        if puppet.uuid and not self.uuid:
            self.uuid = puppet.uuid
            self.by_uuid[self.uuid] = self
        if puppet.custom_mxid != self.mxid and puppet.can_auto_login(self.mxid):
            self.log.info(f"Automatically enabling custom puppet")
            try:
                await puppet.switch_mxid(access_token="auto", mxid=self.mxid)
            except AutologinError as e:
                self.log.warning(f"Failed to enable custom puppet: {e}")

    async def sync(self) -> None:
        await self.sync_puppet()
        await self.sync_contacts()
        await self.sync_groups()

    async def sync_puppet(self) -> None:
        try:
            async with self._sync_lock:
                await self._sync_puppet()
        except Exception:
            self.log.exception("Error while syncing own puppet")

    async def sync_contacts(self) -> None:
        try:
            async with self._sync_lock:
                await self._sync_contacts()
        except Exception:
            self.log.exception("Error while syncing contacts")

    async def sync_groups(self) -> None:
        try:
            async with self._sync_lock:
                await self._sync_groups()
        except Exception:
            self.log.exception("Error while syncing groups")

    async def sync_contact(self, contact: Union[Profile, Address], create_portals: bool = False
                           ) -> None:
        self.log.trace("Syncing contact %s", contact)
        if isinstance(contact, Address):
            address = contact
            profile = await self.bridge.signal.get_profile(self.username, address)
            if profile and profile.name:
                self.log.trace("Got profile for %s: %s", address, profile)
        else:
            address = contact.address
            profile = contact
        puppet = await pu.Puppet.get_by_address(address)
        await puppet.update_info(profile)
        if create_portals:
            portal = await po.Portal.get_by_chat_id(puppet.address, receiver=self.username,
                                                    create=True)
            await portal.create_matrix_room(self, profile)

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
            group_id = group.group_id if isinstance(group, Group) else group.id
            try:
                if isinstance(group, Group):
                    await self._sync_group(group, create_group_portal)
                elif isinstance(group, GroupV2):
                    await self._sync_group_v2(group, create_group_portal)
                else:
                    self.log.warning("Unknown return type in list_groups: %s", type(group))
            except Exception:
                self.log.exception(f"Failed to sync group {group_id}")

    # region Database getters

    def _add_to_cache(self) -> None:
        self.by_mxid[self.mxid] = self
        if self.username:
            self.by_username[self.username] = self
        if self.uuid:
            self.by_uuid[self.uuid] = self

    @classmethod
    @async_getter_lock
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
    @async_getter_lock
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
    @async_getter_lock
    async def get_by_uuid(cls, uuid: UUID) -> Optional['User']:
        try:
            return cls.by_uuid[uuid]
        except KeyError:
            pass

        user = cast(cls, await super().get_by_uuid(uuid))
        if user is not None:
            user._add_to_cache()
            return user

        return None

    @classmethod
    async def get_by_address(cls, address: Address) -> Optional['User']:
        if address.uuid:
            return await cls.get_by_uuid(address.uuid)
        elif address.number:
            return await cls.get_by_username(address.number)
        else:
            raise ValueError("Given address is blank")

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
