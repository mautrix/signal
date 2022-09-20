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

from typing import TYPE_CHECKING, AsyncGenerator, cast
from asyncio.tasks import sleep
from datetime import datetime
from uuid import UUID
import asyncio

from mausignald.errors import AuthorizationFailedError, ProfileUnavailableError
from mausignald.types import (
    Account,
    Address,
    Group,
    GroupV2,
    Profile,
    WebsocketConnectionState,
    WebsocketConnectionStateChangeEvent,
)
from mautrix.appservice import AppService
from mautrix.bridge import AutologinError, BaseUser, async_getter_lock
from mautrix.types import RoomID, UserID
from mautrix.util.bridge_state import BridgeState, BridgeStateEvent
from mautrix.util.opt_prometheus import Gauge

from . import portal as po, puppet as pu
from .config import Config
from .db import User as DBUser

if TYPE_CHECKING:
    from .__main__ import SignalBridge

METRIC_CONNECTED = Gauge("bridge_connected", "Bridge users connected to Signal")
METRIC_LOGGED_IN = Gauge("bridge_logged_in", "Bridge users logged into Signal")

BridgeState.human_readable_errors.update(
    {
        "logged-out": "You're not logged into Signal",
        "signal-not-connected": None,
    }
)


class User(DBUser, BaseUser):
    by_mxid: dict[UserID, User] = {}
    by_username: dict[str, User] = {}
    by_uuid: dict[UUID, User] = {}
    config: Config
    az: AppService
    loop: asyncio.AbstractEventLoop
    bridge: "SignalBridge"

    relay_whitelisted: bool
    is_admin: bool
    permission_level: str

    _sync_lock: asyncio.Lock
    _notice_room_lock: asyncio.Lock
    _connected: bool
    _websocket_connection_state: BridgeStateEvent | None
    _latest_non_transient_disconnect_state: datetime | None

    def __init__(
        self,
        mxid: UserID,
        username: str | None = None,
        uuid: UUID | None = None,
        notice_room: RoomID | None = None,
    ) -> None:
        super().__init__(mxid=mxid, username=username, uuid=uuid, notice_room=notice_room)
        BaseUser.__init__(self)
        self._notice_room_lock = asyncio.Lock()
        self._sync_lock = asyncio.Lock()
        self._connected = False
        self._websocket_connection_state = None
        perms = self.config.get_permissions(mxid)
        self.relay_whitelisted, self.is_whitelisted, self.is_admin, self.permission_level = perms

    @classmethod
    def init_cls(cls, bridge: "SignalBridge") -> None:
        cls.bridge = bridge
        cls.config = bridge.config
        cls.az = bridge.az
        cls.loop = bridge.loop

    @property
    def address(self) -> Address | None:
        if not self.username:
            return None
        return Address(uuid=self.uuid, number=self.username)

    async def is_logged_in(self) -> bool:
        return bool(self.username)

    async def needs_relay(self, portal: po.Portal) -> bool:
        return not await self.is_logged_in() or (
            portal.is_direct and portal.receiver != self.username
        )

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
        await self.push_bridge_state(BridgeStateEvent.LOGGED_OUT, remote_id=username)

    async def fill_bridge_state(self, state: BridgeState) -> None:
        await super().fill_bridge_state(state)
        if not state.remote_id:
            state.remote_id = self.username
        if self.address:
            puppet = await self.get_puppet()
            state.remote_name = puppet.name or self.username

    async def get_bridge_states(self) -> list[BridgeState]:
        if not self.username:
            return []
        state = BridgeState(state_event=BridgeStateEvent.UNKNOWN_ERROR)
        if self.bridge.signal.is_connected and self._connected:
            state.state_event = BridgeStateEvent.CONNECTED
        else:
            state.state_event = BridgeStateEvent.TRANSIENT_DISCONNECT
        return [state]

    async def handle_auth_failure(self, e: Exception) -> None:
        if isinstance(e, AuthorizationFailedError):
            await self.push_bridge_state(BridgeStateEvent.BAD_CREDENTIALS, error=str(e))

    async def get_puppet(self) -> pu.Puppet | None:
        if not self.address:
            return None
        return await pu.Puppet.get_by_address(self.address)

    async def get_portal_with(self, puppet: pu.Puppet, create: bool = True) -> po.Portal | None:
        if not self.username:
            return None
        return await po.Portal.get_by_chat_id(puppet.uuid, receiver=self.username, create=create)

    async def on_signin(self, account: Account) -> None:
        self.username = account.account_id
        self.uuid = account.address.uuid
        self._add_to_cache()
        await self.update()
        await self.bridge.signal.subscribe(self.username)
        asyncio.create_task(self.sync())
        self._track_metric(METRIC_LOGGED_IN, True)

    def on_websocket_connection_state_change(
        self, evt: WebsocketConnectionStateChangeEvent
    ) -> None:
        if evt.state == WebsocketConnectionState.CONNECTED:
            self.log.info(f"Connected to Signal (ws: {evt.socket})")
            self._track_metric(METRIC_CONNECTED, True)
            self._track_metric(METRIC_LOGGED_IN, True)
            self._connected = True
        else:
            if evt.exception:
                self.log.error(
                    f"New {evt.socket} websocket state from signald {evt.state} "
                    f"with error {evt.exception}"
                )
            else:
                self.log.warning(f"New {evt.socket} websocket state from signald {evt.state}")
            self._track_metric(METRIC_CONNECTED, False)
            self._connected = False

        bridge_state = {
            # Signald disconnected
            WebsocketConnectionState.SOCKET_DISCONNECTED: BridgeStateEvent.TRANSIENT_DISCONNECT,
            # Websocket state reported by signald
            WebsocketConnectionState.DISCONNECTED: (
                None
                if self._websocket_connection_state == BridgeStateEvent.BAD_CREDENTIALS
                else BridgeStateEvent.TRANSIENT_DISCONNECT
            ),
            WebsocketConnectionState.CONNECTING: BridgeStateEvent.CONNECTING,
            WebsocketConnectionState.CONNECTED: BridgeStateEvent.CONNECTED,
            WebsocketConnectionState.RECONNECTING: BridgeStateEvent.TRANSIENT_DISCONNECT,
            WebsocketConnectionState.DISCONNECTING: BridgeStateEvent.TRANSIENT_DISCONNECT,
            WebsocketConnectionState.AUTHENTICATION_FAILED: BridgeStateEvent.BAD_CREDENTIALS,
            WebsocketConnectionState.FAILED: BridgeStateEvent.TRANSIENT_DISCONNECT,
        }.get(evt.state)
        if bridge_state is None:
            self.log.info(f"Websocket state {evt.state} seen, not reporting new bridge state")
            return

        now = datetime.now()
        if bridge_state == BridgeStateEvent.TRANSIENT_DISCONNECT:

            async def wait_report_transient_disconnect():
                # Wait for 10 seconds (that should be enough for the bridge to get connected)
                # before sending a TRANSIENT_DISCONNECT.
                # self._latest_non_transient_disconnect_state will only be None if the bridge is
                # still starting.
                if self._latest_non_transient_disconnect_state is None:
                    await sleep(15)
                    if self._latest_non_transient_disconnect_state is None:
                        asyncio.create_task(self.push_bridge_state(bridge_state))

                # Wait for another minute. If the bridge stays in TRANSIENT_DISCONNECT for that
                # long, something terrible has happened (signald failed to restart, the internet
                # broke, etc.)
                await sleep(60)
                if (
                    self._latest_non_transient_disconnect_state
                    and now > self._latest_non_transient_disconnect_state
                ):
                    asyncio.create_task(
                        self.push_bridge_state(
                            BridgeStateEvent.UNKNOWN_ERROR,
                            message="Failed to restore connection to Signal",
                        )
                    )
                else:
                    self.log.info(
                        "New state since last TRANSIENT_DISCONNECT push, "
                        "not transitioning to UNKNOWN_ERROR."
                    )

            asyncio.create_task(wait_report_transient_disconnect())
        else:
            asyncio.create_task(self.push_bridge_state(bridge_state))
            self._latest_non_transient_disconnect_state = now

        self._websocket_connection_state = bridge_state

    async def _sync_puppet(self) -> None:
        puppet = await self.get_puppet()
        if not puppet:
            self.log.warning(f"Didn't find puppet for own address {self.address}")
            return
        if puppet.uuid and not self.uuid:
            self.uuid = puppet.uuid
            self.by_uuid[self.uuid] = self
        if puppet.custom_mxid != self.mxid and puppet.can_auto_login(self.mxid):
            self.log.info("Automatically enabling custom puppet")
            try:
                await puppet.switch_mxid(access_token="auto", mxid=self.mxid)
            except AutologinError as e:
                self.log.warning(f"Failed to enable custom puppet: {e}")

    async def sync(self) -> None:
        await self.sync_puppet()
        await self.sync_contacts()
        await self.sync_groups()
        self.log.debug("Sync complete")

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
        except Exception as e:
            self.log.exception("Error while syncing contacts")
            await self.handle_auth_failure(e)

    async def sync_groups(self) -> None:
        try:
            async with self._sync_lock:
                await self._sync_groups()
        except Exception as e:
            self.log.exception("Error while syncing groups")
            await self.handle_auth_failure(e)

    async def sync_contact(
        self, contact: Profile | Address, create_portals: bool = False, use_cache: bool = True
    ) -> None:
        self.log.trace("Syncing contact %s", contact)
        try:
            if isinstance(contact, Address):
                address = contact
                try:
                    profile = await self.bridge.signal.get_profile(
                        self.username, address, use_cache=use_cache
                    )
                except ProfileUnavailableError:
                    self.log.debug(f"Profile of {address} was not available when syncing")
                    profile = None
                if profile and profile.name:
                    self.log.trace("Got profile for %s: %s", address, profile)
            else:
                address = contact.address
                profile = contact
            puppet = await pu.Puppet.get_by_address(address, resolve_via=self.username)
            if not puppet:
                self.log.debug(f"Didn't find puppet for {address} while syncing contact")
                return
            await puppet.update_info(profile or address, self)
            if create_portals:
                portal = await po.Portal.get_by_chat_id(
                    puppet.uuid, receiver=self.username, create=True
                )
                await portal.create_matrix_room(self, profile or address)
        except Exception as e:
            await self.handle_auth_failure(e)
            raise

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
                await self._sync_group_v2(group, create_group_portal)
            except Exception:
                self.log.exception(f"Failed to sync group {group.id}")

    # region Database getters

    def _add_to_cache(self) -> None:
        self.by_mxid[self.mxid] = self
        if self.username:
            self.by_username[self.username] = self
        if self.uuid:
            self.by_uuid[self.uuid] = self

    @classmethod
    @async_getter_lock
    async def get_by_mxid(cls, mxid: UserID, /, *, create: bool = True) -> User | None:
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
    async def get_by_username(cls, username: str, /) -> User | None:
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
    async def get_by_uuid(cls, uuid: UUID, /) -> User | None:
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
    async def get_by_address(cls, address: Address) -> User | None:
        if address.uuid:
            return await cls.get_by_uuid(address.uuid)
        elif address.number:
            return await cls.get_by_username(address.number)
        else:
            raise ValueError("Given address is blank")

    @classmethod
    async def all_logged_in(cls) -> AsyncGenerator[User, None]:
        users = await super().all_logged_in()
        user: cls
        for user in users:
            try:
                yield cls.by_mxid[user.mxid]
            except KeyError:
                user._add_to_cache()
                yield user

    # endregion
