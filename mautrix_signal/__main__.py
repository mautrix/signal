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
import asyncio
import logging

from mautrix.bridge import Bridge
from mautrix.bridge.state_store.asyncpg import PgBridgeStateStore
from mautrix.types import RoomID, UserID
from mautrix.util.async_db import Database

from .version import version, linkified_version
from .config import Config
from .db import upgrade_table, init as init_db
from .matrix import MatrixHandler
from .signal import SignalHandler
from .user import User
from .portal import Portal
from .puppet import Puppet
from .web import ProvisioningAPI
from . import commands


class SignalBridge(Bridge):
    module = "mautrix_signal"
    name = "mautrix-signal"
    command = "python -m mautrix-signal"
    description = "A Matrix-Signal puppeting bridge."
    repo_url = "https://github.com/mautrix/signal"
    real_user_content_key = "net.maunium.signal.puppet"
    version = version
    markdown_version = linkified_version
    config_class = Config
    matrix_class = MatrixHandler

    db: Database
    matrix: MatrixHandler
    signal: SignalHandler
    config: Config
    state_store: PgBridgeStateStore
    provisioning_api: ProvisioningAPI
    periodic_sync_task: asyncio.Task

    def make_state_store(self) -> None:
        self.state_store = PgBridgeStateStore(self.db, self.get_puppet, self.get_double_puppet)

    def prepare_db(self) -> None:
        self.db = Database(self.config["appservice.database"], upgrade_table=upgrade_table,
                           loop=self.loop, db_args=self.config["appservice.database_opts"])
        init_db(self.db)

    def prepare_bridge(self) -> None:
        self.signal = SignalHandler(self)
        super().prepare_bridge()
        cfg = self.config["bridge.provisioning"]
        self.provisioning_api = ProvisioningAPI(self, cfg["shared_secret"])
        self.az.app.add_subapp(cfg["prefix"], self.provisioning_api.app)

    async def start(self) -> None:
        await self.db.start()
        await self.state_store.upgrade_table.upgrade(self.db.pool)
        if self.matrix.e2ee:
            self.matrix.e2ee.crypto_db.override_pool(self.db.pool)
        User.init_cls(self)
        self.add_startup_actions(Puppet.init_cls(self))
        Portal.init_cls(self)
        if self.config["bridge.resend_bridge_info"]:
            self.add_startup_actions(self.resend_bridge_info())
        self.add_startup_actions(self.signal.start())
        await super().start()
        self.periodic_sync_task = asyncio.create_task(self._periodic_sync_loop())

    @staticmethod
    async def _actual_periodic_sync_loop(log: logging.Logger, interval: int) -> None:
        while True:
            try:
                await asyncio.sleep(interval)
            except asyncio.CancelledError:
                return
            log.info("Executing periodic syncs")
            for user in User.by_username.values():
                try:
                    await user.sync()
                except asyncio.CancelledError:
                    return
                except Exception:
                    log.exception("Error while syncing %s", user.mxid)

    async def _periodic_sync_loop(self) -> None:
        log = logging.getLogger("mau.periodic_sync")
        interval = self.config["bridge.periodic_sync"]
        if interval <= 0:
            log.debug("Periodic sync is not enabled")
            return
        log.debug("Starting periodic sync loop")
        await self._actual_periodic_sync_loop(log, interval)
        log.debug("Periodic sync stopped")

    def prepare_stop(self) -> None:
        self.add_shutdown_actions(self.signal.stop())
        for puppet in Puppet.by_custom_mxid.values():
            puppet.stop()

    async def resend_bridge_info(self) -> None:
        self.config["bridge.resend_bridge_info"] = False
        self.config.save()
        self.log.info("Re-sending bridge info state event to all portals")
        async for portal in Portal.all_with_room():
            await portal.update_bridge_info()
        self.log.info("Finished re-sending bridge info state events")

    async def get_user(self, user_id: UserID, create: bool = True) -> User:
        return await User.get_by_mxid(user_id, create=create)

    async def get_portal(self, room_id: RoomID) -> Portal:
        return await Portal.get_by_mxid(room_id)

    async def get_puppet(self, user_id: UserID, create: bool = False) -> Puppet:
        return await Puppet.get_by_mxid(user_id, create=create)

    async def get_double_puppet(self, user_id: UserID) -> Puppet:
        return await Puppet.get_by_custom_mxid(user_id)

    def is_bridge_ghost(self, user_id: UserID) -> bool:
        return bool(Puppet.get_id_from_mxid(user_id))

    async def count_logged_in_users(self) -> int:
        return len([user for user in User.by_username.values() if user.username])


SignalBridge().run()
