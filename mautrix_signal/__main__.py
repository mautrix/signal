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
from typing import Any, Dict
from random import uniform
import asyncio
import logging
import time

from mautrix.bridge import Bridge
from mautrix.types import MessageType, RoomID, TextMessageEventContent, UserID
from mautrix.util.opt_prometheus import Gauge

from . import commands
from .config import Config
from .db import init as init_db, upgrade_table
from .matrix import MatrixHandler
from .portal import Portal
from .puppet import Puppet
from .signal import SignalHandler
from .user import User
from .version import linkified_version, version
from .web import ProvisioningAPI

ACTIVE_USER_METRICS_INTERVAL_S = 60
ONE_DAY_MS = 24 * 60 * 60 * 1000
SYNC_JITTER = 10

METRIC_ACTIVE_PUPPETS = Gauge(
    "bridge_active_puppets_total", "Number of active Signal users bridged into Matrix"
)
METRIC_BLOCKING = Gauge("bridge_blocked", "Is the bridge currently blocking messages")


class SignalBridge(Bridge):
    module = "mautrix_signal"
    name = "mautrix-signal"
    command = "python -m mautrix-signal"
    description = "A Matrix-Signal puppeting bridge."
    repo_url = "https://github.com/mautrix/signal"
    version = version
    markdown_version = linkified_version
    config_class = Config
    matrix_class = MatrixHandler
    upgrade_table = upgrade_table

    matrix: MatrixHandler
    signal: SignalHandler
    config: Config
    provisioning_api: ProvisioningAPI
    periodic_sync_task: asyncio.Task
    periodic_active_metrics_task: asyncio.Task
    bridge_blocked: bool = False
    last_blocking_notification: int = 0

    def prepare_db(self) -> None:
        super().prepare_db()
        init_db(self.db)

    def prepare_bridge(self) -> None:
        self.signal = SignalHandler(self)
        super().prepare_bridge()
        cfg = self.config["bridge.provisioning"]
        self.provisioning_api = ProvisioningAPI(self, cfg["shared_secret"], cfg["segment_key"])
        self.az.app.add_subapp(cfg["prefix"], self.provisioning_api.app)

    async def start(self) -> None:
        User.init_cls(self)
        self.add_startup_actions(Puppet.init_cls(self))
        Portal.init_cls(self)
        self.add_startup_actions(Portal.restart_scheduled_disappearing())
        if self.config["bridge.resend_bridge_info"]:
            self.add_startup_actions(self.resend_bridge_info())
        self.add_startup_actions(self.signal.start())
        await super().start()
        self.periodic_sync_task = asyncio.create_task(self._periodic_sync_loop())
        self.periodic_active_metrics_task = asyncio.create_task(self._loop_active_puppet_metric())

    @staticmethod
    async def _actual_periodic_sync_loop(log: logging.Logger, interval: int) -> None:
        while True:
            try:
                await asyncio.sleep(interval)
            except asyncio.CancelledError:
                return
            log.info("Executing periodic syncs")
            for user in User.by_username.values():
                # Add some randomness to the sync to avoid a thundering herd
                await asyncio.sleep(uniform(0, SYNC_JITTER))
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

    async def _update_active_puppet_metric(self, log: logging.Logger) -> None:
        maxActivityDays = self.config["bridge.limits.puppet_inactivity_days"]
        minActivityDays = self.config["bridge.limits.min_puppet_activity_days"]
        activeUsers = await Puppet.recently_active_count(minActivityDays, maxActivityDays)

        blockOnLimitReached = self.config["bridge.limits.block_on_limit_reached"]
        maxPuppetLimit = self.config["bridge.limits.max_puppet_limit"]
        if blockOnLimitReached is not None and maxPuppetLimit is not None:
            blocked = maxPuppetLimit < activeUsers
            if blocked and not self.bridge_blocked:
                await self._notify_bridge_blocked()
            if not blocked and self.bridge_blocked:
                await self._notify_bridge_blocked(False)
            self.bridge_blocked = blocked
            METRIC_BLOCKING.set(int(self.bridge_blocked))
        log.debug("Current active puppet count is %d", activeUsers)
        METRIC_ACTIVE_PUPPETS.set(activeUsers)

    async def _loop_active_puppet_metric(self) -> None:
        log = logging.getLogger("mau.active_puppet_metric")

        while True:
            try:
                await asyncio.sleep(ACTIVE_USER_METRICS_INTERVAL_S)
            except asyncio.CancelledError:
                return
            log.info("Executing periodic active puppet metric check")
            try:
                await self._update_active_puppet_metric(log)
            except asyncio.CancelledError:
                return
            except Exception as e:
                log.exception("Error while checking", e)

    async def count_logged_in_users(self) -> int:
        return len([user for user in User.by_username.values() if user.username])

    async def manhole_global_namespace(self, user_id: UserID) -> Dict[str, Any]:
        return {
            **await super().manhole_global_namespace(user_id),
            "User": User,
            "Portal": Portal,
            "Puppet": Puppet,
        }

    async def _notify_bridge_blocked(self, is_blocked: bool = True) -> None:
        msg = self.config["bridge.limits.block_ends_notification"]
        if is_blocked:
            msg = self.config["bridge.limits.block_begins_notification"]
            next_notification = (
                self.last_blocking_notification
                + self.config["bridge.limits.block_notification_interval_seconds"]
            )
            # We're only checking if the block is active, since the unblock notification will not be resent and we want it ASAP
            if next_notification > int(time.time()):
                return
            self.last_blocking_notification = int(time.time())

        admins = list(
            map(
                lambda entry: entry[0],
                filter(
                    lambda entry: entry[1] == "admin", self.config["bridge.permissions"].items()
                ),
            )
        )
        if len(admins) == 0:
            self.log.debug("No bridge admins to notify about the bridge being blocked")
            return

        self.log.debug(f'Notifying bridge admins ({",".join(admins)}) about bridge being blocked')
        for admin_mxid in admins:
            admin = await User.get_by_mxid(admin_mxid, True)  # create if needed
            if admin.notice_room is None:
                room_id = await self.az.intent.create_room(
                    name="Signal Bridge notice room",
                    is_direct=True,
                    invitees=[admin_mxid],
                )
                admin.notice_room = room_id
                admin.update()

            await self.az.intent.send_message(
                admin.notice_room,
                TextMessageEventContent(
                    # \u26a0 is a warning sign
                    msgtype=MessageType.NOTICE,
                    body=f"\u26a0 {msg}",
                ),
            )


SignalBridge().run()
