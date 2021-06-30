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
from typing import Awaitable, Dict, TYPE_CHECKING
import logging
import asyncio
import json

from aiohttp import web

from mausignald.types import Address, Account
from mausignald.errors import TimeoutException
from mautrix.types import UserID
from mautrix.util.logging import TraceLogger

from .. import user as u

if TYPE_CHECKING:
    from ..__main__ import SignalBridge


class ProvisioningAPI:
    log: TraceLogger = logging.getLogger("mau.web.provisioning")
    app: web.Application
    bridge: 'SignalBridge'

    def __init__(self, bridge: 'SignalBridge', shared_secret: str) -> None:
        self.bridge = bridge
        self.app = web.Application()
        self.shared_secret = shared_secret
        self.app.router.add_get("/api/whoami", self.status)
        self.app.router.add_options("/api/link", self.login_options)
        self.app.router.add_options("/api/link/wait", self.login_options)
        # self.app.router.add_options("/api/register", self.login_options)
        # self.app.router.add_options("/api/register/code", self.login_options)
        self.app.router.add_options("/api/logout", self.login_options)
        self.app.router.add_post("/api/link", self.link)
        self.app.router.add_post("/api/link/wait", self.link_wait)
        # self.app.router.add_post("/api/register", self.register)
        # self.app.router.add_post("/api/register/code", self.register_code)
        self.app.router.add_post("/api/logout", self.logout)

    @property
    def _acao_headers(self) -> Dict[str, str]:
        return {
            "Access-Control-Allow-Origin": "*",
            "Access-Control-Allow-Headers": "Authorization, Content-Type",
            "Access-Control-Allow-Methods": "POST, OPTIONS",
        }

    @property
    def _headers(self) -> Dict[str, str]:
        return {
            **self._acao_headers,
            "Content-Type": "application/json",
        }

    async def login_options(self, _: web.Request) -> web.Response:
        return web.Response(status=200, headers=self._headers)

    async def check_token(self, request: web.Request) -> 'u.User':
        try:
            token = request.headers["Authorization"]
            token = token[len("Bearer "):]
        except KeyError:
            raise web.HTTPBadRequest(text='{"error": "Missing Authorization header"}',
                                     headers=self._headers)
        except IndexError:
            raise web.HTTPBadRequest(text='{"error": "Malformed Authorization header"}',
                                     headers=self._headers)
        if token != self.shared_secret:
            raise web.HTTPForbidden(text='{"error": "Invalid token"}', headers=self._headers)
        try:
            user_id = request.query["user_id"]
        except KeyError:
            raise web.HTTPBadRequest(text='{"error": "Missing user_id query param"}',
                                     headers=self._headers)

        if not self.bridge.signal.is_connected:
            await self.bridge.signal.wait_for_connected()

        return await u.User.get_by_mxid(UserID(user_id))

    async def status(self, request: web.Request) -> web.Response:
        user = await self.check_token(request)
        data = {
            "permissions": user.permission_level,
            "mxid": user.mxid,
            "signal": None,
        }
        if await user.is_logged_in():
            try:
                profile = await self.bridge.signal.get_profile(
                    username=user.username, address=Address(number=user.username))
            except Exception as e:
                self.log.exception(f"Failed to get {user.username}'s profile for whoami")
                data["signal"] = {
                    "number": user.username,
                    "ok": False,
                    "error": str(e),
                }
            else:
                addr = profile.address if profile else None
                number = addr.number if addr else None
                uuid = addr.uuid if addr else None
                data["signal"] = {
                    "number": number or user.username,
                    "uuid": str(uuid or user.uuid or ""),
                    "name": profile.name if profile else None,
                    "ok": True,
                }
        return web.json_response(data, headers=self._acao_headers)

    async def link(self, request: web.Request) -> web.Response:
        user = await self.check_token(request)

        if await user.is_logged_in():
            raise web.HTTPConflict(text='''{"error": "You're already logged in"}''',
                                   headers=self._headers)

        try:
            data = await request.json()
        except json.JSONDecodeError:
            raise web.HTTPBadRequest(text='{"error": "Malformed JSON"}', headers=self._headers)

        device_name = data.get("device_name", "Mautrix-Signal bridge")
        sess = await self.bridge.signal.start_link()

        user.command_status = {
            "action": "Link",
            "session_id": sess.session_id,
            "device_name": device_name,
        }

        self.log.debug(f"Returning linking URI for {user.mxid} / {sess.session_id}")
        return web.json_response({"uri": sess.uri}, headers=self._acao_headers)

    async def _shielded_link(self, user: 'u.User', session_id: str, device_name: str) -> Account:
        try:
            self.log.debug(f"Starting finish link request for {user.mxid} / {session_id}")
            account = await self.bridge.signal.finish_link(session_id=session_id, overwrite=True,
                                                           device_name=device_name)
        except TimeoutException:
            self.log.warning(f"Timed out waiting for linking to finish (session {session_id})")
            raise
        except Exception:
            self.log.exception("Fatal error while waiting for linking to finish "
                               f"(session {session_id})")
            raise
        else:
            await user.on_signin(account)
            return account

    async def link_wait(self, request: web.Request) -> web.Response:
        user = await self.check_token(request)
        if not user.command_status or user.command_status["action"] != "Link":
            raise web.HTTPBadRequest(text='{"error": "No Signal linking started"}',
                                     headers=self._headers)
        session_id = user.command_status["session_id"]
        device_name = user.command_status["device_name"]
        try:
            account = await asyncio.shield(self._shielded_link(user, session_id, device_name))
        except asyncio.CancelledError:
            self.log.warning(f"Client cancelled link wait request ({session_id})"
                             " before it finished")
        except TimeoutException:
            raise web.HTTPBadRequest(text='{"error": "Signal linking timed out"}',
                                     headers=self._headers)
        except Exception:
            raise web.HTTPInternalServerError(text='{"error": "Fatal error in Signal linking"}',
                                              headers=self._headers)
        else:
            return web.json_response(account.address.serialize())

    async def logout(self, request: web.Request) -> web.Response:
        user = await self.check_token(request)
        if not await user.is_logged_in():
            raise web.HTTPNotFound(text='''{"error": "You're not logged in"}''',
                                   headers=self._headers)
        await user.logout()
        return web.json_response({}, headers=self._acao_headers)
