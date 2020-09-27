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
from typing import Awaitable, Dict
import logging
import json

from aiohttp import web

from mautrix.types import UserID
from mautrix.util.logging import TraceLogger

from .. import user as u


class ProvisioningAPI:
    log: TraceLogger = logging.getLogger("mau.web.provisioning")
    app: web.Application

    def __init__(self, shared_secret: str) -> None:
        self.app = web.Application()
        self.shared_secret = shared_secret
        self.app.router.add_get("/api/whoami", self.status)
        self.app.router.add_options("/api/login", self.login_options)
        self.app.router.add_post("/api/login", self.login)
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

    def check_token(self, request: web.Request) -> Awaitable['u.User']:
        try:
            token = request.headers["Authorization"]
            token = token[len("Bearer "):]
        except KeyError:
            raise web.HTTPBadRequest(body='{"error": "Missing Authorization header"}',
                                     headers=self._headers)
        except IndexError:
            raise web.HTTPBadRequest(body='{"error": "Malformed Authorization header"}',
                                     headers=self._headers)
        if token != self.shared_secret:
            raise web.HTTPForbidden(body='{"error": "Invalid token"}', headers=self._headers)
        try:
            user_id = request.query["user_id"]
        except KeyError:
            raise web.HTTPBadRequest(body='{"error": "Missing user_id query param"}',
                                     headers=self._headers)

        return u.User.get_by_mxid(UserID(user_id))

    async def status(self, request: web.Request) -> web.Response:
        user = await self.check_token(request)
        data = {
            "permissions": user.permission_level,
            "mxid": user.mxid,
            "twitter": None,
        }
        if await user.is_logged_in():
            data["twitter"] = (await user.get_info()).serialize()
        return web.json_response(data, headers=self._acao_headers)

    async def login(self, request: web.Request) -> web.Response:
        user = await self.check_token(request)

        try:
            data = await request.json()
        except json.JSONDecodeError:
            raise web.HTTPBadRequest(body='{"error": "Malformed JSON"}', headers=self._headers)

        try:
            auth_token = data["auth_token"]
            csrf_token = data["csrf_token"]
        except KeyError:
            raise web.HTTPBadRequest(body='{"error": "Missing keys"}', headers=self._headers)

        try:
            await user.connect(auth_token=auth_token, csrf_token=csrf_token)
        except Exception:
            self.log.debug("Failed to log in", exc_info=True)
            raise web.HTTPUnauthorized(body='{"error": "Twitter authorization failed"}',
                                       headers=self._headers)
        return web.Response(body='{}', status=200, headers=self._headers)

    async def logout(self, request: web.Request) -> web.Response:
        user = await self.check_token(request)
        await user.logout()
        return web.json_response({}, headers=self._acao_headers)
