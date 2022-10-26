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

from typing import TYPE_CHECKING
import asyncio
import json
import logging

from aiohttp import web

from mausignald.errors import (
    InternalError,
    ScanTimeoutError,
    TimeoutException,
    UnregisteredUserError,
)
from mausignald.types import Account, Address, Profile
from mautrix.types import JSON, UserID
from mautrix.util.logging import TraceLogger

from .. import portal as po, puppet as pu, user as u
from ..util import normalize_number
from .segment_analytics import init as init_segment, track

if TYPE_CHECKING:
    from ..__main__ import SignalBridge


class ProvisioningAPI:
    log: TraceLogger = logging.getLogger("mau.web.provisioning")
    app: web.Application
    bridge: "SignalBridge"

    def __init__(
        self, bridge: "SignalBridge", shared_secret: str, segment_key: str | None
    ) -> None:
        self.bridge = bridge
        self.app = web.Application()
        self.shared_secret = shared_secret

        if segment_key:
            init_segment(segment_key)

        # Whoami
        self.app.router.add_get("/v1/api/whoami", self.status)
        self.app.router.add_get("/v2/whoami", self.status)

        # Logout
        self.app.router.add_options("/v1/api/logout", self.login_options)
        self.app.router.add_post("/v1/api/logout", self.logout)
        self.app.router.add_options("/v2/logout", self.login_options)
        self.app.router.add_post("/v2/logout", self.logout)

        # Link API (will be deprecated soon)
        self.app.router.add_options("/v1/api/link", self.login_options)
        self.app.router.add_options("/v1/api/link/wait", self.login_options)
        self.app.router.add_post("/v1/api/link", self.link)
        self.app.router.add_post("/v1/api/link/wait", self.link_wait)

        # New Login API
        self.app.router.add_options("/v2/link/new", self.login_options)
        self.app.router.add_options("/v2/link/wait/scan", self.login_options)
        self.app.router.add_options("/v2/link/wait/account", self.login_options)
        self.app.router.add_post("/v2/link/new", self.link_new)
        self.app.router.add_post("/v2/link/wait/scan", self.link_wait_for_scan)
        self.app.router.add_post("/v2/link/wait/account", self.link_wait_for_account)

        # Start new chat API
        self.app.router.add_get("/v2/contacts", self.list_contacts)
        self.app.router.add_get("/v2/resolve_identifier/{number}", self.resolve_identifier)
        self.app.router.add_post("/v2/pm/{number}", self.start_pm)

    @property
    def _acao_headers(self) -> dict[str, str]:
        return {
            "Access-Control-Allow-Origin": "*",
            "Access-Control-Allow-Headers": "Authorization, Content-Type",
            "Access-Control-Allow-Methods": "POST, OPTIONS",
        }

    @property
    def _headers(self) -> dict[str, str]:
        return {
            **self._acao_headers,
            "Content-Type": "application/json",
        }

    async def login_options(self, _: web.Request) -> web.Response:
        return web.Response(status=200, headers=self._headers)

    async def check_token(self, request: web.Request) -> "u.User":
        try:
            token = request.headers["Authorization"]
            token = token[len("Bearer ") :]
        except KeyError:
            raise web.HTTPBadRequest(
                text='{"error": "Missing Authorization header"}', headers=self._headers
            )
        except IndexError:
            raise web.HTTPBadRequest(
                text='{"error": "Malformed Authorization header"}', headers=self._headers
            )
        if token != self.shared_secret:
            raise web.HTTPForbidden(text='{"error": "Invalid token"}', headers=self._headers)
        try:
            user_id = request.query["user_id"]
        except KeyError:
            raise web.HTTPBadRequest(
                text='{"error": "Missing user_id query param"}', headers=self._headers
            )

        try:
            if not self.bridge.signal.is_connected:
                await self.bridge.signal.wait_for_connected(timeout=10)
        except asyncio.TimeoutError:
            raise web.HTTPServiceUnavailable(
                text=json.dumps({"error": "Cannot connect to signald"}), headers=self._headers
            )

        return await u.User.get_by_mxid(UserID(user_id))

    async def check_token_and_logged_in(self, request: web.Request) -> "u.User":
        user = await self.check_token(request)
        if not await user.is_logged_in():
            error = {"error": "You're not logged in"}
            raise web.HTTPNotFound(text=json.dumps(error), headers=self._headers)
        return user

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
                    username=user.username, address=user.address
                )
            except Exception as e:
                self.log.exception(f"Failed to get {user.username}'s profile for whoami")
                await user.handle_auth_failure(e)

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

    async def _shielded_link(self, user: "u.User", session_id: str, device_name: str) -> Account:
        try:
            self.log.debug(f"Starting finish link request for {user.mxid} / {session_id}")
            account = await self.bridge.signal.finish_link(
                session_id=session_id, device_name=device_name, overwrite=True
            )
        except TimeoutException:
            self.log.warning(f"Timed out waiting for linking to finish (session {session_id})")
            raise
        except Exception:
            self.log.exception(
                f"Fatal error while waiting for linking to finish (session {session_id})"
            )
            raise
        else:
            await user.on_signin(account)
            return account

    async def _try_shielded_link(
        self, user: "u.User", session_id: str, device_name: str
    ) -> web.Response:
        try:
            account = await asyncio.shield(self._shielded_link(user, session_id, device_name))
        except asyncio.CancelledError:
            self.log.warning(
                f"Client cancelled link wait request ({session_id}) before it finished"
            )
            raise
        except (TimeoutException, ScanTimeoutError):
            raise web.HTTPBadRequest(
                text='{"error": "Signal linking timed out"}', headers=self._headers
            )
        except InternalError:
            raise web.HTTPInternalServerError(
                text='{"error": "Fatal error in Signal linking"}', headers=self._headers
            )
        except Exception:
            raise web.HTTPInternalServerError(
                text='{"error": "Fatal error in Signal linking"}', headers=self._headers
            )
        else:
            return web.json_response(account.address.serialize())

    # region Old Link API

    async def link(self, request: web.Request) -> web.Response:
        user = await self.check_token(request)

        if await user.is_logged_in():
            raise web.HTTPConflict(
                text="""{"error": "You're already logged in"}""", headers=self._headers
            )

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

    async def link_wait(self, request: web.Request) -> web.Response:
        user = await self.check_token(request)
        if not user.command_status or user.command_status["action"] != "Link":
            raise web.HTTPBadRequest(
                text='{"error": "No Signal linking started"}', headers=self._headers
            )
        session_id = user.command_status["session_id"]
        device_name = user.command_status["device_name"]
        return await self._try_shielded_link(user, session_id, device_name)

    # endregion

    # region New Link API

    async def _get_request_data(self, request: web.Request) -> tuple[u.User, dict]:
        user = await self.check_token(request)
        if await user.is_logged_in():
            error_text = """{"error": "You're already logged in"}"""
            raise web.HTTPConflict(text=error_text, headers=self._headers)

        try:
            return user, (await request.json())
        except json.JSONDecodeError:
            raise web.HTTPBadRequest(text='{"error": "Malformed JSON"}', headers=self._headers)

    async def link_new(self, request: web.Request) -> web.Response:
        """
        Starts a new link session.

        Params: none

        Returns a JSON object with the following fields:

        * session_id: a session ID that should be used for all future link-related commands
          (wait_for_scan and wait_for_account).
        * uri: a URI that should be used to display the QR code.
        """
        user, _ = await self._get_request_data(request)
        self.log.debug(f"Getting session ID and link URI for {user.mxid}")
        try:
            sess = await self.bridge.signal.start_link()
            track(user, "$link_new_success")
            self.log.debug(
                f"Returning session ID and link URI for {user.mxid} / {sess.session_id}"
            )
            return web.json_response(sess.serialize(), headers=self._acao_headers)
        except Exception as e:
            error = {"error": f"Getting a new link failed: {e}"}
            track(user, "$link_new_failed", error)
            raise web.HTTPBadRequest(text=json.dumps(error), headers=self._headers)

    async def link_wait_for_scan(self, request: web.Request) -> web.Response:
        """
        Waits for the QR code associated with the provided session ID to be scanned.

        Params: a JSON object with the following field:

        * session_id: a session ID that you got from a call to /link/v2/new.
        """
        user, request_data = await self._get_request_data(request)
        try:
            session_id = request_data["session_id"]
        except KeyError:
            error_text = '{"error": "session_id not provided"}'
            raise web.HTTPBadRequest(text=error_text, headers=self._headers)

        try:
            await self.bridge.signal.wait_for_scan(session_id)
            track(user, "$qrcode_scanned")
        except Exception as e:
            error = {"error": f"Failed waiting for scan. Error: {e}"}
            self.log.exception(error["error"])
            track(user, "$qrcode_scan_failed", error)
            raise web.HTTPBadRequest(text=json.dumps(error), headers=self._headers)
        else:
            return web.json_response({}, headers=self._acao_headers)

    async def link_wait_for_account(self, request: web.Request) -> web.Response:
        """
        Waits for the link to the user's phone to complete.

        Params: a JSON object with the following fields:

        * session_id: a session ID that you got from a call to /link/v2/new.
        * device_name: the device name that will show up in Linked Devices on the user's device.

        Returns: a JSON object representing the user's account.
        """
        user, request_data = await self._get_request_data(request)
        try:
            session_id = request_data["session_id"]
            device_name = request_data.get("device_name", "Mautrix-Signal bridge")
        except KeyError:
            error = {"error": "session_id not provided"}
            track(user, "$wait_for_account_failed", error)
            raise web.HTTPBadRequest(text=json.dumps(error), headers=self._headers)

        try:
            resp = await self._try_shielded_link(user, session_id, device_name)
            track(user, "$wait_for_account_success")
            return resp
        except Exception as e:
            error = {"error": f"Failed waiting for account. Error: {e}"}
            self.log.exception(error["error"])
            track(user, "$wait_for_account_failed", error)
            raise web.HTTPBadRequest(text=json.dumps(error), headers=self._headers)

    # endregion

    # region Logout

    async def logout(self, request: web.Request) -> web.Response:
        user = await self.check_token_and_logged_in(request)
        await user.logout()
        return web.json_response({}, headers=self._acao_headers)

    # endregion

    # region Start new chat API

    async def list_contacts(self, request: web.Request) -> web.Response:
        user = await self.check_token_and_logged_in(request)
        contacts = await self.bridge.signal.list_contacts(user.username, use_cache=True)

        async def transform(profile: Profile) -> JSON:
            assert profile.address
            puppet = await pu.Puppet.get_by_address(profile.address, create=False)
            avatar_url = puppet.avatar_url if puppet else None
            return {
                "name": profile.name,
                "contact_name": profile.contact_name,
                "profile_name": profile.profile_name,
                "avatar_url": avatar_url,
                "address": profile.address.serialize(),
            }

        return web.json_response(
            {
                c.address.number: await transform(c)
                for c in contacts
                if c.address and c.address.number
            },
            headers=self._acao_headers,
        )

    async def _resolve_identifier(self, number: str, user: u.User) -> pu.Puppet:
        try:
            number = normalize_number(number)
        except Exception as e:
            raise web.HTTPBadRequest(text=json.dumps({"error": str(e)}), headers=self._headers)

        try:
            puppet: pu.Puppet = await pu.Puppet.get_by_number(
                number, resolve_via=user.username, raise_resolve=True
            )
        except UnregisteredUserError:
            error = {"error": f"The phone number {number} is not a registered Signal account"}
            raise web.HTTPNotFound(text=json.dumps(error), headers=self._headers)
        except Exception:
            self.log.exception(f"Unknown error fetching UUID for {number}")
            error = {"error": "Unknown error while fetching UUID"}
            raise web.HTTPInternalServerError(text=json.dumps(error), headers=self._headers)
        if not puppet:
            error = {
                "error": (
                    f"The phone number {number} doesn't seem to be a registered Signal account"
                )
            }
            raise web.HTTPNotFound(text=json.dumps(error), headers=self._headers)
        return puppet

    async def start_pm(self, request: web.Request) -> web.Response:
        user = await self.check_token_and_logged_in(request)
        puppet = await self._resolve_identifier(request.match_info["number"], user)

        portal = await po.Portal.get_by_chat_id(puppet.uuid, receiver=user.username, create=True)
        assert portal, "Portal.get_by_chat_id with create=True can't return None"

        if portal.mxid:
            await portal.main_intent.invite_user(portal.mxid, user.mxid)
            just_created = False
        else:
            await portal.create_matrix_room(user, puppet.address)
            just_created = True
        return web.json_response(
            {
                "room_id": portal.mxid,
                "just_created": just_created,
                "chat_id": puppet.address.serialize(),
                "other_user": {
                    "mxid": puppet.mxid,
                    "displayname": puppet.name,
                    "avatar_url": puppet.avatar_url,
                },
            },
            headers=self._acao_headers,
            status=201 if just_created else 200,
        )

    async def resolve_identifier(self, request: web.Request) -> web.Response:
        user = await self.check_token_and_logged_in(request)
        puppet = await self._resolve_identifier(request.match_info["number"], user)
        portal = await po.Portal.get_by_chat_id(puppet.uuid, receiver=user.username, create=False)
        return web.json_response(
            {
                "room_id": portal.mxid if portal else None,
                "chat_id": puppet.address.serialize(),
                "other_user": {
                    "mxid": puppet.mxid,
                    "displayname": puppet.name,
                    "avatar_url": puppet.avatar_url,
                },
            },
            headers=self._acao_headers,
        )

    # endregion
