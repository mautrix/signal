# Copyright (c) 2022 Tulir Asokan
#
# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this
# file, You can obtain one at http://mozilla.org/MPL/2.0/.
from __future__ import annotations

from typing import Any, Awaitable, Callable, Dict
from uuid import UUID, uuid4
import asyncio
import json
import logging

from mautrix.util.logging import TraceLogger

from .errors import NotConnected, UnexpectedError, UnexpectedResponse, make_response_error

EventHandler = Callable[[Dict[str, Any]], Awaitable[None]]

# These are synthetic RPC events for registering callbacks on socket
# connect and disconnect.
CONNECT_EVENT = "_socket_connected"
DISCONNECT_EVENT = "_socket_disconnected"
_SOCKET_LIMIT = 1024 * 1024  # 1 MiB


class SignaldRPCClient:
    loop: asyncio.AbstractEventLoop
    log: TraceLogger

    socket_path: str
    _reader: asyncio.StreamReader | None
    _writer: asyncio.StreamWriter | None
    is_connected: bool
    _connect_future: asyncio.Future
    _communicate_task: asyncio.Task | None

    _response_waiters: dict[UUID, asyncio.Future]
    _rpc_event_handlers: dict[str, list[EventHandler]]

    def __init__(
        self,
        socket_path: str,
        log: TraceLogger | None = None,
        loop: asyncio.AbstractEventLoop | None = None,
    ) -> None:
        self.socket_path = socket_path
        self.log = log or logging.getLogger("mausignald")
        self.loop = loop or asyncio.get_event_loop()
        self._reader = None
        self._writer = None
        self._communicate_task = None
        self.is_connected = False
        self._connect_future = self.loop.create_future()
        self._response_waiters = {}
        self._rpc_event_handlers = {CONNECT_EVENT: [], DISCONNECT_EVENT: []}
        self.add_rpc_handler(DISCONNECT_EVENT, self._abandon_responses)

    async def wait_for_connected(self, timeout: int | None = None) -> bool:
        if self.is_connected:
            return True
        await asyncio.wait_for(asyncio.shield(self._connect_future), timeout)
        return self.is_connected

    async def connect(self) -> None:
        if self._writer is not None:
            return

        self._communicate_task = asyncio.create_task(self._communicate_forever())
        await self._connect_future

    async def _communicate_forever(self) -> None:
        while True:
            try:
                await self._communicate()
            except Exception:
                self.log.exception("Unknown error in signald socket")
                await asyncio.sleep(30)

    async def _communicate(self) -> None:
        try:
            self.log.debug(f"Connecting to {self.socket_path}...")
            self._reader, self._writer = await asyncio.open_unix_connection(
                self.socket_path, limit=_SOCKET_LIMIT
            )
        except OSError as e:
            self.log.error(f"Connection to {self.socket_path} failed: {e}")
            await asyncio.sleep(5)
            return

        read_loop = asyncio.create_task(self._try_read_loop())
        self.is_connected = True
        asyncio.create_task(self._run_rpc_handler(CONNECT_EVENT, {}))
        self._connect_future.set_result(True)

        await read_loop
        self.is_connected = False
        self._connect_future = self.loop.create_future()
        await self._run_rpc_handler(DISCONNECT_EVENT, {})

    async def disconnect(self) -> None:
        if self._writer is not None:
            self._writer.write_eof()
            await self._writer.drain()
            if self._communicate_task:
                self._communicate_task.cancel()
                self._communicate_task = None
            self._writer = None
            self._reader = None
            self.is_connected = False
            self._connect_future = self.loop.create_future()

    def add_rpc_handler(self, method: str, handler: EventHandler) -> None:
        self._rpc_event_handlers.setdefault(method, []).append(handler)

    def remove_rpc_handler(self, method: str, handler: EventHandler) -> None:
        self._rpc_event_handlers.setdefault(method, []).remove(handler)

    async def _run_rpc_handler(self, command: str, req: dict[str, Any]) -> None:
        try:
            handlers = self._rpc_event_handlers[command]
        except KeyError:
            self.log.warning("No handlers for RPC request %s", command)
            self.log.trace("Data unhandled request: %s", req)
        else:
            for handler in handlers:
                try:
                    await handler(req)
                except Exception:
                    self.log.exception("Exception in RPC event handler")

    def _run_response_handlers(self, req_id: UUID, command: str, req: Any) -> None:
        try:
            waiter = self._response_waiters.pop(req_id)
        except KeyError:
            self.log.debug(f"Nobody waiting for response to {req_id}")
            return
        data = req.get("data")
        if command == "unexpected_error":
            try:
                waiter.set_exception(UnexpectedError(data["message"]))
            except KeyError:
                waiter.set_exception(UnexpectedError("Unexpected error with no message"))
        # elif data and "error" in data and isinstance(data["error"], (str, dict)):
        #     waiter.set_exception(make_response_error(data))
        elif "error" in req and isinstance(req["error"], (str, dict)):
            waiter.set_exception(make_response_error(req))
        else:
            waiter.set_result((command, data))

    async def _handle_incoming_line(self, line: str) -> None:
        try:
            req = json.loads(line)
        except json.JSONDecodeError:
            self.log.debug(f"Got non-JSON data from server: {line}")
            return
        try:
            req_type = req["type"]
        except KeyError:
            self.log.debug(f"Got invalid request from server: {line}")
            return

        self.log.trace("Got data from server: %s", req)

        req_id = req.get("id")
        if req_id is None:
            asyncio.create_task(self._run_rpc_handler(req_type, req))
        else:
            self._run_response_handlers(UUID(req_id), req_type, req)

    async def _try_read_loop(self) -> None:
        try:
            await self._read_loop()
        except Exception:
            self.log.exception("Fatal error in read loop")
        else:
            self.log.debug("Reader disconnected")
        finally:
            self._reader = None
            self._writer = None

    async def _read_loop(self) -> None:
        while self._reader is not None and not self._reader.at_eof():
            line = await self._reader.readline()
            if not line:
                continue
            try:
                line_str = line.decode("utf-8")
            except UnicodeDecodeError:
                self.log.exception("Got non-unicode request from server: %s", line)
                continue
            try:
                await self._handle_incoming_line(line_str)
            except Exception:
                self.log.exception("Failed to handle incoming request %s", line_str)

    def _create_request(
        self, command: str, req_id: UUID | None = None, **data: Any
    ) -> tuple[asyncio.Future, dict[str, Any]]:
        req_id = req_id or uuid4()
        req = {"id": str(req_id), "type": command, **data}
        self.log.debug("Request %s: %s", req_id, command)
        self.log.trace("Request %s: %s with data: %s", req_id, command, data)
        return self._wait_response(req_id), req

    def _wait_response(self, req_id: UUID) -> asyncio.Future:
        try:
            future = self._response_waiters[req_id]
        except KeyError:
            future = self._response_waiters[req_id] = self.loop.create_future()
        return future

    async def _abandon_responses(self, unused_data: dict[str, Any]) -> None:
        for req_id, waiter in self._response_waiters.items():
            if not waiter.done():
                self.log.trace(f"Abandoning response for {req_id}")
                waiter.set_exception(
                    NotConnected("Disconnected from signald before RPC completed")
                )

    async def _send_request(self, data: dict[str, Any]) -> None:
        if self._writer is None:
            raise NotConnected("Not connected to signald")

        self._writer.write(json.dumps(data).encode("utf-8"))
        self._writer.write(b"\n")
        await self._writer.drain()
        self.log.trace("Sent data to server server: %s", data)

    async def _raw_request(
        self, command: str, req_id: UUID | None = None, **data: Any
    ) -> tuple[str, dict[str, Any]]:
        future, data = self._create_request(command, req_id, **data)
        await self._send_request(data)
        return await asyncio.shield(future)

    async def _request(self, command: str, expected_response: str, **data: Any) -> Any:
        resp_type, resp_data = await self._raw_request(command, **data)
        if resp_type != expected_response:
            raise UnexpectedResponse(resp_type, resp_data)
        return resp_data

    async def request_v1(self, command: str, **data: Any) -> Any:
        return await self._request(command, expected_response=command, version="v1", **data)
