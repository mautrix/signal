# Copyright (c) 2020 Tulir Asokan
#
# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this
# file, You can obtain one at http://mozilla.org/MPL/2.0/.
from typing import Optional, Dict, List, Callable, Awaitable, Any, Tuple
from uuid import UUID, uuid4
import asyncio
import logging
import json

from mautrix.util.logging import TraceLogger

from .errors import UnexpectedError, UnexpectedResponse

EventHandler = Callable[[Dict[str, Any]], Awaitable[None]]


class SignaldRPCClient:
    loop: asyncio.AbstractEventLoop
    log: TraceLogger

    socket_path: str
    _reader: Optional[asyncio.StreamReader]
    _writer: Optional[asyncio.StreamWriter]

    _response_waiters: Dict[UUID, asyncio.Future]
    _rpc_event_handlers: Dict[str, List[EventHandler]]

    def __init__(self, socket_path: str, log: Optional[TraceLogger] = None,
                 loop: Optional[asyncio.AbstractEventLoop] = None) -> None:
        self.socket_path = socket_path
        self.log = log or logging.getLogger("mausignald")
        self.loop = loop or asyncio.get_event_loop()
        self._reader = None
        self._writer = None
        self._response_waiters = {}
        self._rpc_event_handlers = {}

    async def connect(self) -> None:
        if self._writer is not None:
            return

        self._reader, self._writer = await asyncio.open_unix_connection(self.socket_path)
        self.loop.create_task(self._try_read_loop())

    async def disconnect(self) -> None:
        self._writer.write_eof()
        await self._writer.drain()
        self._writer = None
        self._reader = None

    def add_rpc_handler(self, method: str, handler: EventHandler) -> None:
        self._rpc_event_handlers.setdefault(method, []).append(handler)

    def remove_rpc_handler(self, method: str, handler: EventHandler) -> None:
        self._rpc_event_handlers.setdefault(method, []).remove(handler)

    async def _run_rpc_handler(self, command: str, req: Dict[str, Any]) -> None:
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

    async def _run_response_handlers(self, req_id: UUID, command: str, data: Any) -> None:
        try:
            waiter = self._response_waiters.pop(req_id)
        except KeyError:
            self.log.debug(f"Nobody waiting for response to {req_id}")
            return
        if command == "unexpected_error":
            try:
                waiter.set_exception(UnexpectedError(data["message"]))
            except KeyError:
                waiter.set_exception(UnexpectedError("Unexpected error with no message"))
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
            await self._run_rpc_handler(req_type, req)
        else:
            await self._run_response_handlers(UUID(req_id), req_type, req.get("data"))

    async def _try_read_loop(self) -> None:
        try:
            await self._read_loop()
        except Exception:
            self.log.exception("Fatal error in read loop")

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
        self.log.debug("Reader disconnected")
        self._reader = None
        self._writer = None

    def _create_request(self, command: str, req_id: Optional[UUID] = None, **data: Any
                        ) -> Tuple[asyncio.Future, Dict[str, Any]]:
        req_id = req_id or uuid4()
        req = {"id": str(req_id), "type": command, **data}
        self.log.trace("Request %s: %s %s", req_id, command, data)
        return self._wait_response(req_id), req

    def _wait_response(self, req_id: UUID) -> asyncio.Future:
        try:
            future = self._response_waiters[req_id]
        except KeyError:
            future = self._response_waiters[req_id] = self.loop.create_future()
        return future

    async def _send_request(self, data: Dict[str, Any]) -> None:
        self._writer.write(json.dumps(data).encode("utf-8"))
        self._writer.write(b"\n")
        await self._writer.drain()
        self.log.trace("Sent data to server server: %s", data)

    async def _raw_request(self, command: str, req_id: Optional[UUID] = None, **data: Any
                           ) -> Tuple[str, Dict[str, Any]]:
        future, data = self._create_request(command, req_id, **data)
        await self._send_request(data)
        return await future

    async def request(self, command: str, expected_response: str, **data: Any) -> Any:
        resp_type, resp_data = await self._raw_request(command, **data)
        if resp_type != expected_response:
            raise UnexpectedResponse(resp_type, resp_data)
        return resp_data

    async def request_nowait(self, command: str, **data: Any) -> None:
        _, req = self._create_request(command, **data)
        await self._send_request(req)
