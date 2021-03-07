# Copyright (c) 2020 Tulir Asokan
#
# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this
# file, You can obtain one at http://mozilla.org/MPL/2.0/.
from typing import Any, Dict, Optional


class RPCError(Exception):
    pass


class UnexpectedError(RPCError):
    pass


class UnexpectedResponse(RPCError):
    def __init__(self, resp_type: str, data: Any) -> None:
        super().__init__(f"Got unexpected response type {resp_type}")
        self.resp_type = resp_type
        self.data = data


class NotConnected(RPCError):
    pass


class ResponseError(RPCError):
    def __init__(self, data: Dict[str, Any], message_override: Optional[str] = None) -> None:
        self.data = data
        super().__init__(message_override or data["message"])


class UnknownResponseError(ResponseError):
    def __init__(self, message: str) -> None:
        self.data = {}
        super(RPCError, self).__init__(message)


class InvalidRequest(ResponseError):
    def __init__(self, data: Dict[str, Any]) -> None:
        super().__init__(data, ", ".join(data.get("validationResults", "")))


class TimeoutException(ResponseError):
    pass


class UserAlreadyExistsError(ResponseError):
    def __init__(self, data: Dict[str, Any]) -> None:
        super().__init__(data, message_override="You're already logged in")


response_error_types = {
    "invalid_request": InvalidRequest,
    "TimeoutException": TimeoutException,
    "UserAlreadyExists": UserAlreadyExistsError,
}


def make_response_error(data: Dict[str, Any]) -> ResponseError:
    if isinstance(data, str):
        return UnknownResponseError(data)
    return response_error_types.get(data["type"], ResponseError)(data)
