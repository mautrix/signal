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


class LinkingError(RPCError):
    def __init__(self, message: str, number: int) -> None:
        super().__init__(message)
        self.number = number


class NotConnected(RPCError):
    pass


class LinkingTimeout(LinkingError):
    pass


class LinkingConflict(LinkingError):
    pass


def make_linking_error(data: Dict[str, Any]) -> LinkingError:
    message = data["message"]
    msg_number = data.get("msg_number")
    return {
        1: LinkingTimeout,
        3: LinkingConflict,
    }.get(msg_number, LinkingError)(message, msg_number)


class ResponseError(RPCError):
    def __init__(self, data: Dict[str, Any], message_override: Optional[str] = None) -> None:
        self.data = data
        super().__init__(message_override or data["message"])


class InvalidRequest(ResponseError):
    def __init__(self, data: Dict[str, Any]) -> None:
        super().__init__(data, ", ".join(data.get("validationResults", "")))


response_error_types = {
    "invalid_request": InvalidRequest,
}


def make_response_error(data: Dict[str, Any]) -> ResponseError:
    return response_error_types.get(data["type"], ResponseError)(data)
