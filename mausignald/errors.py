# Copyright (c) 2020 Tulir Asokan
#
# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this
# file, You can obtain one at http://mozilla.org/MPL/2.0/.
from typing import Any, Dict


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
