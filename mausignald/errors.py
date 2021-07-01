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
    def __init__(self, data: Dict[str, Any], error_type: Optional[str] = None,
                 message_override: Optional[str] = None) -> None:
        self.data = data
        msg = message_override or data["message"]
        if error_type:
            msg = f"{error_type}: {msg}"
        super().__init__(msg)


class TimeoutException(ResponseError):
    pass


class UnknownIdentityKey(ResponseError):
    pass


class CaptchaRequired(ResponseError):
    pass


class AuthorizationFailedException(ResponseError):
    pass


class UserAlreadyExistsError(ResponseError):
    def __init__(self, data: Dict[str, Any]) -> None:
        super().__init__(data, message_override="You're already logged in")


class RequestValidationFailure(ResponseError):
    def __init__(self, data: Dict[str, Any]) -> None:
        results = data["validationResults"]
        result_str = ", ".join(results) if isinstance(results, list) else str(results)
        super().__init__(data, message_override=result_str)


response_error_types = {
    "invalid_request": RequestValidationFailure,
    "TimeoutException": TimeoutException,
    "UserAlreadyExists": UserAlreadyExistsError,
    "RequestValidationFailure": RequestValidationFailure,
    "UnknownIdentityKey": UnknownIdentityKey,
    "CaptchaRequired": CaptchaRequired,
    "AuthorizationFailedException": AuthorizationFailedException,
    # TODO add rest from https://gitlab.com/signald/signald/-/tree/main/src/main/java/io/finn/signald/exceptions
}


def make_response_error(data: Dict[str, Any]) -> ResponseError:
    error_data = data["error"]
    if isinstance(error_data, str):
        error_data = {"message": error_data}
    elif not isinstance(error_data, dict):
        error_data = {"message": str(error_data)}
    if "message" not in error_data:
        error_data["message"] = "no message, see signald logs"
    error_type = data.get("error_type")
    try:
        error_class = response_error_types[error_type]
    except KeyError:
        return ResponseError(error_data, error_type=error_type)
    else:
        return error_class(error_data)
