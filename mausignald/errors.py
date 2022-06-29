# Copyright (c) 2022 Tulir Asokan
#
# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this
# file, You can obtain one at http://mozilla.org/MPL/2.0/.
from __future__ import annotations

from typing import Any


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
    def __init__(
        self,
        data: dict[str, Any],
        error_type: str | None = None,
        message_override: str | None = None,
    ) -> None:
        self.data = data
        msg = message_override or data["message"]
        if error_type:
            msg = f"{error_type}: {msg}"
        super().__init__(msg)


class TimeoutException(ResponseError):
    pass


class UnknownIdentityKey(ResponseError):
    pass


class CaptchaRequiredError(ResponseError):
    pass


class AuthorizationFailedError(ResponseError):
    pass


class ScanTimeoutError(ResponseError):
    pass


class UserAlreadyExistsError(ResponseError):
    def __init__(self, data: dict[str, Any]) -> None:
        super().__init__(data, message_override="You're already logged in")


class OwnProfileKeyDoesNotExistError(ResponseError):
    def __init__(self, data: dict[str, Any]) -> None:
        super().__init__(
            data,
            message_override=(
                "Cannot find own profile key. Please make sure you have a Signal profile name set."
            ),
        )


class RequestValidationFailure(ResponseError):
    def __init__(self, data: dict[str, Any]) -> None:
        results = data["validationResults"]
        result_str = ", ".join(results) if isinstance(results, list) else str(results)
        super().__init__(data, message_override=result_str)


class InternalError(ResponseError):
    """
    If you find yourself using this, please file an issue against signald. We want to make
    explicit error types at the protocol for anything a client might normally expect.
    """

    def __init__(self, data: dict[str, Any]) -> None:
        exceptions = data.get("exceptions", [])
        self.exceptions = exceptions
        message = data.get("message")
        super().__init__(data, error_type=", ".join(exceptions), message_override=message)


class AttachmentTooLargeError(ResponseError):
    def __init__(self, data: dict[str, Any]) -> None:
        self.filename = data.get("filename", "")
        super().__init__(data, message_override="File is over the 100MB limit.")


class UnregisteredUserError(ResponseError):
    pass


class ProfileUnavailableError(ResponseError):
    pass


response_error_types = {
    "invalid_request": RequestValidationFailure,
    "TimeoutException": TimeoutException,
    "UserAlreadyExists": UserAlreadyExistsError,
    "RequestValidationFailure": RequestValidationFailure,
    "UnknownIdentityKey": UnknownIdentityKey,
    "CaptchaRequiredError": CaptchaRequiredError,
    "InternalError": InternalError,
    "AttachmentTooLargeError": AttachmentTooLargeError,
    "AuthorizationFailedError": AuthorizationFailedError,
    "ScanTimeoutError": ScanTimeoutError,
    "OwnProfileKeyDoesNotExistError": OwnProfileKeyDoesNotExistError,
    "UnregisteredUserError": UnregisteredUserError,
    "ProfileUnavailableError": ProfileUnavailableError,
    # TODO add rest from https://gitlab.com/signald/signald/-/tree/main/src/main/java/io/finn/signald/clientprotocol/v1/exceptions
}


def make_response_error(data: dict[str, Any]) -> ResponseError:
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
