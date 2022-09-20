# Copyright (c) 2022 Tulir Asokan
#
# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this
# file, You can obtain one at http://mozilla.org/MPL/2.0/.
from __future__ import annotations

from typing import Any, Awaitable, Callable, Type, TypeVar
from uuid import UUID
import asyncio

from mautrix.util.logging import TraceLogger

from .errors import AuthorizationFailedError, RPCError, UnexpectedResponse
from .rpc import CONNECT_EVENT, DISCONNECT_EVENT, SignaldRPCClient
from .types import (
    Account,
    Address,
    Attachment,
    DeviceInfo,
    ErrorMessage,
    GetIdentitiesResponse,
    GroupAccessControl,
    GroupID,
    GroupMember,
    GroupV2,
    IncomingMessage,
    JoinGroupResponse,
    LinkPreview,
    LinkSession,
    Mention,
    Profile,
    ProofRequiredType,
    Quote,
    Reaction,
    SendMessageResponse,
    StorageChange,
    TrustLevel,
    WebsocketConnectionState,
    WebsocketConnectionStateChangeEvent,
)

T = TypeVar("T")
EventHandler = Callable[[T], Awaitable[None]]


class SignaldClient(SignaldRPCClient):
    _event_handlers: dict[Type[T], list[EventHandler]]
    _subscriptions: set[str]

    def __init__(
        self,
        socket_path: str = "/var/run/signald/signald.sock",
        log: TraceLogger | None = None,
        loop: asyncio.AbstractEventLoop | None = None,
    ) -> None:
        super().__init__(socket_path, log, loop)
        self._event_handlers = {}
        self._subscriptions = set()
        self.add_rpc_handler("IncomingMessage", self._parse_message)
        self.add_rpc_handler("ProtocolInvalidMessageError", self._parse_error)
        self.add_rpc_handler("WebSocketConnectionState", self._websocket_connection_state_change)
        self.add_rpc_handler("version", self._log_version)
        self.add_rpc_handler("StorageChange", self._parse_storage_change)
        self.add_rpc_handler(CONNECT_EVENT, self._resubscribe)
        self.add_rpc_handler(DISCONNECT_EVENT, self._on_disconnect)

    def add_event_handler(self, event_class: Type[T], handler: EventHandler) -> None:
        self._event_handlers.setdefault(event_class, []).append(handler)

    def remove_event_handler(self, event_class: Type[T], handler: EventHandler) -> None:
        self._event_handlers.setdefault(event_class, []).remove(handler)

    async def _run_event_handler(self, event: T) -> None:
        try:
            handlers = self._event_handlers[type(event)]
        except KeyError:
            self.log.warning(f"No handlers for {type(event)}")
        else:
            for handler in handlers:
                try:
                    await handler(event)
                except Exception:
                    self.log.exception("Exception in event handler")

    async def _parse_error(self, data: dict[str, Any]) -> None:
        if not data.get("error"):
            return
        await self._run_event_handler(ErrorMessage.deserialize(data))

    async def _parse_storage_change(self, data: dict[str, Any]) -> None:
        if data["type"] != "StorageChange":
            return
        await self._run_event_handler(StorageChange.deserialize(data))

    async def _parse_message(self, data: dict[str, Any]) -> None:
        event_type = data["type"]
        event_data = data["data"]
        event_class = {
            "IncomingMessage": IncomingMessage,
        }[event_type]
        event = event_class.deserialize(event_data)
        await self._run_event_handler(event)

    async def _log_version(self, data: dict[str, Any]) -> None:
        name = data["data"]["name"]
        version = data["data"]["version"]
        self.log.info(f"Connected to {name} v{version}")

    async def _websocket_connection_state_change(self, change_event: dict[str, Any]) -> None:
        evt = WebsocketConnectionStateChangeEvent.deserialize(
            {
                "account": change_event["account"],
                **change_event["data"],
            }
        )
        await self._run_event_handler(evt)

    async def subscribe(self, username: str) -> bool:
        try:
            await self.request_v1("subscribe", account=username)
            self._subscriptions.add(username)
            return True
        except RPCError as e:
            self.log.debug("Failed to subscribe to %s: %s", username, e)
            state = WebsocketConnectionState.DISCONNECTED
            if isinstance(e, AuthorizationFailedError):
                state = WebsocketConnectionState.AUTHENTICATION_FAILED
            evt = WebsocketConnectionStateChangeEvent(state=state, account=username)
            await self._run_event_handler(evt)
            return False

    async def unsubscribe(self, username: str) -> bool:
        try:
            await self.request_v1("unsubscribe", account=username)
            self._subscriptions.discard(username)
            return True
        except RPCError as e:
            self.log.debug("Failed to unsubscribe from %s: %s", username, e)
            return False

    async def _resubscribe(self, unused_data: dict[str, Any]) -> None:
        if self._subscriptions:
            self.log.debug("Resubscribing to users")
            for username in list(self._subscriptions):
                await self.subscribe(username)

    async def _on_disconnect(self, *_) -> None:
        if self._subscriptions:
            self.log.debug("Notifying of disconnection from users")
            for username in self._subscriptions:
                evt = WebsocketConnectionStateChangeEvent(
                    state=WebsocketConnectionState.SOCKET_DISCONNECTED,
                    account=username,
                    exception="Disconnected from signald",
                )
                await self._run_event_handler(evt)

    async def register(self, phone: str, voice: bool = False, captcha: str | None = None) -> str:
        resp = await self.request_v1("register", account=phone, voice=voice, captcha=captcha)
        return resp["account_id"]

    async def verify(self, username: str, code: str) -> Account:
        resp = await self.request_v1("verify", account=username, code=code)
        return Account.deserialize(resp)

    async def start_link(self) -> LinkSession:
        return LinkSession.deserialize(await self.request_v1("generate_linking_uri"))

    async def wait_for_scan(self, session_id: str) -> None:
        await self.request_v1("wait_for_scan", session_id=session_id)

    async def finish_link(
        self, session_id: str, device_name: str = "mausignald", overwrite: bool = False
    ) -> Account:
        resp = await self.request_v1(
            "finish_link", device_name=device_name, session_id=session_id, overwrite=overwrite
        )
        return Account.deserialize(resp)

    @staticmethod
    def _recipient_to_args(
        recipient: UUID | Address | GroupID, simple_name: bool = False
    ) -> dict[str, Any]:
        if isinstance(recipient, UUID):
            recipient = Address(uuid=recipient)
        if isinstance(recipient, Address):
            recipient = recipient.serialize()
            field_name = "address" if simple_name else "recipientAddress"
        else:
            field_name = "group" if simple_name else "recipientGroupId"
        return {field_name: recipient}

    async def react(
        self,
        username: str,
        recipient: UUID | Address | GroupID,
        reaction: Reaction,
        req_id: UUID | None = None,
    ) -> None:
        await self.request_v1(
            "react",
            username=username,
            reaction=reaction.serialize(),
            req_id=req_id,
            **self._recipient_to_args(recipient),
        )

    async def remote_delete(
        self, username: str, recipient: UUID | Address | GroupID, timestamp: int
    ) -> None:
        await self.request_v1(
            "remote_delete",
            account=username,
            timestamp=timestamp,
            **self._recipient_to_args(recipient, simple_name=True),
        )

    async def send_raw(
        self,
        username: str,
        recipient: UUID | Address | GroupID,
        body: str,
        quote: Quote | None = None,
        attachments: list[Attachment] | None = None,
        mentions: list[Mention] | None = None,
        previews: list[LinkPreview] | None = None,
        timestamp: int | None = None,
        req_id: UUID | None = None,
    ) -> SendMessageResponse:
        serialized_quote = quote.serialize() if quote else None
        serialized_attachments = [attachment.serialize() for attachment in (attachments or [])]
        serialized_mentions = [mention.serialize() for mention in (mentions or [])]
        serialized_previews = [preview.serialize() for preview in (previews or [])]
        resp = await self.request_v1(
            "send",
            username=username,
            messageBody=body,
            attachments=serialized_attachments,
            quote=serialized_quote,
            mentions=serialized_mentions,
            previews=serialized_previews,
            timestamp=timestamp,
            req_id=req_id,
            **self._recipient_to_args(recipient),
        )
        return SendMessageResponse.deserialize(resp)

    async def send(
        self,
        username: str,
        recipient: UUID | Address | GroupID,
        body: str,
        quote: Quote | None = None,
        attachments: list[Attachment] | None = None,
        mentions: list[Mention] | None = None,
        previews: list[LinkPreview] | None = None,
        timestamp: int | None = None,
        req_id: UUID | None = None,
    ) -> None:
        resp = await self.send_raw(
            username, recipient, body, quote, attachments, mentions, previews, timestamp, req_id
        )

        # We handle unregisteredFailure a little differently than other errors. If there are no
        # successful sends, then we show an error with the unregisteredFailure details, otherwise
        # we ignore it.
        errors = []
        unregistered_failures = []
        successful_send_count = 0
        for result in resp.results:
            number = result.address.number_or_uuid
            if result.network_failure:
                errors.append(f"Network failure occurred while sending message to {number}.")
            elif result.unregistered_failure:
                unregistered_failures.append(
                    f"Unregistered failure occurred while sending message to {number}."
                )
            elif result.identity_failure:
                errors.append(
                    f"Identity failure occurred while sending message to {number}. New identity: "
                    f"{result.identity_failure}"
                )
            elif result.proof_required_failure:
                prf = result.proof_required_failure
                self.log.warning(
                    f"Proof Required Failure {prf.options}. Retry after: {prf.retry_after}. "
                    f"Token: {prf.token}. Message: {prf.message}."
                )
                errors.append(
                    f"Proof required failure occurred while sending message to {number}. Message: "
                    f"{prf.message}"
                )
                if ProofRequiredType.RECAPTCHA in prf.options:
                    errors.append("RECAPTCHA required.")
                elif ProofRequiredType.PUSH_CHALLENGE in prf.options:
                    # Just submit the challenge automatically.
                    await self.request_v1("submit_challenge")
            else:
                successful_send_count += 1
        self.log.info(
            f"Successfully sent message to {successful_send_count}/{len(resp.results)} users in "
            f"{recipient} with {len(unregistered_failures)} unregistered failures"
        )
        if len(unregistered_failures) == len(resp.results):
            errors.extend(unregistered_failures)
        if errors:
            raise Exception("\n".join(errors))

    async def send_receipt(
        self,
        username: str,
        sender: Address,
        timestamps: list[int],
        when: int | None = None,
        read: bool = False,
    ) -> None:
        if not read:
            # TODO implement
            return
        await self.request_v1(
            "mark_read", account=username, timestamps=timestamps, when=when, to=sender.serialize()
        )

    async def list_accounts(self) -> list[Account]:
        resp = await self.request_v1("list_accounts")
        return [Account.deserialize(acc) for acc in resp.get("accounts", [])]

    async def delete_account(self, username: str, server: bool = False) -> None:
        await self.request_v1("delete_account", account=username, server=server)

    async def get_linked_devices(self, username: str) -> list[DeviceInfo]:
        resp = await self.request_v1("get_linked_devices", account=username)
        return [DeviceInfo.deserialize(dev) for dev in resp.get("devices", [])]

    async def add_linked_device(self, username: str, uri: str) -> None:
        await self.request_v1("add_device", account=username, uri=uri)

    async def remove_linked_device(self, username: str, device_id: int) -> None:
        await self.request_v1("remove_linked_device", account=username, deviceId=device_id)

    async def list_contacts(self, username: str, use_cache: bool = False) -> list[Profile]:
        kwargs = {"async": use_cache}
        resp = await self.request_v1("list_contacts", account=username, **kwargs)
        return [Profile.deserialize(contact) for contact in resp["profiles"]]

    async def list_groups(self, username: str) -> list[GroupV2]:
        resp = await self.request_v1("list_groups", account=username)
        return [GroupV2.deserialize(group) for group in resp.get("groups", [])]

    async def join_group(self, username: str, uri: str) -> JoinGroupResponse:
        resp = await self.request_v1("join_group", account=username, uri=uri)
        return JoinGroupResponse.deserialize(resp)

    async def leave_group(self, username: str, group_id: GroupID) -> None:
        await self.request_v1("leave_group", account=username, groupID=group_id)

    async def ban_user(self, username: str, group_id: GroupID, users: list[Address]) -> GroupV2:
        serialized_users = [user.serialize() for user in (users or [])]
        resp = await self.request_v1(
            "ban_user", account=username, group_id=group_id, users=serialized_users
        )
        return GroupV2.deserialize(resp)

    async def unban_user(self, username: str, group_id: GroupID, users: list[Address]) -> GroupV2:
        serialized_users = [user.serialize() for user in (users or [])]
        resp = await self.request_v1(
            "unban_user", account=username, group_id=group_id, users=serialized_users
        )
        return GroupV2.deserialize(resp)

    async def update_group(
        self,
        username: str,
        group_id: GroupID,
        title: str | None = None,
        description: str | None = None,
        avatar_path: str | None = None,
        add_members: list[Address] | None = None,
        remove_members: list[Address] | None = None,
        update_access_control: GroupAccessControl | None = None,
        update_role: GroupMember | None = None,
    ) -> GroupV2 | None:
        update_params = {
            key: value
            for key, value in {
                "groupID": group_id,
                "avatar": avatar_path,
                "title": title,
                "description": description,
                "addMembers": [addr.serialize() for addr in add_members] if add_members else None,
                "removeMembers": (
                    [addr.serialize() for addr in remove_members] if remove_members else None
                ),
                "updateAccessControl": (
                    update_access_control.serialize() if update_access_control else None
                ),
                "updateRole": (update_role.serialize() if update_role else None),
            }.items()
            if value is not None
        }
        resp = await self.request_v1("update_group", account=username, **update_params)
        if "v2" in resp:
            return GroupV2.deserialize(resp["v2"])
        elif "v1" in resp:
            raise RuntimeError("v1 groups are no longer supported")
        else:
            return None

    async def accept_invitation(self, username: str, group_id: GroupID) -> GroupV2:
        resp = await self.request_v1("accept_invitation", account=username, groupID=group_id)
        return GroupV2.deserialize(resp)

    async def get_group(
        self, username: str, group_id: GroupID, revision: int = -1
    ) -> GroupV2 | None:
        resp = await self.request_v1(
            "get_group", account=username, groupID=group_id, revision=revision
        )
        if "id" not in resp:
            return None
        return GroupV2.deserialize(resp)

    async def create_group(
        self,
        username: str,
        avatar_path: str | None = None,
        member_role_administrator: bool = False,
        members: list[Address] | None = None,
        title: str | None = None,
    ) -> GroupV2 | None:
        create_params = {
            "avatar": avatar_path,
            "member_role": "ADMINISTRATOR" if member_role_administrator else "DEFAULT",
            "title": title,
            "members": [addr.serialize() for addr in members],
        }
        create_params = {k: v for k, v in create_params.items() if v is not None}
        resp = await self.request_v1("create_group", account=username, **create_params)
        if "id" not in resp:
            return None
        return GroupV2.deserialize(resp)

    async def get_profile(
        self, username: str, address: Address, use_cache: bool = False
    ) -> Profile | None:
        try:
            # async is a reserved keyword, so can't pass it as a normal parameter
            kwargs = {"async": use_cache}
            resp = await self.request_v1(
                "get_profile", account=username, address=address.serialize(), **kwargs
            )
        except UnexpectedResponse as e:
            if e.resp_type == "profile_not_available":
                return None
            raise
        return Profile.deserialize(resp)

    async def get_identities(self, username: str, address: Address) -> GetIdentitiesResponse:
        resp = await self.request_v1(
            "get_identities", account=username, address=address.serialize()
        )
        return GetIdentitiesResponse.deserialize(resp)

    async def set_profile(
        self, username: str, name: str | None = None, avatar_path: str | None = None
    ) -> None:
        args = {}
        if name is not None:
            args["name"] = name
        if avatar_path is not None:
            args["avatarFile"] = avatar_path
        await self.request_v1("set_profile", account=username, **args)

    async def trust(
        self,
        username: str,
        recipient: Address,
        trust_level: TrustLevel | str,
        safety_number: str | None = None,
        qr_code_data: str | None = None,
    ) -> None:
        args = {}
        if safety_number:
            if qr_code_data:
                raise ValueError("only one of safety_number and qr_code_data must be set")
            args["safety_number"] = safety_number
        elif qr_code_data:
            args["qr_code_data"] = qr_code_data
        else:
            raise ValueError("safety_number or qr_code_data is required")
        await self.request_v1(
            "trust",
            account=username,
            **args,
            trust_level=trust_level.value if isinstance(trust_level, TrustLevel) else trust_level,
            address=recipient.serialize(),
        )

    async def find_uuid(self, username: str, number: str) -> UUID | None:
        resp = await self.request_v1(
            "resolve_address", partial=Address(number=number).serialize(), account=username
        )
        return Address.deserialize(resp).uuid
