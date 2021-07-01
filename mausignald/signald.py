# Copyright (c) 2020 Tulir Asokan
#
# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this
# file, You can obtain one at http://mozilla.org/MPL/2.0/.
from typing import Union, Optional, List, Dict, Any, Callable, Awaitable, Set, TypeVar, Type
import asyncio

from mautrix.util.logging import TraceLogger

from .rpc import CONNECT_EVENT, SignaldRPCClient
from .errors import UnexpectedError, UnexpectedResponse
from .types import (Address, Quote, Attachment, Reaction, Account, Message, DeviceInfo, Group,
                    Profile, GroupID, GetIdentitiesResponse, ListenEvent, ListenAction, GroupV2,
                    Mention, LinkSession)

T = TypeVar('T')
EventHandler = Callable[[T], Awaitable[None]]


class SignaldClient(SignaldRPCClient):
    _event_handlers: Dict[Type[T], List[EventHandler]]
    _subscriptions: Set[str]

    def __init__(self, socket_path: str = "/var/run/signald/signald.sock",
                 log: Optional[TraceLogger] = None,
                 loop: Optional[asyncio.AbstractEventLoop] = None) -> None:
        super().__init__(socket_path, log, loop)
        self._event_handlers = {}
        self._subscriptions = set()
        self.add_rpc_handler("message", self._parse_message)
        self.add_rpc_handler("listen_started", self._parse_listen_start)
        self.add_rpc_handler("listen_stopped", self._parse_listen_stop)
        self.add_rpc_handler("version", self._log_version)
        self.add_rpc_handler(CONNECT_EVENT, self._resubscribe)

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

    async def _parse_message(self, data: Dict[str, Any]) -> None:
        event_type = data["type"]
        event_data = data["data"]
        event_class = {
            "message": Message,
        }[event_type]
        event = event_class.deserialize(event_data)
        await self._run_event_handler(event)

    async def _log_version(self, data: Dict[str, Any]) -> None:
        name = data["data"]["name"]
        version = data["data"]["version"]
        self.log.info(f"Connected to {name} v{version}")

    async def _parse_listen_start(self, data: Dict[str, Any]) -> None:
        evt = ListenEvent(action=ListenAction.STARTED, username=data["data"])
        await self._run_event_handler(evt)

    async def _parse_listen_stop(self, data: Dict[str, Any]) -> None:
        evt = ListenEvent(action=ListenAction.STOPPED, username=data["data"],
                          exception=data.get("exception", None))
        await self._run_event_handler(evt)

    async def subscribe(self, username: str) -> bool:
        try:
            await self.request("subscribe", "subscribed", username=username)
            self._subscriptions.add(username)
            return True
        except UnexpectedError as e:
            self.log.debug("Failed to subscribe to %s: %s", username, e)
            return False

    async def unsubscribe(self, username: str) -> bool:
        try:
            await self.request("unsubscribe", "unsubscribed", username=username)
            self._subscriptions.remove(username)
            return True
        except UnexpectedError as e:
            self.log.debug("Failed to unsubscribe from %s: %s", username, e)
            return False

    async def _resubscribe(self, unused_data: Dict[str, Any]) -> None:
        if self._subscriptions:
            self.log.debug("Resubscribing to users")
            for username in list(self._subscriptions):
                await self.subscribe(username)

    async def register(self, phone: str, voice: bool = False, captcha: Optional[str] = None
                       ) -> str:
        resp = await self.request_v1("register", account=phone, voice=voice, captcha=captcha)
        return resp["account_id"]

    async def verify(self, username: str, code: str) -> Account:
        resp = await self.request_v1("verify", account=username, code=code)
        return Account.deserialize(resp)

    async def start_link(self) -> LinkSession:
        return LinkSession.deserialize(await self.request_v1("generate_linking_uri"))

    async def finish_link(self, session_id: str, device_name: str = "mausignald",
                          overwrite: bool = False) -> Account:
        resp = await self.request_v1("finish_link", device_name=device_name, session_id=session_id,
                                     overwrite=overwrite)
        return Account.deserialize(resp)

    @staticmethod
    def _recipient_to_args(recipient: Union[Address, GroupID]) -> Dict[str, Any]:
        if isinstance(recipient, Address):
            return {"recipientAddress": recipient.serialize()}
        else:
            return {"recipientGroupId": recipient}

    async def react(self, username: str, recipient: Union[Address, GroupID],
                    reaction: Reaction) -> None:
        await self.request_v1("react", username=username, reaction=reaction.serialize(),
                              **self._recipient_to_args(recipient))

    async def send(self, username: str, recipient: Union[Address, GroupID], body: str,
                   quote: Optional[Quote] = None, attachments: Optional[List[Attachment]] = None,
                   mentions: Optional[List[Mention]] = None, timestamp: Optional[int] = None
                   ) -> None:
        serialized_quote = quote.serialize() if quote else None
        serialized_attachments = [attachment.serialize() for attachment in (attachments or [])]
        serialized_mentions = [mention.serialize() for mention in (mentions or [])]
        await self.request_v1("send", username=username, messageBody=body,
                              attachments=serialized_attachments, quote=serialized_quote,
                              mentions=serialized_mentions, timestamp=timestamp,
                              **self._recipient_to_args(recipient))
        # TODO return something?

    async def send_receipt(self, username: str, sender: Address, timestamps: List[int],
                           when: Optional[int] = None, read: bool = False) -> None:
        if not read:
            # TODO implement
            return
        await self.request_v1("mark_read", account=username, timestamps=timestamps, when=when,
                              to=sender.serialize())

    async def list_accounts(self) -> List[Account]:
        resp = await self.request_v1("list_accounts")
        return [Account.deserialize(acc) for acc in resp.get("accounts", [])]

    async def delete_account(self, username: str, server: bool = False) -> None:
        await self.request_v1("delete_account", account=username, server=server)

    async def get_linked_devices(self, username: str) -> List[DeviceInfo]:
        resp = await self.request_v1("get_linked_devices", account=username)
        return [DeviceInfo.deserialize(dev) for dev in resp.get("devices", [])]

    async def remove_linked_device(self, username: str, device_id: int) -> None:
        await self.request_v1("remove_linked_device", account=username, deviceId=device_id)

    async def list_contacts(self, username: str) -> List[Profile]:
        resp = await self.request_v1("list_contacts", account=username)
        return [Profile.deserialize(contact) for contact in resp["profiles"]]

    async def list_groups(self, username: str) -> List[Union[Group, GroupV2]]:
        resp = await self.request_v1("list_groups", account=username)
        legacy = [Group.deserialize(group) for group in resp.get("legacyGroups", [])]
        v2 = [GroupV2.deserialize(group) for group in resp.get("groups", [])]
        return legacy + v2

    async def update_group(self, username: str, group_id: GroupID, title: Optional[str] = None,
                           avatar_path: Optional[str] = None,
                           add_members: Optional[List[Address]] = None,
                           remove_members: Optional[List[Address]] = None
                           ) -> Union[Group, GroupV2, None]:
        update_params = {key: value for key, value in {
            "groupID": group_id,
            "avatar": avatar_path,
            "title": title,
            "addMembers": [addr.serialize() for addr in add_members] if add_members else None,
            "removeMembers": ([addr.serialize() for addr in remove_members]
                              if remove_members else None),
        }.items() if value is not None}
        resp = await self.request_v1("update_group", account=username, **update_params)
        if "v1" in resp:
            return Group.deserialize(resp["v1"])
        elif "v2" in resp:
            return GroupV2.deserialize(resp["v2"])
        else:
            return None

    async def accept_invitation(self, username: str, group_id: GroupID) -> GroupV2:
        resp = await self.request_v1("accept_invitation", account=username, groupID=group_id)
        return GroupV2.deserialize(resp)

    async def get_group(self, username: str, group_id: GroupID, revision: int = -1
                        ) -> Optional[GroupV2]:
        resp = await self.request_v1("get_group", account=username, groupID=group_id,
                                     revision=revision)
        if "id" not in resp:
            return None
        return GroupV2.deserialize(resp)

    async def get_profile(self, username: str, address: Address) -> Optional[Profile]:
        try:
            resp = await self.request_v1("get_profile", account=username,
                                         address=address.serialize())
        except UnexpectedResponse as e:
            if e.resp_type == "profile_not_available":
                return None
            raise
        return Profile.deserialize(resp)

    async def get_identities(self, username: str, address: Address) -> GetIdentitiesResponse:
        resp = await self.request_v1("get_identities", account=username,
                                     address=address.serialize())
        return GetIdentitiesResponse.deserialize(resp)

    async def set_profile(self, username: str, name: Optional[str] = None,
                          avatar_path: Optional[str] = None) -> None:
        args = {}
        if name is not None:
            args["name"] = name
        if avatar_path is not None:
            args["avatarFile"] = avatar_path
        await self.request_v1("set_profile", account=username, **args)

    async def trust(self, username: str, recipient: Address, trust_level: str,
                    safety_number: Optional[str] = None, qr_code_data: Optional[str] = None
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
        await self.request_v1("trust", account=username, **args, trust_level=trust_level,
                              address=recipient.serialize())
