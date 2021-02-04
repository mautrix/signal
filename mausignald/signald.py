# Copyright (c) 2020 Tulir Asokan
#
# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this
# file, You can obtain one at http://mozilla.org/MPL/2.0/.
from typing import Union, Optional, List, Dict, Any, Callable, Awaitable, Set, TypeVar, Type
from uuid import uuid4
import asyncio

from mautrix.util.logging import TraceLogger

from .rpc import CONNECT_EVENT, SignaldRPCClient
from .errors import UnexpectedError, UnexpectedResponse, make_linking_error
from .types import (Address, Quote, Attachment, Reaction, Account, Message, Contact, Group,
                    Profile, GroupID, GetIdentitiesResponse, ListenEvent, ListenAction, GroupV2,
                    Mention)

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
        resp = await self.request("register", "verification_required", username=phone,
                                  voice=voice, captcha=captcha)
        return resp["username"]

    async def verify(self, username: str, code: str) -> Account:
        resp = await self.request("verify", "verification_succeeded", username=username, code=code)
        return Account.deserialize(resp)

    async def link(self, url_callback: Callable[[str], Awaitable[None]],
                   device_name: str = "mausignald") -> Account:
        req_id = uuid4()
        resp_type, resp = await self._raw_request("link", req_id, deviceName=device_name)
        if resp_type == "linking_error":
            raise make_linking_error(resp)
        elif resp_type != "linking_uri":
            raise UnexpectedResponse(resp_type, resp)

        self.loop.create_task(url_callback(resp["uri"]))

        resp_type, resp = await self._wait_response(req_id)
        if resp_type == "linking_error":
            raise make_linking_error(resp)
        elif resp_type != "linking_successful":
            raise UnexpectedResponse(resp_type, resp)

        return Account.deserialize(resp)

    async def list_accounts(self) -> List[Account]:
        data = await self.request("list_accounts", "account_list")
        return [Account.deserialize(acc) for acc in data["accounts"]]

    @staticmethod
    def _recipient_to_args(recipient: Union[Address, GroupID]) -> Dict[str, Any]:
        if isinstance(recipient, Address):
            return {"recipientAddress": recipient.serialize()}
        else:
            return {"recipientGroupId": recipient}

    async def react(self, username: str, recipient: Union[Address, GroupID],
                    reaction: Reaction) -> None:
        await self.request("react", "send_results", username=username,
                           reaction=reaction.serialize(),
                           **self._recipient_to_args(recipient))

    async def send(self, username: str, recipient: Union[Address, GroupID], body: str,
                   quote: Optional[Quote] = None, attachments: Optional[List[Attachment]] = None,
                   mentions: Optional[List[Mention]] = None, timestamp: Optional[int] = None
                   ) -> None:
        serialized_quote = quote.serialize() if quote else None
        serialized_attachments = [attachment.serialize() for attachment in (attachments or [])]
        serialized_mentions = [mention.serialize() for mention in (mentions or [])]
        await self.request("send", "send", username=username, messageBody=body,
                           attachments=serialized_attachments, quote=serialized_quote,
                           mentions=serialized_mentions, timestamp=timestamp,
                           **self._recipient_to_args(recipient), version="v1")
        # TODO return something?

    async def send_receipt(self, username: str, sender: Address, timestamps: List[int],
                           when: Optional[int] = None, read: bool = False) -> None:
        await self.request_nowait("mark_read" if read else "mark_delivered", username=username,
                                  timestamps=timestamps, when=when,
                                  recipientAddress=sender.serialize())

    async def list_contacts(self, username: str) -> List[Contact]:
        contacts = await self.request("list_contacts", "contact_list", username=username)
        return [Contact.deserialize(contact) for contact in contacts]

    async def list_groups(self, username: str) -> List[Union[Group, GroupV2]]:
        resp = await self.request("list_groups", "group_list", username=username)
        return ([Group.deserialize(group) for group in resp["groups"]]
                + [GroupV2.deserialize(group) for group in resp["groupsv2"]])

    async def get_group(self, username: str, group_id: GroupID, revision: int = -1
                        ) -> Optional[GroupV2]:
        resp = await self.request("get_group", "get_group", account=username, groupID=group_id,
                                  version="v1", revision=revision)
        if "id" not in resp:
            return None
        return GroupV2.deserialize(resp)

    async def get_profile(self, username: str, address: Address) -> Optional[Profile]:
        try:
            resp = await self.request("get_profile", "get_profile", account=username,
                                      address=address.serialize(), version="v1")
        except UnexpectedResponse as e:
            if e.resp_type == "profile_not_available":
                return None
            raise
        return Profile.deserialize(resp)

    async def get_identities(self, username: str, address: Address) -> GetIdentitiesResponse:
        resp = await self.request("get_identities", "identities", username=username,
                                  recipientAddress=address.serialize())
        return GetIdentitiesResponse.deserialize(resp)

    async def set_profile(self, username: str, new_name: str) -> None:
        await self.request("set_profile", "profile_set", username=username, name=new_name)
