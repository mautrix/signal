# mautrix-signal - A Matrix-Signal puppeting bridge
# Copyright (C) 2021 Tulir Asokan
#
# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU Affero General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU Affero General Public License for more details.
#
# You should have received a copy of the GNU Affero General Public License
# along with this program.  If not, see <https://www.gnu.org/licenses/>.
from __future__ import annotations

from typing import TYPE_CHECKING, AsyncGenerator, AsyncIterable, Awaitable, cast
from uuid import UUID
import asyncio
import hashlib
import os.path

from yarl import URL

from mausignald.errors import UnregisteredUserError
from mausignald.types import Address, Profile
from mautrix.appservice import IntentAPI
from mautrix.bridge import BasePuppet, async_getter_lock
from mautrix.errors import MForbidden
from mautrix.types import (
    ContentURI,
    EventType,
    PowerLevelStateEventContent,
    RoomID,
    SyncToken,
    UserID,
)
from mautrix.util.simple_template import SimpleTemplate

from . import portal as p, signal, user as u
from .config import Config
from .db import Puppet as DBPuppet

if TYPE_CHECKING:
    from .__main__ import SignalBridge

try:
    import phonenumbers
except ImportError:
    phonenumbers = None


class Puppet(DBPuppet, BasePuppet):
    by_uuid: dict[UUID, Puppet] = {}
    by_number: dict[str, Puppet] = {}
    by_custom_mxid: dict[UserID, Puppet] = {}
    hs_domain: str
    mxid_template: SimpleTemplate[str]

    config: Config
    signal: signal.SignalHandler

    default_mxid_intent: IntentAPI
    default_mxid: UserID

    _uuid_lock: asyncio.Lock
    _update_info_lock: asyncio.Lock

    def __init__(
        self,
        uuid: UUID,
        number: str | None,
        name: str | None = None,
        name_quality: int = 0,
        avatar_url: ContentURI | None = None,
        avatar_hash: str | None = None,
        name_set: bool = False,
        avatar_set: bool = False,
        is_registered: bool = False,
        custom_mxid: UserID | None = None,
        access_token: str | None = None,
        next_batch: SyncToken | None = None,
        base_url: URL | None = None,
    ) -> None:
        assert uuid, "UUID must be set for ghosts"
        assert isinstance(uuid, UUID)
        super().__init__(
            uuid=uuid,
            number=number,
            name=name,
            name_quality=name_quality,
            avatar_url=avatar_url,
            avatar_hash=avatar_hash,
            name_set=name_set,
            avatar_set=avatar_set,
            is_registered=is_registered,
            custom_mxid=custom_mxid,
            access_token=access_token,
            next_batch=next_batch,
            base_url=base_url,
        )
        self.log = self.log.getChild(str(uuid) if uuid else number)

        self.default_mxid = self.get_mxid_from_id(self.uuid)
        self.default_mxid_intent = self.az.intent.user(self.default_mxid)
        self.intent = self._fresh_intent()

        self._uuid_lock = asyncio.Lock()
        self._update_info_lock = asyncio.Lock()

    @classmethod
    def init_cls(cls, bridge: "SignalBridge") -> AsyncIterable[Awaitable[None]]:
        cls.config = bridge.config
        cls.loop = bridge.loop
        cls.signal = bridge.signal
        cls.mx = bridge.matrix
        cls.az = bridge.az
        cls.hs_domain = cls.config["homeserver.domain"]
        cls.mxid_template = SimpleTemplate(
            cls.config["bridge.username_template"],
            "userid",
            prefix="@",
            suffix=f":{cls.hs_domain}",
            type=str,
        )
        cls.sync_with_custom_puppets = cls.config["bridge.sync_with_custom_puppets"]

        cls.homeserver_url_map = {
            server: URL(url)
            for server, url in cls.config["bridge.double_puppet_server_map"].items()
        }
        cls.allow_discover_url = cls.config["bridge.double_puppet_allow_discovery"]
        cls.login_shared_secret_map = {
            server: secret.encode("utf-8")
            for server, secret in cls.config["bridge.login_shared_secret_map"].items()
        }
        cls.login_device_name = "Signal Bridge"
        return (puppet.try_start() async for puppet in cls.all_with_custom_mxid())

    def intent_for(self, portal: p.Portal) -> IntentAPI:
        if portal.chat_id == self.uuid:
            return self.default_mxid_intent
        return self.intent

    @property
    def address(self) -> Address:
        return Address(uuid=self.uuid, number=self.number)

    async def handle_number_receive(self, number: str) -> None:
        async with self._uuid_lock:
            if self.number == number:
                return
            if self.number:
                self.by_number.pop(self.number, None)
            self.number = number
            self._add_number_to_cache()
            await self._update_number()

    async def _migrate_memberships(self, prev_intent: IntentAPI, new_intent: IntentAPI) -> None:
        self.log.debug(f"Migrating memberships {prev_intent.mxid} -> {new_intent.mxid}")
        try:
            joined_rooms = await prev_intent.get_joined_rooms()
        except MForbidden as e:
            self.log.debug(
                f"Got MForbidden ({e.message}) when getting joined rooms of old mxid, "
                "assuming there are no rooms to rejoin"
            )
            return
        for room_id in joined_rooms:
            await prev_intent.invite_user(room_id, self.default_mxid)
            await self._migrate_powers(prev_intent, new_intent, room_id)
            await prev_intent.leave_room(room_id)
            await new_intent.join_room_by_id(room_id)

    async def _migrate_powers(
        self, prev_intent: IntentAPI, new_intent: IntentAPI, room_id: RoomID
    ) -> None:
        try:
            powers: PowerLevelStateEventContent
            powers = await prev_intent.get_state_event(room_id, EventType.ROOM_POWER_LEVELS)
            user_level = powers.get_user_level(prev_intent.mxid)
            pl_state_level = powers.get_event_level(EventType.ROOM_POWER_LEVELS)
            if user_level >= pl_state_level > powers.users_default:
                powers.ensure_user_level(new_intent.mxid, user_level)
                await prev_intent.send_state_event(room_id, EventType.ROOM_POWER_LEVELS, powers)
        except Exception:
            self.log.warning("Failed to migrate power levels", exc_info=True)

    async def update_info(self, info: Profile | Address, source: u.User) -> None:
        update = False
        address = info.address if isinstance(info, Profile) else info
        if address.number and address.number != self.number:
            await self.handle_number_receive(address.number)
            update = True
        self.log.debug("Updating info with %s (source: %s)", info, source.mxid)
        async with self._update_info_lock:
            if isinstance(info, Profile) or self.name is None:
                update = await self._update_name(info) or update
            if isinstance(info, Profile):
                update = await self._update_avatar(info.avatar) or update
            elif self.config["bridge.contact_list_names"] != "disallow" and self.number:
                # Try to use a contact list avatar
                update = await self._update_avatar(f"contact-{self.number}") or update
            if update:
                await self.update()
                asyncio.create_task(self._try_update_portal_meta())

    @staticmethod
    def fmt_phone(number: str) -> str:
        if phonenumbers is None:
            return number
        parsed = phonenumbers.parse(number)
        fmt = phonenumbers.PhoneNumberFormat.INTERNATIONAL
        return phonenumbers.format_number(parsed, fmt)

    @classmethod
    def _get_displayname(cls, info: Profile | Address) -> tuple[str, int]:
        quality = 10
        if isinstance(info, Profile):
            address = info.address
            name = None
            contact_names = cls.config["bridge.contact_list_names"]
            if info.profile_name:
                name = info.profile_name
                quality = 90 if contact_names == "prefer" else 100
            if info.contact_name:
                if contact_names == "prefer":
                    quality = 100
                    name = info.contact_name
                elif contact_names == "allow" and not name:
                    quality = 50
                    name = info.contact_name
            names = name.split("\x00") if name else []
        else:
            address = info
            names = []
        data = {
            "first_name": names[0] if len(names) > 0 else "",
            "last_name": names[-1] if len(names) > 1 else "",
            "full_name": " ".join(names),
            "phone": cls.fmt_phone(address.number) if address.number else None,
            "uuid": str(address.uuid) if address.uuid else None,
            "displayname": "Unknown user",
        }
        for pref in cls.config["bridge.displayname_preference"]:
            value = data.get(pref.replace(" ", "_"))
            if value:
                data["displayname"] = value
                break

        return cls.config["bridge.displayname_template"].format(**data), quality

    async def _update_name(self, info: Profile | Address) -> bool:
        name, quality = self._get_displayname(info)
        if quality >= self.name_quality and (name != self.name or not self.name_set):
            self.log.debug(
                "Updating name from '%s' to '%s' (quality: %d)", self.name, name, quality
            )
            self.name = name
            self.name_quality = quality
            try:
                await self.default_mxid_intent.set_displayname(self.name)
                self.name_set = True
            except Exception:
                self.log.exception("Error setting displayname")
                self.name_set = False
            return True
        elif name != self.name or not self.name_set:
            self.log.debug(
                "Not updating name from '%s' to '%s', new quality (%d) is lower than old (%d)",
                self.name,
                name,
                quality,
                self.name_quality,
            )
        elif self.name_quality == 0:
            # Name matches, but quality is not stored in database - store it now
            self.name_quality = quality
            return True
        return False

    @staticmethod
    async def upload_avatar(
        self: Puppet | p.Portal, path: str, intent: IntentAPI
    ) -> bool | tuple[str, ContentURI]:
        if not path:
            return False
        if not path.startswith("/"):
            path = os.path.join(self.config["signal.avatar_dir"], path)
        try:
            with open(path, "rb") as file:
                data = file.read()
        except FileNotFoundError:
            return False
        if not data:
            return False
        new_hash = hashlib.sha256(data).hexdigest()
        if self.avatar_set and new_hash == self.avatar_hash:
            return False
        mxc = await intent.upload_media(data, async_upload=self.config["homeserver.async_media"])
        return new_hash, mxc

    async def _update_avatar(self, path: str) -> bool:
        res = await Puppet.upload_avatar(self, path, self.default_mxid_intent)
        if res is False:
            return False
        self.avatar_hash, self.avatar_url = res
        try:
            await self.default_mxid_intent.set_avatar_url(self.avatar_url)
            self.avatar_set = True
        except Exception:
            self.log.exception("Error setting avatar")
            self.avatar_set = False
        return True

    async def _try_update_portal_meta(self) -> None:
        try:
            await self._update_portal_meta()
        except Exception:
            self.log.exception("Error updating portal meta")

    async def _update_portal_meta(self) -> None:
        async for portal in p.Portal.find_private_chats_with(self.uuid):
            if portal.receiver == self.number:
                # This is a note to self chat, don't change the name
                continue
            try:
                await portal.update_puppet_name(self.name)
                await portal.update_puppet_avatar(self.avatar_hash, self.avatar_url)
                if self.number:
                    await portal.update_puppet_number(self.fmt_phone(self.number))
            except Exception:
                self.log.exception(f"Error updating portal meta for {portal.receiver}")

    async def default_puppet_should_leave_room(self, room_id: RoomID) -> bool:
        portal: p.Portal = await p.Portal.get_by_mxid(room_id)
        # Leave all portals except the notes to self room
        return not (portal and portal.is_direct and portal.chat_id == self.uuid)

    # region Database getters

    def _add_number_to_cache(self) -> None:
        if self.number:
            try:
                existing = self.by_number[self.number]
                if existing and existing.uuid != self.uuid and existing != self:
                    existing.number = None
            except KeyError:
                pass
            self.by_number[self.number] = self

    def _add_to_cache(self) -> None:
        self.by_uuid[self.uuid] = self
        self._add_number_to_cache()
        if self.custom_mxid:
            self.by_custom_mxid[self.custom_mxid] = self

    async def save(self) -> None:
        await self.update()

    @classmethod
    async def get_by_mxid(cls, mxid: UserID, create: bool = True) -> Puppet | None:
        uuid = cls.get_id_from_mxid(mxid)
        if not uuid:
            return None
        return await cls.get_by_uuid(uuid, create=create)

    @classmethod
    @async_getter_lock
    async def get_by_custom_mxid(cls, mxid: UserID) -> Puppet | None:
        try:
            return cls.by_custom_mxid[mxid]
        except KeyError:
            pass

        puppet = cast(cls, await super().get_by_custom_mxid(mxid))
        if puppet:
            puppet._add_to_cache()
            return puppet

        return None

    @classmethod
    def get_id_from_mxid(cls, mxid: UserID) -> UUID | None:
        identifier = cls.mxid_template.parse(mxid)
        if not identifier:
            return None
        try:
            return UUID(identifier.upper())
        except ValueError:
            return None

    @classmethod
    def get_mxid_from_id(cls, uuid: UUID) -> UserID:
        return UserID(cls.mxid_template.format_full(str(uuid).lower()))

    @classmethod
    @async_getter_lock
    async def get_by_number(
        cls, number: str, /, *, resolve_via: str | None = None, raise_resolve: bool = False
    ) -> Puppet | None:
        try:
            return cls.by_number[number]
        except KeyError:
            pass

        puppet = cast(cls, await super().get_by_number(number))
        if puppet is not None:
            puppet._add_to_cache()
            return puppet

        if resolve_via:
            cls.log.debug(
                f"Couldn't find puppet with number {number}, resolving UUID via {resolve_via}"
            )
            try:
                uuid = await cls.signal.find_uuid(resolve_via, number)
            except UnregisteredUserError:
                if raise_resolve:
                    raise
                cls.log.debug(f"Resolving {number} via {resolve_via} threw UnregisteredUserError")
                return None
            except Exception:
                if raise_resolve:
                    raise
                cls.log.exception(f"Failed to resolve {number} via {resolve_via}")
                return None
            if uuid:
                cls.log.debug(f"Found {uuid} for {number} after resolving via {resolve_via}")
                return await cls.get_by_uuid(uuid, number=number)
            else:
                cls.log.debug(f"Didn't find UUID for {number} via {resolve_via}")

        return None

    @classmethod
    async def get_by_address(
        cls,
        address: Address,
        create: bool = True,
        resolve_via: str | None = None,
        raise_resolve: bool = False,
    ) -> Puppet | None:
        if not address.uuid:
            return await cls.get_by_number(
                address.number, resolve_via=resolve_via, raise_resolve=raise_resolve
            )
        else:
            return await cls.get_by_uuid(address.uuid, create=create, number=address.number)

    @classmethod
    @async_getter_lock
    async def get_by_uuid(
        cls, uuid: UUID, /, *, create: bool = True, number: str | None = None
    ) -> Puppet | None:
        try:
            return cls.by_uuid[uuid]
        except KeyError:
            pass

        puppet = cast(cls, await super().get_by_uuid(uuid))
        if puppet is not None:
            puppet._add_to_cache()
            return puppet

        if create:
            puppet = cls(uuid, number)
            await puppet.insert()
            puppet._add_to_cache()
            return puppet

        return None

    @classmethod
    async def all_with_custom_mxid(cls) -> AsyncGenerator[Puppet, None]:
        puppets = await super().all_with_custom_mxid()
        puppet: cls
        for index, puppet in enumerate(puppets):
            try:
                yield cls.by_uuid[puppet.uuid]
            except KeyError:
                puppet._add_to_cache()
                yield puppet

    # endregion
