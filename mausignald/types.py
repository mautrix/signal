# Copyright (c) 2020 Tulir Asokan
#
# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this
# file, You can obtain one at http://mozilla.org/MPL/2.0/.
from typing import Optional, Dict, Any, List, NewType
from uuid import UUID

from attr import dataclass
import attr

from mautrix.types import SerializableAttrs, SerializableEnum

GroupID = NewType('GroupID', str)


@dataclass
class Account(SerializableAttrs['Account']):
    device_id: int = attr.ib(metadata={"json": "deviceId"})
    username: str
    filename: str
    registered: bool
    has_keys: bool
    subscribed: bool
    uuid: Optional[UUID] = None


@dataclass(frozen=True, eq=False)
class Address(SerializableAttrs['Address']):
    number: Optional[str] = None
    uuid: Optional[UUID] = None

    @property
    def is_valid(self) -> bool:
        return bool(self.number) or bool(self.uuid)

    @property
    def best_identifier(self) -> str:
        return str(self.uuid) if self.uuid else self.number

    def __eq__(self, other: 'Address') -> bool:
        if not isinstance(other, Address):
            return False
        if self.uuid and other.uuid:
            return self.uuid == other.uuid
        elif self.number and other.number:
            return self.number == other.number
        return False

    def __hash__(self) -> int:
        if self.uuid:
            return hash(self.uuid)
        return hash(self.number)

    @classmethod
    def parse(cls, value: str) -> 'Address':
        return Address(number=value) if value.startswith("+") else Address(uuid=UUID(value))


@dataclass
class TrustLevel(SerializableEnum):
    TRUSTED_UNVERIFIED = "TRUSTED_UNVERIFIED"
    TRUSTED_VERIFIED = "TRUSTED_VERIFIED"


@dataclass
class Identity(SerializableAttrs['Identity']):
    trust_level: TrustLevel
    added: int
    fingerprint: str
    safety_number: str
    qr_code_data: str
    address: Address


@dataclass
class GetIdentitiesResponse(SerializableAttrs['GetIdentitiesResponse']):
    identities: List[Identity]


@dataclass
class Contact(SerializableAttrs['Contact']):
    address: Address
    name: Optional[str] = None
    color: Optional[str] = None
    profile_key: Optional[str] = attr.ib(default=None, metadata={"json": "profileKey"})
    message_expiration_time: int = attr.ib(default=0, metadata={"json": "messageExpirationTime"})


@dataclass
class Capabilities(SerializableAttrs['Capabilities']):
    gv2: bool = False
    storage: bool = False
    gv1_migration: bool = attr.ib(default=False, metadata={"json": "gv1-migration"})


@dataclass
class Profile(SerializableAttrs['Profile']):
    name: str = ""
    profile_name: str = ""
    avatar: str = ""
    identity_key: str = ""
    unidentified_access: str = ""
    unrestricted_unidentified_access: bool = False
    address: Optional[Address] = None
    expiration_time: int = 0
    capabilities: Optional[Capabilities] = None


@dataclass
class Group(SerializableAttrs['Group']):
    group_id: GroupID = attr.ib(metadata={"json": "groupId"})
    name: str = "Unknown group"

    # Sometimes "UPDATE"
    type: Optional[str] = None

    # Not always present
    members: List[Address] = attr.ib(factory=lambda: [])
    avatar_id: int = attr.ib(default=0, metadata={"json": "avatarId"})


@dataclass(kw_only=True)
class GroupV2ID(SerializableAttrs['GroupV2ID']):
    id: GroupID
    revision: Optional[int] = None


@dataclass
class GroupV2(GroupV2ID, SerializableAttrs['GroupV2']):
    title: str
    members: List[Address]
    pending_members: List[Address] = attr.ib(factory=lambda: [],
                                             metadata={"json": "pendingMembers"})
    requesting_members: List[Address] = attr.ib(factory=lambda: [],
                                                metadata={"json": "requestingMembers"})
    master_key: Optional[str] = attr.ib(default=None, metadata={"json": "masterKey"})
    invite_link: Optional[str] = attr.ib(default=None, metadata={"json": "inviteLink"})
    timer: Optional[int] = None


@dataclass
class Attachment(SerializableAttrs['Attachment']):
    width: int = 0
    height: int = 0
    caption: Optional[str] = None
    preview: Optional[str] = None
    blurhash: Optional[str] = None
    voice_note: bool = attr.ib(default=False, metadata={"json": "voiceNote"})
    content_type: Optional[str] = attr.ib(default=None, metadata={"json": "contentType"})
    custom_filename: Optional[str] = attr.ib(default=None, metadata={"json": "customFilename"})

    # Only for incoming
    id: Optional[str] = None
    incoming_filename: Optional[str] = attr.ib(default=None, metadata={"json": "storedFilename"})
    digest: Optional[str] = None

    # Only for outgoing
    outgoing_filename: Optional[str] = attr.ib(default=None, metadata={"json": "filename"})


@dataclass
class Quote(SerializableAttrs['Quote']):
    id: int
    author: Address
    text: Optional[str] = None
    # TODO: attachments, mentions


@dataclass(kw_only=True)
class Reaction(SerializableAttrs['Reaction']):
    emoji: str
    remove: bool = False
    target_author: Address = attr.ib(metadata={"json": "targetAuthor"})
    target_sent_timestamp: int = attr.ib(metadata={"json": "targetSentTimestamp"})


@dataclass
class Sticker(SerializableAttrs['Sticker']):
    attachment: Attachment
    pack_id: str = attr.ib(metadata={"json": "packID"})
    pack_key: str = attr.ib(metadata={"json": "packKey"})
    sticker_id: int = attr.ib(metadata={"json": "stickerID"})


@dataclass
class RemoteDelete(SerializableAttrs['RemoteDelete']):
    target_sent_timestamp: int = attr.ib(metadata={"json": "targetSentTimestamp"})


@dataclass
class Mention(SerializableAttrs['Mention']):
    uuid: UUID
    length: int
    start: int = 0


@dataclass
class MessageData(SerializableAttrs['MessageData']):
    timestamp: int

    body: Optional[str] = None
    quote: Optional[Quote] = None
    reaction: Optional[Reaction] = None
    attachments: List[Attachment] = attr.ib(factory=lambda: [])
    sticker: Optional[Sticker] = None
    mentions: List[Mention] = attr.ib(factory=lambda: [])

    group: Optional[Group] = None
    group_v2: Optional[GroupV2ID] = attr.ib(default=None, metadata={"json": "groupV2"})

    end_session: bool = attr.ib(default=False, metadata={"json": "endSession"})
    expires_in_seconds: int = attr.ib(default=0, metadata={"json": "expiresInSeconds"})
    profile_key_update: bool = attr.ib(default=False, metadata={"json": "profileKeyUpdate"})
    view_once: bool = attr.ib(default=False, metadata={"json": "viewOnce"})

    remote_delete: Optional[RemoteDelete] = attr.ib(default=None,
                                                    metadata={"json": "remoteDelete"})


@dataclass
class SentSyncMessage(SerializableAttrs['SentSyncMessage']):
    message: MessageData
    timestamp: int
    expiration_start_timestamp: Optional[int] = attr.ib(default=None, metadata={
        "json": "expirationStartTimestamp"})
    is_recipient_update: bool = attr.ib(default=False, metadata={"json": "isRecipientUpdate"})
    unidentified_status: Dict[str, bool] = attr.ib(factory=lambda: {})
    destination: Optional[Address] = None


class TypingAction(SerializableEnum):
    UNKNOWN = "UNKNOWN"
    STARTED = "STARTED"
    STOPPED = "STOPPED"


@dataclass
class TypingNotification(SerializableAttrs['TypingNotification']):
    action: TypingAction
    timestamp: int
    group_id: Optional[GroupID] = attr.ib(default=None, metadata={"json": "groupId"})


@dataclass
class OwnReadReceipt(SerializableAttrs['OwnReadReceipt']):
    sender: Address
    timestamp: int


class ReceiptType(SerializableEnum):
    UNKNOWN = "UNKNOWN"
    DELIVERY = "DELIVERY"
    READ = "READ"


@dataclass
class Receipt(SerializableAttrs['Receipt']):
    type: ReceiptType
    timestamps: List[int]
    when: int


@dataclass
class SyncMessage(SerializableAttrs['SyncMessage']):
    sent: Optional[SentSyncMessage] = None
    typing: Optional[TypingNotification] = None
    read_messages: Optional[List[OwnReadReceipt]] = attr.ib(default=None,
                                                            metadata={"json": "readMessages"})
    contacts: Optional[Dict[str, Any]] = None
    contacts_complete: bool = attr.ib(default=False, metadata={"json": "contactsComplete"})


class MessageType(SerializableEnum):
    CIPHERTEXT = "CIPHERTEXT"
    UNIDENTIFIED_SENDER = "UNIDENTIFIED_SENDER"
    RECEIPT = "RECEIPT"
    PREKEY_BUNDLE = "PREKEY_BUNDLE"
    KEY_EXCHANGE = "KEY_EXCHANGE"
    UNKNOWN = "UNKNOWN"


@dataclass(kw_only=True)
class Message(SerializableAttrs['Message']):
    username: str
    source: Address
    timestamp: int
    timestamp_iso: str = attr.ib(metadata={"json": "timestampISO"})

    type: MessageType
    source_device: Optional[int] = attr.ib(metadata={"json": "sourceDevice"}, default=None)
    server_timestamp: Optional[int] = attr.ib(metadata={"json": "serverTimestamp"}, default=None)
    server_delivered_timestamp: int = attr.ib(metadata={"json": "serverDeliveredTimestamp"})
    has_content: bool = attr.ib(metadata={"json": "hasContent"}, default=False)
    is_unidentified_sender: Optional[bool] = attr.ib(metadata={"json": "isUnidentifiedSender"},
                                                     default=None)
    has_legacy_message: bool = attr.ib(default=False, metadata={"json": "hasLegacyMessage"})

    data_message: Optional[MessageData] = attr.ib(default=None, metadata={"json": "dataMessage"})
    sync_message: Optional[SyncMessage] = attr.ib(default=None, metadata={"json": "syncMessage"})
    typing: Optional[TypingNotification] = None
    receipt: Optional[Receipt] = None


class ListenAction(SerializableEnum):
    STARTED = "started"
    STOPPED = "stopped"


@dataclass
class ListenEvent(SerializableAttrs['ListenEvent']):
    action: ListenAction
    username: str
    exception: Optional[str] = None
