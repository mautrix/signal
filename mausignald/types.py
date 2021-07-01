# Copyright (c) 2020 Tulir Asokan
#
# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this
# file, You can obtain one at http://mozilla.org/MPL/2.0/.
from typing import Optional, Dict, List, NewType
from datetime import datetime, timedelta
from uuid import UUID

from attr import dataclass

from mautrix.types import SerializableAttrs, SerializableEnum, ExtensibleEnum, field

GroupID = NewType('GroupID', str)


@dataclass(frozen=True, eq=False)
class Address(SerializableAttrs):
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
class Account(SerializableAttrs):
    account_id: str
    device_id: int
    address: Address


def pluralizer(val: int) -> str:
    if val == 1:
        return ""
    return "s"


@dataclass
class DeviceInfo(SerializableAttrs):
    id: int
    created: int
    last_seen: int = field(json="lastSeen")
    name: Optional[str] = None

    @property
    def name_with_default(self) -> str:
        if self.name:
            return self.name
        return "primary device" if self.id == 1 else "unnamed device"

    @property
    def created_fmt(self) -> str:
        return datetime.utcfromtimestamp(self.created / 1000).strftime("%Y-%m-%d %H:%M:%S UTC")

    @property
    def last_seen_fmt(self) -> str:
        dt = datetime.utcfromtimestamp(self.last_seen / 1000)
        now = datetime.utcnow()
        if dt.date() == now.date():
            return "today"
        elif (dt + timedelta(days=1)).date() == now.date():
            return "yesterday"
        day_diff = (now - dt).days
        if day_diff < 30:
            return f"{day_diff} day{pluralizer(day_diff)} ago"
        return dt.strftime("%Y-%m-%d")


@dataclass
class LinkSession(SerializableAttrs):
    uri: str
    session_id: str


@dataclass
class TrustLevel(SerializableEnum):
    TRUSTED_UNVERIFIED = "TRUSTED_UNVERIFIED"
    TRUSTED_VERIFIED = "TRUSTED_VERIFIED"
    UNTRUSTED = "UNTRUSTED"


@dataclass
class Identity(SerializableAttrs):
    trust_level: TrustLevel
    added: int
    safety_number: str
    qr_code_data: str


@dataclass
class GetIdentitiesResponse(SerializableAttrs):
    address: Address
    identities: List[Identity]


@dataclass
class Contact(SerializableAttrs):
    address: Address
    name: Optional[str] = None
    color: Optional[str] = None
    profile_key: Optional[str] = field(default=None, json="profileKey")
    message_expiration_time: int = field(default=0, json="messageExpirationTime")


@dataclass
class Capabilities(SerializableAttrs):
    gv2: bool = False
    storage: bool = False
    gv1_migration: bool = field(default=False, json="gv1-migration")


@dataclass
class Profile(SerializableAttrs):
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
class Group(SerializableAttrs):
    group_id: GroupID = field(json="groupId")
    name: str = "Unknown group"

    # Sometimes "UPDATE"
    type: Optional[str] = None

    # Not always present
    members: List[Address] = field(factory=lambda: [])
    avatar_id: int = field(default=0, json="avatarId")


@dataclass(kw_only=True)
class GroupV2ID(SerializableAttrs):
    id: GroupID
    revision: Optional[int] = None


class AccessControlMode(SerializableEnum):
    UNKNOWN = "UNKNOWN"
    ANY = "ANY"
    MEMBER = "MEMBER"
    ADMINISTRATOR = "ADMINISTRATOR"
    UNSATISFIABLE = "UNSATISFIABLE"
    UNRECOGNIZED = "UNRECOGNIZED"


@dataclass
class GroupAccessControl(SerializableAttrs):
    attributes: AccessControlMode = AccessControlMode.UNKNOWN
    link: AccessControlMode = AccessControlMode.UNKNOWN
    members: AccessControlMode = AccessControlMode.UNKNOWN


class GroupMemberRole(SerializableEnum):
    UNKNOWN = "UNKNOWN"
    DEFAULT = "DEFAULT"
    ADMINISTRATOR = "ADMINISTRATOR"
    UNRECOGNIZED = "UNRECOGNIZED"


@dataclass
class GroupMember(SerializableAttrs):
    uuid: UUID
    joined_revision: int = 0
    role: GroupMemberRole = GroupMemberRole.UNKNOWN


@dataclass(kw_only=True)
class GroupV2(GroupV2ID, SerializableAttrs):
    title: str
    avatar: Optional[str] = None
    timer: Optional[int] = None
    master_key: Optional[str] = field(default=None, json="masterKey")
    invite_link: Optional[str] = field(default=None, json="inviteLink")
    access_control: GroupAccessControl = field(factory=lambda: GroupAccessControl(),
                                               json="accessControl")
    members: List[Address]
    member_detail: List[GroupMember] = field(factory=lambda: [], json="memberDetail")
    pending_members: List[Address] = field(factory=lambda: [], json="pendingMembers")
    pending_member_detail: List[GroupMember] = field(factory=lambda: [],
                                                     json="pendingMemberDetail")
    requesting_members: List[Address] = field(factory=lambda: [], json="requestingMembers")


@dataclass
class Attachment(SerializableAttrs):
    width: int = 0
    height: int = 0
    caption: Optional[str] = None
    preview: Optional[str] = None
    blurhash: Optional[str] = None
    voice_note: bool = field(default=False, json="voiceNote")
    content_type: Optional[str] = field(default=None, json="contentType")
    custom_filename: Optional[str] = field(default=None, json="customFilename")

    # Only for incoming
    id: Optional[str] = None
    incoming_filename: Optional[str] = field(default=None, json="storedFilename")
    digest: Optional[str] = None

    # Only for outgoing
    outgoing_filename: Optional[str] = field(default=None, json="filename")


@dataclass
class Quote(SerializableAttrs):
    id: int
    author: Address
    text: Optional[str] = None
    # TODO: attachments, mentions


@dataclass(kw_only=True)
class Reaction(SerializableAttrs):
    emoji: str
    remove: bool = False
    target_author: Address = field(json="targetAuthor")
    target_sent_timestamp: int = field(json="targetSentTimestamp")


@dataclass
class Sticker(SerializableAttrs):
    attachment: Attachment
    pack_id: str = field(json="packID")
    pack_key: str = field(json="packKey")
    sticker_id: int = field(json="stickerID")


@dataclass
class RemoteDelete(SerializableAttrs):
    target_sent_timestamp: int = field(json="targetSentTimestamp")


@dataclass
class Mention(SerializableAttrs):
    uuid: UUID
    length: int
    start: int = 0


@dataclass
class MessageData(SerializableAttrs):
    timestamp: int

    body: Optional[str] = None
    quote: Optional[Quote] = None
    reaction: Optional[Reaction] = None
    attachments: List[Attachment] = field(factory=lambda: [])
    sticker: Optional[Sticker] = None
    mentions: List[Mention] = field(factory=lambda: [])

    group: Optional[Group] = None
    group_v2: Optional[GroupV2ID] = field(default=None, json="groupV2")

    end_session: bool = field(default=False, json="endSession")
    expires_in_seconds: int = field(default=0, json="expiresInSeconds")
    profile_key_update: bool = field(default=False, json="profileKeyUpdate")
    view_once: bool = field(default=False, json="viewOnce")

    remote_delete: Optional[RemoteDelete] = field(default=None, json="remoteDelete")


@dataclass
class SentSyncMessage(SerializableAttrs):
    message: MessageData
    timestamp: int
    expiration_start_timestamp: Optional[int] = field(default=None,
                                                      json="expirationStartTimestamp")
    is_recipient_update: bool = field(default=False, json="isRecipientUpdate")
    unidentified_status: Dict[str, bool] = field(factory=lambda: {})
    destination: Optional[Address] = None


class TypingAction(SerializableEnum):
    UNKNOWN = "UNKNOWN"
    STARTED = "STARTED"
    STOPPED = "STOPPED"


@dataclass
class TypingNotification(SerializableAttrs):
    action: TypingAction
    timestamp: int
    group_id: Optional[GroupID] = field(default=None, json="groupId")


@dataclass
class OwnReadReceipt(SerializableAttrs):
    sender: Address
    timestamp: int


class ReceiptType(SerializableEnum):
    UNKNOWN = "UNKNOWN"
    DELIVERY = "DELIVERY"
    READ = "READ"
    VIEWED = "VIEWED"


@dataclass
class Receipt(SerializableAttrs):
    type: ReceiptType
    timestamps: List[int]
    when: int


@dataclass
class ContactSyncMeta(SerializableAttrs):
    id: Optional[str] = None


@dataclass
class ConfigItem(SerializableAttrs):
    present: bool = False


@dataclass
class ClientConfiguration(SerializableAttrs):
    read_receipts: Optional[ConfigItem] = field(factory=lambda: ConfigItem(), json="readReceipts")
    typing_indicators: Optional[ConfigItem] = field(factory=lambda: ConfigItem(),
                                                    json="typingIndicators")
    link_previews: Optional[ConfigItem] = field(factory=lambda: ConfigItem(), json="linkPreviews")
    unidentified_delivery_indicators: Optional[ConfigItem] = field(
        factory=lambda: ConfigItem(), json="unidentifiedDeliveryIndicators")


class StickerPackOperation(ExtensibleEnum):
    INSTALL = "INSTALL"
    # there are very likely others


@dataclass
class StickerPackOperations(SerializableAttrs):
    type: StickerPackOperation
    pack_id: str = field(json="packID")
    pack_key: str = field(json="packKey")


@dataclass
class SyncMessage(SerializableAttrs):
    sent: Optional[SentSyncMessage] = None
    typing: Optional[TypingNotification] = None
    read_messages: Optional[List[OwnReadReceipt]] = field(default=None, json="readMessages")
    contacts: Optional[ContactSyncMeta] = None
    groups: Optional[ContactSyncMeta] = None
    configuration: Optional[ClientConfiguration] = None
    # blocked_list: Optional[???] = field(default=None, json="blockedList")
    sticker_pack_operations: Optional[List[StickerPackOperations]] = field(
        default=None, json="stickerPackOperations")
    contacts_complete: bool = field(default=False, json="contactsComplete")


class MessageType(SerializableEnum):
    CIPHERTEXT = "CIPHERTEXT"
    UNIDENTIFIED_SENDER = "UNIDENTIFIED_SENDER"
    RECEIPT = "RECEIPT"
    PREKEY_BUNDLE = "PREKEY_BUNDLE"
    KEY_EXCHANGE = "KEY_EXCHANGE"
    UNKNOWN = "UNKNOWN"


@dataclass(kw_only=True)
class Message(SerializableAttrs):
    username: str
    source: Address
    timestamp: int
    timestamp_iso: str = field(json="timestampISO")

    type: MessageType
    source_device: Optional[int] = field(json="sourceDevice", default=None)
    server_timestamp: Optional[int] = field(json="serverTimestamp", default=None)
    server_delivered_timestamp: int = field(json="serverDeliveredTimestamp")
    has_content: bool = field(json="hasContent", default=False)
    is_unidentified_sender: Optional[bool] = field(json="isUnidentifiedSender", default=None)
    has_legacy_message: bool = field(default=False, json="hasLegacyMessage")

    data_message: Optional[MessageData] = field(default=None, json="dataMessage")
    sync_message: Optional[SyncMessage] = field(default=None, json="syncMessage")
    typing: Optional[TypingNotification] = None
    receipt: Optional[Receipt] = None


class ListenAction(SerializableEnum):
    STARTED = "started"
    STOPPED = "stopped"


@dataclass
class ListenEvent(SerializableAttrs):
    action: ListenAction
    username: str
    exception: Optional[str] = None
