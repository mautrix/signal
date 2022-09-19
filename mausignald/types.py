# Copyright (c) 2022 Tulir Asokan
#
# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this
# file, You can obtain one at http://mozilla.org/MPL/2.0/.
from typing import Dict, List, NewType, Optional
from datetime import datetime, timedelta
from uuid import UUID

from attr import dataclass

from mautrix.types import ExtensibleEnum, SerializableAttrs, SerializableEnum, field

GroupID = NewType("GroupID", str)


@dataclass(frozen=True, eq=False)
class Address(SerializableAttrs):
    uuid: Optional[UUID] = None
    number: Optional[str] = None

    @property
    def is_valid(self) -> bool:
        return bool(self.number) or bool(self.uuid)

    @property
    def best_identifier(self) -> str:
        return str(self.uuid) if self.uuid else self.number

    @property
    def number_or_uuid(self) -> str:
        return self.number or str(self.uuid)

    def __eq__(self, other: "Address") -> bool:
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
    def parse(cls, value: str) -> "Address":
        return Address(number=value) if value.startswith("+") else Address(uuid=UUID(value))


@dataclass
class Account(SerializableAttrs):
    account_id: str
    device_id: int
    address: Address
    pending: bool = False
    pni: Optional[str] = None


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


class TrustLevel(SerializableEnum):
    TRUSTED_UNVERIFIED = "TRUSTED_UNVERIFIED"
    TRUSTED_VERIFIED = "TRUSTED_VERIFIED"
    UNTRUSTED = "UNTRUSTED"

    @property
    def human_str(self) -> str:
        if self == TrustLevel.TRUSTED_VERIFIED:
            return "trusted"
        elif self == TrustLevel.TRUSTED_UNVERIFIED:
            return "trusted (unverified)"
        elif self == TrustLevel.UNTRUSTED:
            return "untrusted"
        return "unknown"


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
class Capabilities(SerializableAttrs):
    gv2: bool = False
    storage: bool = False
    gv1_migration: bool = field(default=False, json="gv1-migration")
    announcement_group: bool = False
    change_number: bool = False
    sender_key: bool = False
    stories: bool = False


@dataclass
class Profile(SerializableAttrs):
    address: Optional[Address] = None
    name: str = ""
    contact_name: str = ""
    profile_name: str = ""
    about: str = ""
    avatar: str = ""
    color: str = ""
    emoji: str = ""
    inbox_position: Optional[int] = None
    mobilecoin_address: Optional[str] = None
    expiration_time: Optional[int] = None
    capabilities: Optional[Capabilities] = None
    # visible_badge_ids: List[str]


@dataclass
class Group(SerializableAttrs):
    group_id: GroupID = field(json="groupId")
    name: str = "Unknown group"

    # Sometimes "UPDATE"
    type: Optional[str] = None

    # Not always present
    members: List[Address] = field(factory=lambda: [])
    avatar_id: int = field(default=0, json="avatarId")


class AccessControlMode(SerializableEnum):
    UNKNOWN = "UNKNOWN"
    ANY = "ANY"
    MEMBER = "MEMBER"
    ADMINISTRATOR = "ADMINISTRATOR"
    UNSATISFIABLE = "UNSATISFIABLE"
    UNRECOGNIZED = "UNRECOGNIZED"


class AnnouncementsMode(SerializableEnum):
    UNKNOWN = "UNKNOWN"
    ENABLED = "ENABLED"
    DISABLED = "DISABLED"


@dataclass
class GroupAccessControl(SerializableAttrs):
    attributes: Optional[AccessControlMode] = None
    link: Optional[AccessControlMode] = None
    members: Optional[AccessControlMode] = None


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

    @property
    def address(self) -> Address:
        return Address(uuid=self.uuid)


@dataclass
class BannedGroupMember(SerializableAttrs):
    uuid: UUID
    timestamp: int


@dataclass
class GroupChange(SerializableAttrs):
    revision: int
    editor: Address
    delete_members: Optional[List[Address]] = None
    delete_pending_members: Optional[List[Address]] = None
    delete_requesting_members: Optional[List[Address]] = None
    modified_profile_keys: Optional[List[GroupMember]] = None
    modify_member_roles: Optional[List[GroupMember]] = None
    new_access_control: Optional[GroupAccessControl] = None
    new_avatar: bool = False
    new_banned_members: Optional[List[GroupMember]] = None
    new_description: Optional[str] = None
    new_invite_link_password: bool = False
    new_is_announcement_group: Optional[AnnouncementsMode] = None
    new_members: Optional[List[GroupMember]] = None
    new_pending_members: Optional[List[GroupMember]] = None
    new_requesting_members: Optional[List[GroupMember]] = None
    new_timer: Optional[int] = None
    new_title: Optional[str] = None
    new_unbanned_members: Optional[List[GroupMember]] = None
    promote_pending_members: Optional[List[GroupMember]] = None
    promote_requesting_members: Optional[List[GroupMember]] = None


@dataclass(kw_only=True)
class GroupV2ID(SerializableAttrs):
    id: GroupID
    revision: Optional[int] = None
    removed: Optional[bool] = False
    group_change: Optional[GroupChange] = None


@dataclass(kw_only=True)
class GroupV2(GroupV2ID, SerializableAttrs):
    title: str = None
    description: Optional[str] = None
    avatar: Optional[str] = None
    timer: Optional[int] = None
    master_key: Optional[str] = field(default=None, json="masterKey")
    invite_link: Optional[str] = field(default=None, json="inviteLink")
    access_control: GroupAccessControl = field(
        factory=lambda: GroupAccessControl(), json="accessControl"
    )
    members: List[Address] = None
    member_detail: List[GroupMember] = field(factory=lambda: [], json="memberDetail")
    pending_members: List[Address] = field(factory=lambda: [], json="pendingMembers")
    pending_member_detail: List[GroupMember] = field(
        factory=lambda: [], json="pendingMemberDetail"
    )
    requesting_members: List[Address] = field(factory=lambda: [], json="requestingMembers")
    announcements: AnnouncementsMode = field(default=AnnouncementsMode.UNKNOWN)
    banned_members: Optional[List[BannedGroupMember]] = None


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
    size: Optional[int] = None

    # Only for outgoing
    outgoing_filename: Optional[str] = field(default=None, json="filename")


@dataclass
class Mention(SerializableAttrs):
    uuid: UUID
    length: int
    start: int = 0


@dataclass
class QuotedAttachment(SerializableAttrs):
    content_type: Optional[str] = field(default=None, json="contentType")
    filename: Optional[str] = field(default=None, json="fileName")


@dataclass
class Quote(SerializableAttrs):
    id: int
    author: Address
    text: Optional[str] = None
    attachments: Optional[List[QuotedAttachment]] = None
    mentions: Optional[List[Mention]] = None


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
    target_sent_timestamp: int


class SharedContactDetailType(SerializableEnum):
    HOME = "HOME"
    WORK = "WORK"
    MOBILE = "MOBILE"
    CUSTOM = "CUSTOM"


@dataclass
class SharedContactDetail(SerializableAttrs):
    type: SharedContactDetailType
    value: str
    label: Optional[str] = None

    @property
    def type_or_label(self) -> str:
        if self.type != SharedContactDetailType.CUSTOM:
            return self.type.value.title()
        return self.label


@dataclass
class SharedContactAvatar(SerializableAttrs):
    attachment: Attachment
    is_profile: bool


@dataclass
class SharedContactName(SerializableAttrs):
    display: Optional[str] = None
    given: Optional[str] = None
    middle: Optional[str] = None
    family: Optional[str] = None
    prefix: Optional[str] = None
    suffix: Optional[str] = None

    @property
    def parts(self) -> List[str]:
        return [self.prefix, self.given, self.middle, self.family, self.suffix]

    def __str__(self) -> str:
        if self.display:
            return self.display
        return " ".join(part for part in self.parts if part)


@dataclass
class SharedContactAddress(SerializableAttrs):
    type: SharedContactDetailType
    label: Optional[str] = None
    street: Optional[str] = None
    pobox: Optional[str] = None
    neighborhood: Optional[str] = None
    city: Optional[str] = None
    region: Optional[str] = None
    postcode: Optional[str] = None
    country: Optional[str] = None


@dataclass
class SharedContact(SerializableAttrs):
    name: SharedContactName
    organization: Optional[str] = None
    avatar: Optional[SharedContactAvatar] = None
    email: List[SharedContactDetail] = field(factory=lambda: [])
    phone: List[SharedContactDetail] = field(factory=lambda: [])
    address: Optional[SharedContactAddress] = None


@dataclass
class LinkPreview(SerializableAttrs):
    url: str
    title: str
    description: str
    attachment: Optional[Attachment] = None


@dataclass
class MessageData(SerializableAttrs):
    timestamp: int

    body: Optional[str] = None
    quote: Optional[Quote] = None
    reaction: Optional[Reaction] = None
    attachments: List[Attachment] = field(factory=lambda: [])
    sticker: Optional[Sticker] = None
    mentions: List[Mention] = field(factory=lambda: [])
    contacts: List[SharedContact] = field(factory=lambda: [])

    group: Optional[Group] = None
    group_v2: Optional[GroupV2ID] = field(default=None, json="groupV2")

    end_session: bool = field(default=False, json="endSession")
    expires_in_seconds: int = field(default=0, json="expiresInSeconds")
    is_expiration_update: bool = field(default=False)
    profile_key_update: bool = field(default=False, json="profileKeyUpdate")
    view_once: bool = field(default=False, json="viewOnce")

    remote_delete: Optional[RemoteDelete] = field(default=None, json="remoteDelete")

    previews: List[LinkPreview] = field(factory=lambda: [])

    @property
    def is_message(self) -> bool:
        return bool(self.body or self.attachments or self.sticker or self.contacts)


@dataclass
class SentSyncMessage(SerializableAttrs):
    message: MessageData
    timestamp: int
    expiration_start_timestamp: Optional[int] = field(
        default=None, json="expirationStartTimestamp"
    )
    is_recipient_update: bool = field(default=False, json="isRecipientUpdate")
    unidentified_status: Dict[str, bool] = field(factory=lambda: {})
    destination: Optional[Address] = None


class TypingAction(SerializableEnum):
    UNKNOWN = "UNKNOWN"
    STARTED = "STARTED"
    STOPPED = "STOPPED"


@dataclass
class TypingMessage(SerializableAttrs):
    action: TypingAction
    timestamp: int
    group_id: Optional[GroupID] = None


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
class ReceiptMessage(SerializableAttrs):
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
    typing_indicators: Optional[ConfigItem] = field(
        factory=lambda: ConfigItem(), json="typingIndicators"
    )
    link_previews: Optional[ConfigItem] = field(factory=lambda: ConfigItem(), json="linkPreviews")
    unidentified_delivery_indicators: Optional[ConfigItem] = field(
        factory=lambda: ConfigItem(), json="unidentifiedDeliveryIndicators"
    )


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
    read_messages: Optional[List[OwnReadReceipt]] = field(default=None, json="readMessages")
    contacts: Optional[ContactSyncMeta] = None
    groups: Optional[ContactSyncMeta] = None
    configuration: Optional[ClientConfiguration] = None
    # blocked_list: Optional[???] = field(default=None, json="blockedList")
    sticker_pack_operations: Optional[List[StickerPackOperations]] = field(
        default=None, json="stickerPackOperations"
    )
    contacts_complete: bool = field(default=False, json="contactsComplete")


class OfferMessageType(SerializableEnum):
    AUDIO_CALL = "audio_call"
    VIDEO_CALL = "video_call"


@dataclass
class OfferMessage(SerializableAttrs):
    id: int
    type: OfferMessageType
    opaque: Optional[str] = None
    sdp: Optional[str] = None


@dataclass
class AnswerMessage(SerializableAttrs):
    id: int
    opaque: Optional[str] = None
    sdp: Optional[str] = None


@dataclass
class ICEUpdateMessage(SerializableAttrs):
    id: int
    opaque: Optional[str] = None
    sdp: Optional[str] = None


@dataclass
class BusyMessage(SerializableAttrs):
    id: int


class HangupMessageType(SerializableEnum):
    NORMAL = "normal"
    ACCEPTED = "accepted"
    DECLINED = "declined"
    BUSY = "busy"
    NEED_PERMISSION = "need_permission"


@dataclass
class HangupMessage(SerializableAttrs):
    id: int
    type: HangupMessageType
    device_id: int
    legacy: bool = False


@dataclass
class CallMessage(SerializableAttrs):
    offer_message: Optional[OfferMessage] = None
    hangup_message: Optional[HangupMessage] = None
    answer_message: Optional[AnswerMessage] = None
    busy_message: Optional[BusyMessage] = None
    ice_update_message: Optional[List[ICEUpdateMessage]] = None
    multi_ring: bool = False
    destination_device_id: Optional[int] = None


class MessageType(SerializableEnum):
    CIPHERTEXT = "CIPHERTEXT"
    PLAINTEXT_CONTENT = "PLAINTEXT_CONTENT"
    UNIDENTIFIED_SENDER = "UNIDENTIFIED_SENDER"
    RECEIPT = "RECEIPT"
    PREKEY_BUNDLE = "PREKEY_BUNDLE"
    KEY_EXCHANGE = "KEY_EXCHANGE"
    UNKNOWN = "UNKNOWN"


@dataclass(kw_only=True)
class IncomingMessage(SerializableAttrs):
    account: str
    source: Address
    timestamp: int

    type: MessageType
    source_device: Optional[int] = None
    server_guid: str
    server_receiver_timestamp: int
    server_deliver_timestamp: int
    has_content: bool
    unidentified_sender: bool
    has_legacy_message: bool

    call_message: Optional[CallMessage] = field(default=None)
    data_message: Optional[MessageData] = field(default=None)
    sync_message: Optional[SyncMessage] = field(default=None)
    typing_message: Optional[TypingMessage] = None
    receipt_message: Optional[ReceiptMessage] = None


@dataclass(kw_only=True)
class ErrorMessageData(SerializableAttrs):
    sender: str
    timestamp: int
    message: str
    sender_device: int
    content_hint: int


@dataclass(kw_only=True)
class ErrorMessage(SerializableAttrs):
    type: str
    version: str
    data: ErrorMessageData
    error: bool
    account: str


@dataclass(kw_only=True)
class StorageChangeData(SerializableAttrs):
    version: int


@dataclass(kw_only=True)
class StorageChange(SerializableAttrs):
    type: str
    version: str
    data: StorageChangeData
    account: str


class WebsocketConnectionState(SerializableEnum):
    # States from signald itself
    DISCONNECTED = "DISCONNECTED"
    CONNECTING = "CONNECTING"
    CONNECTED = "CONNECTED"
    RECONNECTING = "RECONNECTING"
    DISCONNECTING = "DISCONNECTING"
    AUTHENTICATION_FAILED = "AUTHENTICATION_FAILED"
    FAILED = "FAILED"

    # Socket disconnect state
    SOCKET_DISCONNECTED = "SOCKET_DISCONNECTED"


class WebsocketType(SerializableEnum):
    IDENTIFIED = "IDENTIFIED"
    UNIDENTIFIED = "UNIDENTIFIED"


@dataclass
class WebsocketConnectionStateChangeEvent(SerializableAttrs):
    state: WebsocketConnectionState
    account: str
    socket: Optional[WebsocketType] = None
    exception: Optional[str] = None


@dataclass
class JoinGroupResponse(SerializableAttrs):
    group_id: str = field(json="groupID")
    pending_admin_approval: bool = field(json="pendingAdminApproval")
    member_count: Optional[int] = field(json="memberCount", default=None)
    revision: Optional[int] = None
    title: Optional[str] = None
    description: Optional[str] = None


class ProofRequiredType(SerializableEnum):
    RECAPTCHA = "RECAPTCHA"
    PUSH_CHALLENGE = "PUSH_CHALLENGE"


@dataclass
class ProofRequiredError(SerializableAttrs):
    options: List[ProofRequiredType] = field(factory=lambda: [])
    message: Optional[str] = None
    retry_after: Optional[int] = None
    token: Optional[str] = None


@dataclass
class SendSuccessData(SerializableAttrs):
    devices: List[int] = field(factory=lambda: [])
    duration: Optional[int] = None
    needs_sync: bool = field(json="needsSync", default=False)
    unidentified: bool = field(json="unidentified", default=False)


@dataclass
class SendMessageResult(SerializableAttrs):
    address: Address
    success: Optional[SendSuccessData] = None
    proof_required_failure: Optional[ProofRequiredError] = None
    identity_failure: Optional[str] = field(json="identityFailure", default=None)
    network_failure: bool = field(json="networkFailure", default=False)
    unregistered_failure: bool = field(json="unregisteredFailure", default=False)


@dataclass
class SendMessageResponse(SerializableAttrs):
    results: List[SendMessageResult]
    timestamp: int
