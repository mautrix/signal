# Copyright (c) 2020 Tulir Asokan
#
# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this
# file, You can obtain one at http://mozilla.org/MPL/2.0/.
from typing import Optional, Dict, Any, List
from uuid import UUID

from attr import dataclass
import attr

from mautrix.types import SerializableAttrs, SerializableEnum


@dataclass
class Account(SerializableAttrs['Account']):
    device_id: int = attr.ib(metadata={"json": "deviceId"})
    username: str
    filename: str
    registered: bool
    has_keys: bool
    subscribed: bool
    uuid: Optional[UUID] = None


@dataclass
class Address(SerializableAttrs['Address']):
    number: Optional[str] = None
    uuid: Optional[UUID] = None

    @property
    def is_valid(self) -> bool:
        return bool(self.number) or bool(self.uuid)


@dataclass
class Contact(SerializableAttrs['Contact']):
    address: Address
    name: Optional[str] = None
    color: Optional[str] = None
    profile_key: Optional[str] = attr.ib(default=None, metadata={"json": "profileKey"})
    message_expiration_time: int = attr.ib(default=0, metadata={"json": "messageExpirationTime"})


@dataclass
class Profile(SerializableAttrs['Profile']):
    name: str
    avatar: str
    identity_key: str
    unidentified_access: str
    unrestricted_unidentified_access: bool


@dataclass
class Group(SerializableAttrs['Group']):
    group_id: str = attr.ib(metadata={"json": "groupId"})
    name: str
    type: Optional[str] = None


@dataclass
class FullGroup(Group, SerializableAttrs['FullGroup']):
    members: List[Address] = attr.ib(factory=lambda: [])
    avatar_id: int = attr.ib(default=0, metadata={"json": "avatarId"})


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
    text: str
    # TODO: attachments, mentions


@dataclass
class Reaction(SerializableAttrs['Reaction']):
    emoji: str
    remove: bool
    target_author: Address = attr.ib(metadata={"json": "targetAuthor"})
    target_sent_timestamp: int = attr.ib(metadata={"json": "targetSentTimestamp"})


@dataclass
class Sticker(SerializableAttrs['Sticker']):
    attachment: Attachment
    pack_id: str = attr.ib(metadata={"json": "packID"})
    pack_key: str = attr.ib(metadata={"json": "packKey"})
    sticker_id: int = attr.ib(metadata={"json": "stickerID"})


@dataclass
class MessageData(SerializableAttrs['MessageData']):
    timestamp: int

    body: Optional[str] = None
    quote: Optional[Quote] = None
    reaction: Optional[Reaction] = None
    attachments: List[Attachment] = attr.ib(factory=lambda: [])
    sticker: Optional[Sticker] = None
    # TODO mentions (although signald doesn't support group v2 yet)

    group: Optional[Group] = None

    end_session: bool = attr.ib(default=False, metadata={"json": "endSession"})
    expires_in_seconds: int = attr.ib(default=0, metadata={"json": "expiresInSeconds"})
    profile_key_update: bool = attr.ib(default=False, metadata={"json": "profileKeyUpdate"})
    view_once: bool = attr.ib(default=False, metadata={"json": "viewOnce"})

    @property
    def all_attachments(self) -> List[Attachment]:
        return self.attachments + ([self.sticker] if self.sticker else [])


@dataclass
class SentSyncMessage(SerializableAttrs['SentSyncMessage']):
    message: MessageData
    timestamp: int
    expiration_start_timestamp: int = attr.ib(metadata={"json": "expirationStartTimestamp"})
    is_recipient_update: bool = attr.ib(default=False, metadata={"json": "isRecipientUpdate"})
    unidentified_status: Dict[str, bool] = attr.ib(factory=lambda: {})
    destination: Optional[Address] = None


class TypingAction(SerializableEnum):
    STARTED = "STARTED"
    STOPPED = "STOPPED"


@dataclass
class TypingNotification(SerializableAttrs['TypingNotification']):
    action: TypingAction
    timestamp: int
    group_id: Optional[str] = None


@dataclass
class OwnReadReceipt(SerializableAttrs['OwnReadReceipt']):
    sender: Address
    timestamp: int


class ReceiptType(SerializableEnum):
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


@dataclass
class Message(SerializableAttrs['Message']):
    username: str
    source: Address
    timestamp: int
    timestamp_iso: str = attr.ib(metadata={"json": "timestampISO"})

    type: MessageType
    source_device: int = attr.ib(metadata={"json": "sourceDevice"})
    server_timestamp: int = attr.ib(metadata={"json": "serverTimestamp"})
    server_delivered_timestamp: int = attr.ib(metadata={"json": "serverDeliveredTimestamp"})
    has_content: bool = attr.ib(metadata={"json": "hasContent"})
    is_unidentified_sender: bool = attr.ib(metadata={"json": "isUnidentifiedSender"})
    has_legacy_message: bool = attr.ib(default=False, metadata={"json": "hasLegacyMessage"})

    data_message: Optional[MessageData] = attr.ib(default=None, metadata={"json": "dataMessage"})
    sync_message: Optional[SyncMessage] = attr.ib(default=None, metadata={"json": "syncMessage"})
    typing: Optional[TypingNotification] = None
    receipt: Optional[Receipt] = None
