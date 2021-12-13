import sqlite3
import uuid

from mautrix.util.async_db import Database

from .disappearing_message import DisappearingMessage
from .message import Message
from .portal import Portal
from .puppet import Puppet
from .reaction import Reaction
from .upgrade import upgrade_table
from .user import User


def init(db: Database) -> None:
    for table in (User, Puppet, Portal, Message, Reaction, DisappearingMessage):
        table.db = db


# TODO should this be in mautrix-python?
sqlite3.register_adapter(uuid.UUID, lambda u: str(u))
sqlite3.register_converter(
    "UUID", lambda b: uuid.UUID(b.decode("utf-8") if isinstance(b, bytes) else b)
)

__all__ = [
    "upgrade_table",
    "init",
    "User",
    "Puppet",
    "Portal",
    "Message",
    "Reaction",
    "DisappearingMessage",
]
