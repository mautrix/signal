from mautrix.util.async_db import Database

from .disappearing_message import DisappearingMessage
from .message import Message
from .portal import Portal
from .puppet import Puppet
from .reaction import Reaction
from .upgrade import upgrade_table
from .user import User
from .util import ensure_uuid


def init(db: Database) -> None:
    for table in (User, Puppet, Portal, Message, Reaction, DisappearingMessage):
        table.db = db


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
