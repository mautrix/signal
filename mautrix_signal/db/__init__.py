from mautrix.util.async_db import Database

from .upgrade import upgrade_table
from .user import User
from .puppet import Puppet
from .portal import Portal
from .message import Message
from .reaction import Reaction


def init(db: Database) -> None:
    for table in (User, Puppet, Portal, Message, Reaction):
        table.db = db


__all__ = ["upgrade_table", "init", "User", "Puppet", "Portal", "Message", "Reaction"]
