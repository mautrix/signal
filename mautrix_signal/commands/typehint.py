from typing import TYPE_CHECKING

from mautrix.bridge.commands import CommandEvent as BaseCommandEvent

if TYPE_CHECKING:
    from ..__main__ import SignalBridge
    from ..portal import Portal
    from ..user import User


class CommandEvent(BaseCommandEvent):
    bridge: "SignalBridge"
    sender: "User"
    portal: "Portal"
