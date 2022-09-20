from __future__ import annotations

from uuid import UUID
import sqlite3


def ensure_uuid(val: bytes | str | UUID) -> UUID:
    if not isinstance(val, UUID):
        if isinstance(val, bytes):
            val = val.decode("utf-8")
        return UUID(val)
    return val


sqlite3.register_adapter(UUID, str)
sqlite3.register_converter("UUID", ensure_uuid)
