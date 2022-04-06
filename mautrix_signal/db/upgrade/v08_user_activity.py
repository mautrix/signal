from mautrix.util.async_db import Connection

from . import upgrade_table


@upgrade_table.register(description="Add activity times to the puppet table")
async def upgrade_v8(conn: Connection) -> None:
    await conn.execute("ALTER TABLE puppet ADD COLUMN first_activity_ts BIGINT")
    await conn.execute("ALTER TABLE puppet ADD COLUMN last_activity_ts BIGINT")
