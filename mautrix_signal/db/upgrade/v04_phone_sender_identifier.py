# mautrix-signal - A Matrix-Signal puppeting bridge
# Copyright (C) 2022 Tulir Asokan
#
# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU Affero General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU Affero General Public License for more details.
#
# You should have received a copy of the GNU Affero General Public License
# along with this program.  If not, see <https://www.gnu.org/licenses/>.
from mautrix.util.async_db import Connection, Scheme

from . import upgrade_table


@upgrade_table.register(description="Allow phone numbers as message sender identifiers")
async def upgrade_v4(conn: Connection, scheme: Scheme) -> None:
    assert scheme != Scheme.SQLITE, "There shouldn't be any SQLites with this old schemes"

    cname = await conn.fetchval(
        "SELECT constraint_name FROM information_schema.table_constraints "
        "WHERE table_name='reaction' AND constraint_name LIKE '%_fkey'"
    )
    await conn.execute(f"ALTER TABLE reaction DROP CONSTRAINT {cname}")
    await conn.execute("ALTER TABLE reaction ALTER COLUMN msg_author SET DATA TYPE TEXT")
    await conn.execute("ALTER TABLE reaction ALTER COLUMN author SET DATA TYPE TEXT")
    await conn.execute("ALTER TABLE message ALTER COLUMN sender SET DATA TYPE TEXT")
    await conn.execute(
        f"ALTER TABLE reaction ADD CONSTRAINT {cname} "
        "FOREIGN KEY (msg_author, msg_timestamp, signal_chat_id, signal_receiver) "
        "  REFERENCES message(sender, timestamp, signal_chat_id, signal_receiver) "
        "  ON DELETE CASCADE ON UPDATE CASCADE"
    )
