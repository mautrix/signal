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


@upgrade_table.register(description="Drop support for phone numbers as puppet identifiers")
async def upgrade_v11(conn: Connection, scheme: Scheme) -> None:
    await conn.execute("DELETE FROM portal WHERE chat_id LIKE '+%'")
    await conn.execute("DELETE FROM message WHERE sender LIKE '+%'")
    await conn.execute("DELETE FROM reaction WHERE author LIKE '+%'")
    puppet_uuid_as_text = "puppet.uuid" if scheme == Scheme.SQLITE else "puppet.uuid::text"
    await conn.execute(
        f"""
        DELETE FROM message WHERE sender IN (
            SELECT DISTINCT(message.sender) FROM message
            LEFT JOIN puppet ON message.sender={puppet_uuid_as_text}
            WHERE puppet.uuid IS NULL
        )
        """
    )
    await conn.execute(
        f"""
        DELETE FROM reaction WHERE author IN (
            SELECT DISTINCT(reaction.author) FROM reaction
            LEFT JOIN puppet ON reaction.author={puppet_uuid_as_text}
            WHERE puppet.uuid IS NULL
        )
        """
    )
    await conn.execute("DELETE FROM puppet WHERE uuid IS NULL")
    if scheme in (Scheme.POSTGRES, Scheme.COCKROACH):
        await conn.execute(
            """
            ALTER TABLE puppet
                DROP CONSTRAINT puppet_uuid_key,
                ADD CONSTRAINT puppet_pkey PRIMARY KEY (uuid)
            """
        )
        await conn.execute("ALTER TABLE puppet DROP COLUMN number_registered")
        await conn.execute("ALTER TABLE puppet RENAME COLUMN uuid_registered TO is_registered")
        for c_row in await conn.fetch(
            "SELECT constraint_name FROM information_schema.table_constraints tc "
            "WHERE tc.constraint_type='FOREIGN KEY' AND tc.table_name='reaction'"
        ):
            constraint_name = c_row["constraint_name"]
            if constraint_name.startswith("reaction_msg_author_"):
                await conn.execute(f"ALTER TABLE reaction DROP CONSTRAINT {constraint_name}")
        await conn.execute("ALTER TABLE message ALTER COLUMN sender TYPE UUID USING sender::uuid")
        await conn.execute(
            "ALTER TABLE reaction ALTER COLUMN msg_author TYPE UUID USING msg_author::uuid"
        )
        await conn.execute(
            """
            ALTER TABLE reaction ADD CONSTRAINT reaction_message_fkey
                FOREIGN KEY (msg_author, msg_timestamp, signal_chat_id, signal_receiver)
                REFERENCES message(sender, timestamp, signal_chat_id, signal_receiver)
                ON DELETE CASCADE
            """
        )
        await conn.execute("ALTER TABLE reaction ALTER COLUMN author TYPE UUID USING author::uuid")
        await conn.execute(
            """
            ALTER TABLE message ADD CONSTRAINT message_sender_fkey
                FOREIGN KEY (sender) REFERENCES puppet(uuid) ON DELETE CASCADE
            """
        )
        await conn.execute(
            """
            ALTER TABLE reaction ADD CONSTRAINT reaction_author_fkey
                FOREIGN KEY (author) REFERENCES puppet(uuid) ON DELETE CASCADE
            """
        )
    else:
        await conn.execute(
            """CREATE TABLE new_puppet (
                uuid         UUID PRIMARY KEY,
                number       TEXT UNIQUE,
                name         TEXT,
                name_quality INTEGER NOT NULL DEFAULT 0,
                avatar_hash  TEXT,
                avatar_url   TEXT,
                name_set     BOOLEAN NOT NULL DEFAULT false,
                avatar_set   BOOLEAN NOT NULL DEFAULT false,

                is_registered BOOLEAN NOT NULL DEFAULT false,

                custom_mxid  TEXT,
                access_token TEXT,
                next_batch   TEXT,
                base_url     TEXT
            )"""
        )
        await conn.execute(
            """
            INSERT INTO new_puppet (
                uuid, number, name, name_quality, avatar_hash, avatar_url, name_set, avatar_set,
                is_registered, custom_mxid, access_token, next_batch, base_url
            )
            SELECT uuid, number, name, name_quality, avatar_hash, avatar_url, name_set, avatar_set,
                   uuid_registered, custom_mxid, access_token, next_batch, base_url
            FROM puppet
            """
        )
        await conn.execute("DROP TABLE puppet")
        await conn.execute("ALTER TABLE new_puppet RENAME TO puppet")
