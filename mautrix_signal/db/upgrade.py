# mautrix-signal - A Matrix-Signal puppeting bridge
# Copyright (C) 2020 Tulir Asokan
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
from asyncpg import Connection

from mautrix.util.async_db import UpgradeTable

upgrade_table = UpgradeTable()


@upgrade_table.register(description="Initial revision")
async def upgrade_v1(conn: Connection) -> None:
    await conn.execute("""CREATE TABLE portal (
        chat_id     TEXT,
        receiver    TEXT,
        mxid        TEXT,
        name        TEXT,
        encrypted   BOOLEAN NOT NULL DEFAULT false,

        PRIMARY KEY (chat_id, receiver)
    )""")
    await conn.execute("""CREATE TABLE "user" (
        mxid        TEXT PRIMARY KEY,
        username    TEXT,
        uuid        UUID,
        notice_room TEXT
    )""")
    await conn.execute("""CREATE TABLE puppet (
        uuid      UUID UNIQUE,
        number    TEXT UNIQUE,
        name      TEXT,

        uuid_registered   BOOLEAN NOT NULL DEFAULT false,
        number_registered BOOLEAN NOT NULL DEFAULT false,

        custom_mxid  TEXT,
        access_token TEXT,
        next_batch   TEXT
    )""")
    await conn.execute("""CREATE TABLE user_portal (
        "user"          TEXT,
        portal          TEXT,
        portal_receiver TEXT,
        in_community    BOOLEAN NOT NULL DEFAULT false,

        FOREIGN KEY (portal, portal_receiver) REFERENCES portal(chat_id, receiver)
            ON UPDATE CASCADE ON DELETE CASCADE
    )""")
    await conn.execute("""CREATE TABLE message (
        mxid    TEXT NOT NULL,
        mx_room TEXT NOT NULL,
        sender          UUID,
        timestamp       BIGINT,
        signal_chat_id  TEXT,
        signal_receiver TEXT,

        PRIMARY KEY (sender, timestamp, signal_chat_id, signal_receiver),
        FOREIGN KEY (signal_chat_id, signal_receiver) REFERENCES portal(chat_id, receiver)
            ON UPDATE CASCADE ON DELETE CASCADE,
        UNIQUE (mxid, mx_room)
    )""")
    await conn.execute("""CREATE TABLE reaction (
        mxid    TEXT NOT NULL,
        mx_room TEXT NOT NULL,

        signal_chat_id  TEXT   NOT NULL,
        signal_receiver TEXT   NOT NULL,
        msg_author      UUID   NOT NULL,
        msg_timestamp   BIGINT NOT NULL,
        author          UUID   NOT NULL,

        emoji TEXT NOT NULL,

        PRIMARY KEY (signal_chat_id, signal_receiver, msg_author, msg_timestamp, author),
        FOREIGN KEY (msg_author, msg_timestamp, signal_chat_id, signal_receiver)
            REFERENCES message(sender, timestamp, signal_chat_id, signal_receiver)
            ON DELETE CASCADE ON UPDATE CASCADE,
        UNIQUE (mxid, mx_room)
    )""")


@upgrade_table.register(description="Add avatar info to portal table")
async def upgrade_v2(conn: Connection) -> None:
    await conn.execute("ALTER TABLE portal ADD COLUMN avatar_hash TEXT")
    await conn.execute("ALTER TABLE portal ADD COLUMN avatar_url TEXT")


@upgrade_table.register(description="Add double-puppeting base_url to puppe table")
async def upgrade_v3(conn: Connection) -> None:
    await conn.execute("ALTER TABLE puppet ADD COLUMN base_url TEXT")
