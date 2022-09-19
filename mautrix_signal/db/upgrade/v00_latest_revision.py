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
from mautrix.util.async_db import Connection

from . import upgrade_table


@upgrade_table.register(description="Initial revision", upgrades_to=11)
async def upgrade_latest(conn: Connection) -> None:
    await conn.execute(
        """CREATE TABLE portal (
            chat_id     TEXT,
            receiver    TEXT,
            mxid        TEXT,
            name        TEXT,
            topic       TEXT,
            encrypted   BOOLEAN NOT NULL DEFAULT false,
            avatar_hash TEXT,
            avatar_url  TEXT,
            name_set    BOOLEAN NOT NULL DEFAULT false,
            avatar_set  BOOLEAN NOT NULL DEFAULT false,
            revision    INTEGER NOT NULL DEFAULT 0,
            expiration_time BIGINT,
            relay_user_id   TEXT,

            PRIMARY KEY (chat_id, receiver)
        )"""
    )
    await conn.execute(
        """CREATE TABLE "user" (
            mxid        TEXT PRIMARY KEY,
            username    TEXT,
            uuid        UUID,
            notice_room TEXT
        )"""
    )
    await conn.execute(
        """CREATE TABLE puppet (
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
        """CREATE TABLE user_portal (
            "user"          TEXT,
            portal          TEXT,
            portal_receiver TEXT,
            in_community    BOOLEAN NOT NULL DEFAULT false,

            FOREIGN KEY (portal, portal_receiver) REFERENCES portal(chat_id, receiver)
                ON UPDATE CASCADE ON DELETE CASCADE
        )"""
    )
    await conn.execute(
        """CREATE TABLE message (
            mxid    TEXT NOT NULL,
            mx_room TEXT NOT NULL,
            sender          UUID,
            timestamp       BIGINT,
            signal_chat_id  TEXT,
            signal_receiver TEXT,

            PRIMARY KEY (sender, timestamp, signal_chat_id, signal_receiver),
            FOREIGN KEY (signal_chat_id, signal_receiver) REFERENCES portal(chat_id, receiver) ON DELETE CASCADE,
            FOREIGN KEY (sender) REFERENCES puppet(uuid) ON DELETE CASCADE,
            UNIQUE (mxid, mx_room)
        )"""
    )
    await conn.execute(
        """CREATE TABLE reaction (
            mxid    TEXT NOT NULL,
            mx_room TEXT NOT NULL,

            signal_chat_id  TEXT   NOT NULL,
            signal_receiver TEXT   NOT NULL,
            msg_author      UUID   NOT NULL,
            msg_timestamp   BIGINT NOT NULL,
            author          UUID   NOT NULL,

            emoji TEXT NOT NULL,

            PRIMARY KEY (signal_chat_id, signal_receiver, msg_author, msg_timestamp, author),
            CONSTRAINT reaction_message_fkey
                FOREIGN KEY (msg_author, msg_timestamp, signal_chat_id, signal_receiver)
                    REFERENCES message(sender, timestamp, signal_chat_id, signal_receiver)
                    ON DELETE CASCADE,
            FOREIGN KEY (author) REFERENCES puppet(uuid) ON DELETE CASCADE,
            UNIQUE (mxid, mx_room)
        )"""
    )
    await conn.execute(
        """CREATE TABLE disappearing_message (
            room_id             TEXT,
            mxid                TEXT,
            expiration_seconds  BIGINT,
            expiration_ts       BIGINT,

            PRIMARY KEY (room_id, mxid)
        )"""
    )
