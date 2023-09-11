-- v0 -> v12: Latest revision

CREATE TABLE portal (
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
);

CREATE TABLE puppet (
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
    base_url     TEXT,
    contact_info_set BOOLEAN NOT NULL DEFAULT false
);

CREATE TABLE "user" (
    mxid            TEXT PRIMARY KEY,
    username        TEXT,
    uuid            UUID,
    management_room TEXT,
    notice_room     TEXT
);

CREATE TABLE message (
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
);

CREATE TABLE reaction (
    mxid            TEXT   NOT NULL,
    mx_room         TEXT   NOT NULL,

    signal_chat_id  TEXT   NOT NULL,
    signal_receiver TEXT   NOT NULL,

    author          UUID   NOT NULL,
    msg_author      UUID   NOT NULL,
    msg_timestamp   BIGINT NOT NULL,
    emoji           TEXT   NOT NULL,

    PRIMARY KEY (signal_chat_id, signal_receiver, msg_author, msg_timestamp, author),
    CONSTRAINT reaction_message_fkey
    FOREIGN KEY (msg_author, msg_timestamp, signal_chat_id, signal_receiver)
    REFERENCES message(sender, timestamp, signal_chat_id, signal_receiver)
    ON DELETE CASCADE,
    FOREIGN KEY (author) REFERENCES puppet(uuid) ON DELETE CASCADE,
    UNIQUE (mxid, mx_room)
);

CREATE TABLE disappearing_message (
    room_id             TEXT,
    mxid                TEXT,
    expiration_seconds  BIGINT,
    expiration_ts       BIGINT,

    PRIMARY KEY (room_id, mxid)
);
