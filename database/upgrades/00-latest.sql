-- v0 -> v20 (compatible with v17+): Latest revision

CREATE TABLE portal (
    chat_id     TEXT    NOT NULL,
    receiver    uuid    NOT NULL,
    mxid        TEXT,
    name        TEXT    NOT NULL,
    topic       TEXT    NOT NULL,
    encrypted   BOOLEAN NOT NULL DEFAULT false,
    avatar_path TEXT    NOT NULL DEFAULT '',
    avatar_hash TEXT    NOT NULL,
    avatar_url  TEXT    NOT NULL,
    name_set    BOOLEAN NOT NULL DEFAULT false,
    avatar_set  BOOLEAN NOT NULL DEFAULT false,
    topic_set   BOOLEAN NOT NULL DEFAULT false,
    revision    INTEGER NOT NULL DEFAULT 0,

    expiration_time BIGINT NOT NULL,
    relay_user_id   TEXT   NOT NULL,

    PRIMARY KEY (chat_id, receiver),
    CONSTRAINT portal_mxid_unique UNIQUE(mxid)
);

CREATE TABLE puppet (
    uuid         uuid    PRIMARY KEY,
    number       TEXT    UNIQUE,
    name         TEXT    NOT NULL,
    name_quality INTEGER NOT NULL,
    avatar_path  TEXT    NOT NULL,
    avatar_hash  TEXT    NOT NULL,
    avatar_url   TEXT    NOT NULL,
    name_set     BOOLEAN NOT NULL DEFAULT false,
    avatar_set   BOOLEAN NOT NULL DEFAULT false,

    is_registered      BOOLEAN NOT NULL DEFAULT false,
    contact_info_set   BOOLEAN NOT NULL DEFAULT false,
    profile_fetched_at BIGINT,

    custom_mxid  TEXT,
    access_token TEXT NOT NULL,

    CONSTRAINT puppet_custom_mxid_unique UNIQUE(custom_mxid)
);

CREATE TABLE "user" (
    mxid  TEXT PRIMARY KEY,
    uuid  uuid,
    phone TEXT,

    management_room TEXT,
    space_room      TEXT,

    CONSTRAINT user_uuid_unique UNIQUE(uuid)
);

CREATE TABLE user_portal (
    user_mxid       TEXT,
    portal_chat_id  TEXT,
    portal_receiver uuid,
    last_read_ts    BIGINT  NOT NULL DEFAULT 0,
    in_space        BOOLEAN NOT NULL DEFAULT false,

    PRIMARY KEY (user_mxid, portal_chat_id, portal_receiver),
    CONSTRAINT user_portal_user_fkey FOREIGN KEY (user_mxid)
        REFERENCES "user"(mxid) ON UPDATE CASCADE ON DELETE CASCADE,
    CONSTRAINT user_portal_portal_fkey FOREIGN KEY (portal_chat_id, portal_receiver)
        REFERENCES portal(chat_id, receiver) ON UPDATE CASCADE ON DELETE CASCADE
);

CREATE TABLE message (
    sender     uuid    NOT NULL,
    timestamp  BIGINT  NOT NULL,
    part_index INTEGER NOT NULL,

    signal_chat_id  TEXT NOT NULL,
    signal_receiver uuid NOT NULL,

    mxid    TEXT NOT NULL,
    mx_room TEXT NOT NULL,

    PRIMARY KEY (sender, timestamp, part_index, signal_receiver),
    CONSTRAINT message_portal_fkey FOREIGN KEY (signal_chat_id, signal_receiver)
        REFERENCES portal(chat_id, receiver) ON DELETE CASCADE ON UPDATE CASCADE,
    FOREIGN KEY (sender) REFERENCES puppet(uuid) ON DELETE CASCADE,
    CONSTRAINT message_mxid_unique UNIQUE (mxid)
);

CREATE TABLE reaction (
    msg_author    uuid    NOT NULL,
    msg_timestamp BIGINT  NOT NULL,
    -- part_index is not used in reactions, but is required for the foreign key.
    _part_index   INTEGER NOT NULL DEFAULT 0,

    author uuid NOT NULL,
    emoji  TEXT NOT NULL,

    signal_chat_id  TEXT NOT NULL,
    signal_receiver uuid NOT NULL,

    mxid    TEXT NOT NULL,
    mx_room TEXT NOT NULL,

    PRIMARY KEY (msg_author, msg_timestamp, author, signal_receiver),
    CONSTRAINT reaction_message_fkey FOREIGN KEY (msg_author, msg_timestamp, _part_index, signal_receiver)
        REFERENCES message (sender, timestamp, part_index, signal_receiver) ON DELETE CASCADE ON UPDATE CASCADE,
    FOREIGN KEY (author) REFERENCES puppet(uuid) ON DELETE CASCADE,
    CONSTRAINT reaction_mxid_unique UNIQUE (mxid)
);

CREATE TABLE disappearing_message (
    mxid                TEXT   NOT NULL PRIMARY KEY,
    room_id             TEXT   NOT NULL,
    expiration_seconds  BIGINT NOT NULL,
    expiration_ts       BIGINT
);
