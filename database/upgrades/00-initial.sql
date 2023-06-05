-- v0 -> v1: Latest revision

CREATE TABLE portal (
    signal_id          TEXT,
    receiver      TEXT,
    other_user_id TEXT,
    type          INTEGER NOT NULL,

    mxid       TEXT UNIQUE,
    plain_name TEXT NOT NULL,
    name       TEXT NOT NULL,
    name_set   BOOLEAN NOT NULL,
    topic      TEXT NOT NULL,
    topic_set  BOOLEAN NOT NULL,
    avatar     TEXT NOT NULL,
    avatar_url TEXT NOT NULL,
    avatar_set BOOLEAN NOT NULL,
    encrypted  BOOLEAN NOT NULL,
    in_space   TEXT NOT NULL,

    first_event_id TEXT NOT NULL,

    relay_webhook_id     TEXT,
    relay_webhook_secret TEXT,

    PRIMARY KEY (signal_id, receiver)
);

CREATE TABLE puppet (
    id TEXT PRIMARY KEY,

    name       TEXT NOT NULL,
    name_set   BOOLEAN NOT NULL,
    avatar     TEXT NOT NULL,
    avatar_url TEXT NOT NULL,
    avatar_set BOOLEAN NOT NULL,

    custom_mxid  TEXT,
    access_token TEXT,
    next_batch   TEXT
);

CREATE TABLE "user" (
    mxid TEXT PRIMARY KEY,
    signal_id TEXT UNIQUE,

    management_room TEXT,
    space_room      TEXT,
    dm_space_room   TEXT,

    read_state_version INTEGER NOT NULL DEFAULT 0
);
