-- v0 -> v1: Latest revision
CREATE TABLE "user" (
    mxid TEXT PRIMARY KEY,
    signal_id TEXT UNIQUE,

    signal_token   TEXT,
    management_room TEXT,
    space_room      TEXT,
    dm_space_room   TEXT,

    read_state_version INTEGER NOT NULL DEFAULT 0
)

CREATE TABLE portal (
    signal_id     TEXT,
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

    PRIMARY KEY (signal_id, receiver),
)
