-- v17: Refactor types (SQLite)
-- transaction: off
-- only: sqlite

-- This is separate from v16 so that postgres can run with transaction: on
-- (split upgrades by dialect don't currently allow disabling transaction in only one dialect)

DROP TABLE IF EXISTS user_portal;

PRAGMA foreign_keys = OFF;
BEGIN;

CREATE TABLE message_new (
    sender     uuid    NOT NULL,
    timestamp  BIGINT  NOT NULL,
    part_index INTEGER NOT NULL,

    signal_chat_id  TEXT NOT NULL,
    signal_receiver TEXT NOT NULL,

    mxid    TEXT NOT NULL,
    mx_room TEXT NOT NULL,

    PRIMARY KEY (sender, timestamp, part_index, signal_receiver),
    CONSTRAINT message_portal_fkey FOREIGN KEY (signal_chat_id, signal_receiver) REFERENCES portal(chat_id, receiver) ON DELETE CASCADE ON UPDATE CASCADE,
    FOREIGN KEY (sender) REFERENCES puppet(uuid) ON DELETE CASCADE,
    CONSTRAINT message_mxid_unique UNIQUE (mxid)
);

CREATE TABLE reaction_new (
    msg_author    uuid    NOT NULL,
    msg_timestamp BIGINT  NOT NULL,
    -- part_index is not used in reactions, but is required for the foreign key.
    _part_index   INTEGER NOT NULL DEFAULT 0,

    author uuid NOT NULL,
    emoji  TEXT NOT NULL,

    signal_chat_id  TEXT NOT NULL,
    signal_receiver TEXT NOT NULL,

    mxid    TEXT NOT NULL,
    mx_room TEXT NOT NULL,

    PRIMARY KEY (msg_author, msg_timestamp, author, signal_receiver),
    CONSTRAINT reaction_message_fkey FOREIGN KEY (msg_author, msg_timestamp, _part_index, signal_receiver)
        REFERENCES message (sender, timestamp, part_index, signal_receiver) ON DELETE CASCADE ON UPDATE CASCADE,
    FOREIGN KEY (author) REFERENCES puppet(uuid) ON DELETE CASCADE,
    CONSTRAINT reaction_mxid_unique UNIQUE (mxid)
);


INSERT INTO message_new
SELECT sender,
       CASE WHEN timestamp > 1500000000000000 THEN timestamp / 1000 ELSE timestamp END,
       CASE WHEN timestamp > 1500000000000000 THEN timestamp % 1000 ELSE 0 END,
       COALESCE(signal_chat_id, ''),
       COALESCE(signal_receiver, ''),
       mxid,
       mx_room
FROM message;

INSERT INTO reaction_new
SELECT msg_author,
       msg_timestamp,
       0, -- _part_index
       author,
       emoji,
       COALESCE(signal_chat_id, ''),
       COALESCE(signal_receiver, ''),
       mxid,
       mx_room
FROM reaction
WHERE msg_timestamp<1500000000000000;

DROP TABLE message;
DROP TABLE reaction;
ALTER TABLE message_new RENAME TO message;
ALTER TABLE reaction_new RENAME TO reaction;

PRAGMA foreign_key_check;
COMMIT;

PRAGMA foreign_keys = ON;

BEGIN;
CREATE TABLE lost_portals (
    mxid     TEXT PRIMARY KEY,
    chat_id  TEXT,
    receiver TEXT
);
INSERT INTO lost_portals SELECT mxid, chat_id, receiver FROM portal WHERE mxid<>'';
DELETE FROM portal WHERE receiver<>'' AND receiver NOT IN (SELECT username FROM "user" WHERE uuid<>'');
UPDATE portal SET receiver=(SELECT uuid FROM "user" WHERE username=receiver LIMIT 1) WHERE receiver<>'';
UPDATE portal SET receiver='00000000-0000-0000-0000-000000000000' WHERE receiver='';
DELETE FROM portal WHERE chat_id NOT LIKE '________-____-____-____-____________' AND LENGTH(chat_id) <> 44;
DELETE FROM lost_portals WHERE mxid IN (SELECT mxid FROM portal WHERE mxid<>'');
COMMIT;

PRAGMA foreign_keys = OFF;

BEGIN;

CREATE TABLE portal_new (
    chat_id     TEXT    NOT NULL,
    receiver    uuid    NOT NULL,
    mxid        TEXT,
    name        TEXT    NOT NULL,
    topic       TEXT    NOT NULL,
    encrypted   BOOLEAN NOT NULL DEFAULT false,
    avatar_hash TEXT    NOT NULL,
    avatar_url  TEXT    NOT NULL,
    name_set    BOOLEAN NOT NULL DEFAULT false,
    avatar_set  BOOLEAN NOT NULL DEFAULT false,
    revision    INTEGER NOT NULL DEFAULT 0,

    expiration_time BIGINT NOT NULL,
    relay_user_id   TEXT   NOT NULL,

    PRIMARY KEY (chat_id, receiver),
    CONSTRAINT portal_mxid_unique UNIQUE(mxid)
);

INSERT INTO portal_new
    SELECT chat_id, receiver, CASE WHEN mxid='' THEN NULL ELSE mxid END,
           COALESCE(name, ''), COALESCE(topic, ''), encrypted, COALESCE(avatar_hash, ''), COALESCE(avatar_url, ''),
           name_set, avatar_set, revision, COALESCE(expiration_time, 0), COALESCE(relay_user_id, '')
    FROM portal;
DROP TABLE portal;
ALTER TABLE portal_new RENAME TO portal;

CREATE TABLE puppet_new (
    uuid         uuid    PRIMARY KEY,
    number       TEXT    UNIQUE,
    name         TEXT    NOT NULL,
    name_quality INTEGER NOT NULL,
    avatar_hash  TEXT    NOT NULL,
    avatar_url   TEXT    NOT NULL,
    name_set     BOOLEAN NOT NULL DEFAULT false,
    avatar_set   BOOLEAN NOT NULL DEFAULT false,

    is_registered    BOOLEAN NOT NULL DEFAULT false,
    contact_info_set BOOLEAN NOT NULL DEFAULT false,

    custom_mxid  TEXT,
    access_token TEXT NOT NULL,

    CONSTRAINT puppet_custom_mxid_unique UNIQUE(custom_mxid)
);

INSERT INTO puppet_new
    SELECT uuid, number, COALESCE(name, ''), COALESCE(name_quality, 0), COALESCE(avatar_hash, ''),
        COALESCE(avatar_url, ''), name_set, avatar_set, is_registered, contact_info_set,
        CASE WHEN custom_mxid='' THEN NULL ELSE custom_mxid END, COALESCE(access_token, '')
    FROM puppet;
DROP TABLE puppet;
ALTER TABLE puppet_new RENAME TO puppet;

CREATE TABLE user_new (
    mxid  TEXT PRIMARY KEY,
    uuid  uuid,
    phone TEXT,

    management_room TEXT,

    CONSTRAINT user_uuid_unique UNIQUE(uuid)
);

INSERT INTO user_new
    SELECT mxid, uuid, username, management_room
    FROM user;
DROP TABLE user;
ALTER TABLE user_new RENAME TO user;

CREATE TABLE disappearing_message_new (
    mxid                TEXT   NOT NULL PRIMARY KEY,
    room_id             TEXT   NOT NULL,
    expiration_seconds  BIGINT NOT NULL,
    expiration_ts       BIGINT
);

INSERT INTO disappearing_message_new
    SELECT mxid, room_id, COALESCE(expiration_seconds, 0), expiration_ts
    FROM disappearing_message;
DROP TABLE disappearing_message;
ALTER TABLE disappearing_message_new RENAME TO disappearing_message;

PRAGMA foreign_key_check;
COMMIT;
PRAGMA foreign_keys = ON;
