-- v0 -> v7: Latest revision
CREATE TABLE signalmeow_device (
    aci_uuid              TEXT PRIMARY KEY,

    aci_identity_key_pair bytea   NOT NULL,
    registration_id       INTEGER NOT NULL CHECK ( registration_id >= 0 AND registration_id < 4294967296 ),

    pni_uuid              TEXT    NOT NULL,
    pni_identity_key_pair bytea   NOT NULL,
    pni_registration_id   INTEGER NOT NULL CHECK ( pni_registration_id >= 0 AND pni_registration_id < 4294967296 ),

    device_id             INTEGER NOT NULL,
    number                TEXT    NOT NULL DEFAULT '',
    password              TEXT    NOT NULL DEFAULT ''
);

CREATE TABLE signalmeow_pre_keys (
    aci_uuid  TEXT    NOT NULL,
    key_id    INTEGER NOT NULL,
    uuid_kind TEXT    NOT NULL,
    is_signed BOOLEAN NOT NULL,
    key_pair  bytea   NOT NULL,
    uploaded  BOOLEAN NOT NULL,

    PRIMARY KEY (aci_uuid, uuid_kind, is_signed, key_id),
    FOREIGN KEY (aci_uuid) REFERENCES signalmeow_device (aci_uuid) ON DELETE CASCADE ON UPDATE CASCADE
);

CREATE TABLE signalmeow_identity_keys (
    our_aci_uuid    TEXT    NOT NULL,
    their_aci_uuid  TEXT    NOT NULL,
    their_device_id INTEGER NOT NULL,
    key             bytea   NOT NULL,
    trust_level     TEXT    NOT NULL,

    PRIMARY KEY (our_aci_uuid, their_aci_uuid, their_device_id),
    FOREIGN KEY (our_aci_uuid) REFERENCES signalmeow_device (aci_uuid) ON DELETE CASCADE ON UPDATE CASCADE
);

CREATE TABLE signalmeow_sessions (
    our_aci_uuid    TEXT    NOT NULL,
    their_aci_uuid  TEXT    NOT NULL,
    their_device_id INTEGER NOT NULL,
    record          bytea   NOT NULL,

    PRIMARY KEY (our_aci_uuid, their_aci_uuid, their_device_id),
    FOREIGN KEY (our_aci_uuid) REFERENCES signalmeow_device (aci_uuid) ON DELETE CASCADE ON UPDATE CASCADE
);

CREATE TABLE signalmeow_profile_keys (
    our_aci_uuid   TEXT  NOT NULL,
    their_aci_uuid TEXT  NOT NULL,
    key            bytea NOT NULL,

    PRIMARY KEY (our_aci_uuid, their_aci_uuid),
    FOREIGN KEY (our_aci_uuid) REFERENCES signalmeow_device (aci_uuid) ON DELETE CASCADE ON UPDATE CASCADE
);

CREATE TABLE signalmeow_sender_keys (
    our_aci_uuid     TEXT    NOT NULL,
    sender_uuid      TEXT    NOT NULL,
    sender_device_id INTEGER NOT NULL,
    distribution_id  TEXT    NOT NULL,
    key_record       bytea   NOT NULL,

    PRIMARY KEY (our_aci_uuid, sender_uuid, sender_device_id, distribution_id),
    FOREIGN KEY (our_aci_uuid) REFERENCES signalmeow_device (aci_uuid) ON DELETE CASCADE ON UPDATE CASCADE
);

CREATE TABLE signalmeow_groups (
    our_aci_uuid     TEXT NOT NULL,
    group_identifier TEXT NOT NULL,
    master_key       TEXT NOT NULL,

    PRIMARY KEY (our_aci_uuid, group_identifier)
);

CREATE TABLE signalmeow_contacts (
    our_aci_uuid        TEXT NOT NULL,
    aci_uuid            TEXT NOT NULL,
    -- TODO make all fields not null
    e164_number         TEXT,
    contact_name        TEXT,
    contact_avatar_hash TEXT,
    profile_key         bytea,
    profile_name        TEXT,
    profile_about       TEXT,
    profile_about_emoji TEXT,
    profile_avatar_path TEXT NOT NULL DEFAULT '',
    profile_avatar_hash TEXT,
    profile_fetch_ts    BIGINT NOT NULL DEFAULT 0,

    PRIMARY KEY (our_aci_uuid, aci_uuid),
    FOREIGN KEY (our_aci_uuid) REFERENCES signalmeow_device (aci_uuid) ON DELETE CASCADE ON UPDATE CASCADE
);

CREATE TABLE signalmeow_kyber_pre_keys (
    aci_uuid       TEXT    NOT NULL,
    key_id         INTEGER NOT NULL,
    uuid_kind      TEXT    NOT NULL,
    key_pair       bytea   NOT NULL,
    is_last_resort BOOLEAN NOT NULL,

    PRIMARY KEY (aci_uuid, uuid_kind, key_id),
    FOREIGN KEY (aci_uuid) REFERENCES signalmeow_device (aci_uuid) ON DELETE CASCADE ON UPDATE CASCADE
);
