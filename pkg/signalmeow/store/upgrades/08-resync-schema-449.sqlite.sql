-- v7 -> v8: Migration from https://github.com/mautrix/signal/pull/449 to match the new v8 upgrade
ALTER TABLE signalmeow_contacts DROP COLUMN profile_avatar_hash;

CREATE TABLE signalmeow_contacts_new (
    our_aci_uuid        TEXT   NOT NULL,
    aci_uuid            TEXT   NOT NULL,
    e164_number         TEXT   NOT NULL,
    contact_name        TEXT   NOT NULL,
    contact_avatar_hash TEXT   NOT NULL,
    profile_key         bytea,
    profile_name        TEXT   NOT NULL,
    profile_about       TEXT   NOT NULL,
    profile_about_emoji TEXT   NOT NULL,
    profile_avatar_path TEXT   NOT NULL,
    profile_fetched_at  BIGINT,

    PRIMARY KEY (our_aci_uuid, aci_uuid),
    FOREIGN KEY (our_aci_uuid) REFERENCES signalmeow_device (aci_uuid) ON DELETE CASCADE ON UPDATE CASCADE
);

INSERT INTO signalmeow_contacts_new
SELECT our_aci_uuid,
       aci_uuid,
       e164_number,
       contact_name,
       contact_avatar_hash,
       profile_key,
       profile_name,
       profile_about,
       profile_about_emoji,
       profile_avatar_path,
       CASE WHEN profile_fetch_ts <= 0 THEN NULL ELSE profile_fetch_ts END
FROM signalmeow_contacts;

DROP TABLE signalmeow_contacts;
ALTER TABLE signalmeow_contacts_new RENAME TO signalmeow_contacts;
