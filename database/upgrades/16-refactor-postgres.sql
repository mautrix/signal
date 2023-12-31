-- v16: Refactor types (Postgres)
-- only: postgres

-- Drop constraints so we can fix timestamps.
ALTER TABLE reaction DROP CONSTRAINT reaction_message_fkey;
ALTER TABLE message DROP CONSTRAINT message_pkey;

-- Add part index to message and fix the hacky timestamps
ALTER TABLE message ADD COLUMN part_index INTEGER;
UPDATE message
    SET timestamp=CASE WHEN timestamp > 1500000000000000 THEN timestamp / 1000 ELSE timestamp END,
        part_index=CASE WHEN timestamp > 1500000000000000 THEN timestamp % 1000 ELSE 0 END;
ALTER TABLE message ALTER COLUMN part_index SET NOT NULL;
ALTER TABLE reaction ADD COLUMN _part_index INTEGER NOT NULL DEFAULT 0;

-- Re-add the dropped constraints (but with part index and no chat)
ALTER TABLE message ADD PRIMARY KEY (sender, timestamp, part_index, signal_receiver);
ALTER TABLE message DROP CONSTRAINT message_signal_chat_id_signal_receiver_fkey;
ALTER TABLE message ADD CONSTRAINT message_portal_fkey
    FOREIGN KEY (signal_chat_id, signal_receiver)
        REFERENCES portal (chat_id, receiver)
        ON DELETE CASCADE ON UPDATE CASCADE;
ALTER TABLE reaction ADD CONSTRAINT reaction_message_fkey FOREIGN KEY (msg_author, msg_timestamp, _part_index, signal_receiver)
    REFERENCES message (sender, timestamp, part_index, signal_receiver) ON DELETE CASCADE ON UPDATE CASCADE;
-- Also update the reaction primary key
ALTER TABLE reaction DROP CONSTRAINT reaction_pkey;
ALTER TABLE reaction ADD PRIMARY KEY (author, msg_author, msg_timestamp, signal_receiver);

-- Change unique constraint from (mxid, mx_room) to just mxid.
ALTER TABLE message DROP CONSTRAINT message_mxid_mx_room_key;
ALTER TABLE message ADD CONSTRAINT message_mxid_unique UNIQUE (mxid);
ALTER TABLE reaction DROP CONSTRAINT reaction_mxid_mx_room_key;
ALTER TABLE reaction ADD CONSTRAINT reaction_mxid_unique UNIQUE (mxid);

CREATE TABLE lost_portals (
    mxid     TEXT PRIMARY KEY,
    chat_id  TEXT,
    receiver TEXT
);
INSERT INTO lost_portals SELECT mxid, chat_id, receiver FROM portal WHERE mxid<>'';

-- Make mxid column unique (requires using nulls for missing values)
UPDATE portal SET mxid=NULL WHERE mxid='';
ALTER TABLE portal ADD CONSTRAINT portal_mxid_unique UNIQUE(mxid);
-- Delete any portals that aren't associated with logged-in users.
DELETE FROM portal WHERE receiver<>'' AND receiver NOT IN (SELECT username FROM "user" WHERE uuid IS NOT NULL);
-- Change receiver to uuid instead of phone number, also add nil uuid for groups.
UPDATE portal SET receiver=(SELECT uuid FROM "user" WHERE username=receiver) WHERE receiver<>'';
UPDATE portal SET receiver='00000000-0000-0000-0000-000000000000' WHERE receiver='';
-- Drop the foreign keys again to allow changing types (the ON UPDATE CASCADEs are needed for the above step)
ALTER TABLE message DROP CONSTRAINT message_portal_fkey;
ALTER TABLE reaction DROP CONSTRAINT reaction_message_fkey;
ALTER TABLE portal ALTER COLUMN receiver TYPE uuid USING receiver::uuid;
ALTER TABLE message ALTER COLUMN signal_receiver TYPE uuid USING signal_receiver::uuid;
ALTER TABLE reaction ALTER COLUMN signal_receiver TYPE uuid USING signal_receiver::uuid;
-- Re-add the dropped constraints again
ALTER TABLE message ADD CONSTRAINT message_portal_fkey
    FOREIGN KEY (signal_chat_id, signal_receiver)
        REFERENCES portal (chat_id, receiver)
        ON DELETE CASCADE ON UPDATE CASCADE;
ALTER TABLE reaction ADD CONSTRAINT reaction_message_fkey FOREIGN KEY (msg_author, msg_timestamp, _part_index, signal_receiver)
    REFERENCES message (sender, timestamp, part_index, signal_receiver) ON DELETE CASCADE ON UPDATE CASCADE;
-- Delete group v1 portal entries
DELETE FROM portal WHERE chat_id NOT LIKE '________-____-____-____-____________' AND LENGTH(chat_id) <> 44;
DELETE FROM lost_portals WHERE mxid IN (SELECT mxid FROM portal WHERE mxid<>'');

-- Remove unnecessary nullables in portal
UPDATE portal SET name='' WHERE name IS NULL;
UPDATE portal SET topic='' WHERE topic IS NULL;
UPDATE portal SET avatar_hash='' WHERE avatar_hash IS NULL;
UPDATE portal SET avatar_url='' WHERE avatar_url IS NULL;
UPDATE portal SET expiration_time=0 WHERE expiration_time IS NULL;
UPDATE portal SET relay_user_id='' WHERE relay_user_id IS NULL;
ALTER TABLE portal ALTER COLUMN name SET NOT NULL;
ALTER TABLE portal ALTER COLUMN topic SET NOT NULL;
ALTER TABLE portal ALTER COLUMN avatar_hash SET NOT NULL;
ALTER TABLE portal ALTER COLUMN avatar_url SET NOT NULL;
ALTER TABLE portal ALTER COLUMN expiration_time SET NOT NULL;
ALTER TABLE portal ALTER COLUMN relay_user_id SET NOT NULL;

-- Add unique constraint to custom_mxid
UPDATE puppet SET custom_mxid=NULL WHERE custom_mxid='';
ALTER TABLE puppet ADD CONSTRAINT puppet_custom_mxid_unique UNIQUE(custom_mxid);
-- Remove unnecessary nullables in puppet
UPDATE puppet SET name='' WHERE name IS NULL;
UPDATE puppet SET avatar_hash='' WHERE avatar_hash IS NULL;
UPDATE puppet SET avatar_url='' WHERE avatar_url IS NULL;
UPDATE puppet SET access_token='' WHERE access_token IS NULL;
ALTER TABLE puppet ALTER COLUMN name SET NOT NULL;
ALTER TABLE puppet ALTER COLUMN avatar_hash SET NOT NULL;
ALTER TABLE puppet ALTER COLUMN avatar_url SET NOT NULL;
ALTER TABLE puppet ALTER COLUMN access_token SET NOT NULL;
ALTER TABLE puppet ALTER COLUMN name_quality DROP DEFAULT;

ALTER TABLE "user" ADD CONSTRAINT user_uuid_unique UNIQUE(uuid);
ALTER TABLE "user" RENAME COLUMN username TO phone;

-- Drop room_id from disappearing message primary key
ALTER TABLE disappearing_message DROP CONSTRAINT disappearing_message_pkey;
ALTER TABLE disappearing_message ADD PRIMARY KEY (mxid);
-- Remove unnecessary nullables in disappearing_message
ALTER TABLE disappearing_message ALTER COLUMN room_id SET NOT NULL;
UPDATE disappearing_message SET expiration_seconds=0 WHERE expiration_seconds IS NULL;
ALTER TABLE disappearing_message ALTER COLUMN expiration_seconds SET NOT NULL;
