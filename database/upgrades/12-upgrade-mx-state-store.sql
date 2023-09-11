-- v12: Switch mx_room_state from Python to Go format
ALTER TABLE mx_room_state DROP COLUMN is_encrypted;
ALTER TABLE mx_room_state DROP COLUMN has_full_member_list;

-- only: postgres for next 2 lines
ALTER TABLE mx_room_state ALTER COLUMN power_levels TYPE jsonb;
ALTER TABLE mx_room_state ALTER COLUMN encryption TYPE jsonb;

UPDATE mx_user_profile SET displayname='' WHERE displayname IS NULL;
UPDATE mx_user_profile SET avatar_url='' WHERE avatar_url IS NULL;

CREATE TABLE mx_registrations (
	user_id TEXT PRIMARY KEY
);