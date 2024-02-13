-- v7 (compatible with v5+): Save profile fetch timestamp
ALTER TABLE signalmeow_contacts ADD COLUMN profile_fetch_ts BIGINT NOT NULL DEFAULT 0;
