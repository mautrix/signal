-- v28 (compatible with v13+): Persist view-once opened state
CREATE TABLE signalmeow_view_once_open (
    account_id TEXT   NOT NULL,
    sender     uuid   NOT NULL,
    timestamp  BIGINT NOT NULL,
    handled    BOOLEAN NOT NULL DEFAULT false,
    sync_pending BOOLEAN NOT NULL DEFAULT false,
    PRIMARY KEY (account_id, sender, timestamp),
    FOREIGN KEY (account_id) REFERENCES signalmeow_device (aci_uuid) ON DELETE CASCADE ON UPDATE CASCADE
);
