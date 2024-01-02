-- v18 (compatible with v17+): Add columns for personal filtering space info
ALTER TABLE "user" ADD COLUMN space_room TEXT;

DROP TABLE IF EXISTS user_portal;
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
