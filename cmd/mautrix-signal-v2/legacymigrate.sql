INSERT INTO "user" (bridge_id, mxid, management_room, access_token)
SELECT '', mxid, management_room, NULL
FROM user_old;

INSERT INTO user_login (bridge_id, user_mxid, id, remote_name, space_room, metadata)
SELECT
    '',
    mxid,
    cast(uuid AS TEXT),
    phone, -- remote_name
    space_room,
    CAST(
        '{"phone":"' || phone || '"}'
        -- only: postgres
        AS jsonb
        -- only: sqlite (line commented)
--      AS text
    )
FROM user_old WHERE uuid IS NOT NULL AND phone IS NOT NULL;

INSERT INTO portal (
    bridge_id, id, receiver, mxid, parent_id, parent_receiver, relay_bridge_id, relay_login_id,
    name, topic, avatar_id, avatar_hash, avatar_mxc,
    name_set, avatar_set, topic_set, in_space,
    room_type, disappear_type, disappear_timer, metadata
)
SELECT
    '', -- bridge_id
    chat_id, -- id
    CASE
        WHEN receiver='00000000-0000-0000-0000-000000000000' THEN ''
        ELSE CAST(receiver AS TEXT)
    END, -- receiver
    mxid,
    NULL, -- parent_id
    '', -- parent_receiver
    CASE WHEN portal_old.relay_user_id<>'' THEN '' END, -- relay_bridge_id
    CASE WHEN portal_old.relay_user_id<>'' THEN portal_old.relay_user_id END, -- relay_login_id
    name,
    topic,
    CASE
        WHEN avatar_path='notetoself' THEN avatar_url
        WHEN avatar_path<>'' THEN ('path:' || avatar_path)
        WHEN avatar_hash<>'' THEN ('hash:' || avatar_hash)
        ELSE ''
    END, -- avatar_id
    avatar_hash, -- avatar_hash
    avatar_url, -- avatar_mxc
    name_set,
    avatar_set,
    topic_set,
    false, -- in_space
    CASE WHEN LENGTH(chat_id)=44 THEN '' ELSE 'dm' END, -- room_type
    CASE WHEN expiration_time<>0 THEN 'after_read' END,
    CASE WHEN expiration_time<>0 THEN expiration_time * 1000000000 END,
    CAST(
        '{"revision":' || revision || '}'
        -- only: postgres
        AS jsonb
        -- only: sqlite (line commented)
--      AS text
    ) -- metadata
FROM portal_old;

INSERT INTO ghost (
    bridge_id, id, name, avatar_id, avatar_hash, avatar_mxc,
    name_set, avatar_set, contact_info_set,
    is_bot, identifiers, metadata
)
SELECT
    '', -- bridge_id
    cast(uuid AS TEXT), -- id
    name,
    CASE
        WHEN avatar_path<>'' THEN ('path:' || avatar_path)
        WHEN avatar_hash<>'' THEN ('hash:' || avatar_hash)
        ELSE ''
    END, -- avatar_id
    avatar_hash, -- avatar_hash
    avatar_url, -- avatar_mxc
    name_set,
    avatar_set,
    contact_info_set,
    false, -- is_bot
    '[]', -- identifiers
    CAST(
        CASE
             WHEN profile_fetched_at IS NOT NULL THEN ('{"profile_fetched_at":' || profile_fetched_at || '}')
             ELSE '{}'
        END
        -- only: postgres
        AS jsonb
        -- only: sqlite (line commented)
--      AS text
    ) -- metadata
FROM puppet_old;

INSERT INTO message (
    bridge_id, id, part_id, mxid, room_id, room_receiver,
    sender_id, sender_mxid, timestamp, edit_count, metadata
)
SELECT
    '', -- bridge_id
    cast(sender AS TEXT) || '|' || timestamp, -- id
    CASE WHEN part_index=0 THEN '' ELSE CAST(part_index AS TEXT) END, -- part_id
    mxid,
    signal_chat_id, -- room_id
    CASE
        WHEN signal_receiver='00000000-0000-0000-0000-000000000000' THEN ''
        ELSE cast(signal_receiver AS TEXT)
    END, -- room_receiver
    cast(sender AS TEXT), -- sender_id
    '', -- sender_mxid
    timestamp * 1000000,
    0, -- edit_count
    '{}' -- metadata
FROM message_old;

INSERT INTO disappearing_message (
    bridge_id, mx_room, mxid, type, timer, disappear_at
)
SELECT
    '', -- bridge_id
    room_id, -- mx_room
    mxid,
    'after_read', -- type
    expiration_seconds * 1000000000, -- timer
    CASE WHEN expiration_ts IS NOT NULL THEN expiration_ts * 1000000000 END -- disappear_at
FROM disappearing_message_old;

INSERT INTO reaction (
    bridge_id, message_id, message_part_id, sender_id, emoji_id, emoji,
    room_id, room_receiver, mxid, timestamp, metadata
)
SELECT
    '', -- bridge_id
    cast(msg_author AS TEXT) || '|' || msg_timestamp, -- message_id
    '', -- message_part_id
    cast(author AS TEXT), -- sender_id
    '', -- emoji_id
    emoji,
    signal_chat_id, -- room_id
    CASE
        WHEN signal_receiver='00000000-0000-0000-0000-000000000000' THEN ''
        ELSE cast(signal_receiver AS TEXT)
    END, -- room_receiver
    mxid,
    msg_timestamp * 1000000, -- timestamp (actual reaction timestamp not available)
    '{}' -- metadata
FROM reaction_old;

INSERT INTO user_portal (
    bridge_id, user_mxid, login_id, portal_id, portal_receiver, in_space, preferred, last_read
)
SELECT
    '', -- bridge_id
    user_mxid,
    cast(user_old.uuid AS TEXT), -- login_id
    portal_chat_id, -- portal_id
    CASE
        WHEN portal_receiver='00000000-0000-0000-0000-000000000000' THEN ''
        ELSE cast(portal_receiver AS TEXT)
    END, -- portal_receiver
    in_space,
    false, -- preferred
    CASE WHEN last_read_ts = 0 THEN NULL ELSE last_read_ts * 1000000 END -- last_read
FROM user_portal_old
LEFT JOIN user_old ON user_old.mxid = user_portal_old.user_mxid;

DROP TABLE disappearing_message_old;
DROP TABLE reaction_old;
DROP TABLE user_portal_old;
DROP TABLE message_old;
DROP TABLE puppet_old;
DROP TABLE portal_old;
DROP TABLE user_old;
