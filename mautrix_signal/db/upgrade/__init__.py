from mautrix.util.async_db import UpgradeTable

upgrade_table = UpgradeTable()

from . import (
    v00_latest_revision,
    v02_portal_avatar_info,
    v03_puppet_base_url,
    v04_phone_sender_identifier,
    v05_puppet_avatar_info,
    v06_portal_revision,
    v07_portal_relay_user,
    v08_disappearing_messages,
    v09_group_topic,
    v10_puppet_name_quality,
    v11_drop_number_support,
)
