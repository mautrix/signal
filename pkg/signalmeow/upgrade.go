package signalmeow

import (
	"database/sql"
)

type upgradeFunc func(*sql.Tx, *StoreContainer) error

// Upgrades is a list of functions that will upgrade a database to the latest version.
//
// This may be of use if you want to manage the database fully manually, but in most cases you
// should just call StoreContainer.Upgrade to let the library handle everything.
var Upgrades = [...]upgradeFunc{upgradeV1, upgradeV2, upgradeV3, upgradeV4}

func (c *StoreContainer) getVersion() (int, error) {
	_, err := c.db.Exec("CREATE TABLE IF NOT EXISTS signalmeow_version (version INTEGER)")
	if err != nil {
		return -1, err
	}

	version := 0
	row := c.db.QueryRow("SELECT version FROM signalmeow_version LIMIT 1")
	if row != nil {
		_ = row.Scan(&version)
	}
	return version, nil
}

func (c *StoreContainer) setVersion(tx *sql.Tx, version int) error {
	_, err := tx.Exec("DELETE FROM signalmeow_version")
	if err != nil {
		return err
	}
	_, err = tx.Exec("INSERT INTO signalmeow_version (version) VALUES ($1)", version)
	return err
}

// Upgrade upgrades the database from the current to the latest version available.
func (c *StoreContainer) Upgrade() error {
	version, err := c.getVersion()
	if err != nil {
		return err
	}

	for ; version < len(Upgrades); version++ {
		var tx *sql.Tx
		tx, err = c.db.Begin()
		if err != nil {
			return err
		}

		migrateFunc := Upgrades[version]
		//c.log.Infof("Upgrading database to v%d", version+1)
		err = migrateFunc(tx, c)
		if err != nil {
			_ = tx.Rollback()
			return err
		}

		if err = c.setVersion(tx, version+1); err != nil {
			_ = tx.Rollback()
			return err
		}

		if err = tx.Commit(); err != nil {
			return err
		}
	}

	return nil
}

func upgradeV1(tx *sql.Tx, _ *StoreContainer) error {
	_, err := tx.Exec(`CREATE TABLE signalmeow_device (
		aci_uuid                TEXT PRIMARY KEY,

		aci_identity_key_pair   bytea NOT NULL,
		registration_id         INTEGER NOT NULL CHECK ( registration_id >= 0 AND registration_id < 4294967296 ),

		pni_uuid                TEXT NOT NULL,
		pni_identity_key_pair   bytea NOT NULL,
		pni_registration_id     INTEGER NOT NULL CHECK ( pni_registration_id >= 0 AND pni_registration_id < 4294967296 ),

		device_id   INTEGER NOT NULL,
		number      TEXT NOT NULL DEFAULT '',
		password    TEXT NOT NULL DEFAULT ''
	)`)
	if err != nil {
		return err
	}
	_, err = tx.Exec(`CREATE TABLE signalmeow_pre_keys (
		aci_uuid	TEXT NOT NULL,
		key_id		INTEGER NOT NULL,
		uuid_kind	TEXT NOT NULL,
		is_signed   BOOLEAN NOT NULL,
		key_pair	bytea   NOT NULL,
		uploaded	BOOLEAN NOT NULL,

		PRIMARY KEY (aci_uuid, uuid_kind, is_signed, key_id),
		FOREIGN KEY (aci_uuid) REFERENCES signalmeow_device(aci_uuid) ON DELETE CASCADE ON UPDATE CASCADE
	)`)
	if err != nil {
		return err
	}
	_, err = tx.Exec(`CREATE TABLE signalmeow_identity_keys (
		our_aci_uuid	TEXT	NOT NULL,
		their_aci_uuid	TEXT	NOT NULL,
		their_device_id	INTEGER	NOT NULL,
		key				bytea   NOT NULL,
		trust_level		TEXT	NOT NULL,

		PRIMARY KEY (our_aci_uuid, their_aci_uuid, their_device_id),
		FOREIGN KEY (our_aci_uuid) REFERENCES signalmeow_device(aci_uuid) ON DELETE CASCADE ON UPDATE CASCADE
	)`)
	if err != nil {
		return err
	}
	_, err = tx.Exec(`CREATE TABLE signalmeow_sessions (
		our_aci_uuid	TEXT	NOT NULL,
		their_aci_uuid	TEXT	NOT NULL,
		their_device_id	INTEGER	NOT NULL,
		record			bytea   NOT NULL,

		PRIMARY KEY (our_aci_uuid, their_aci_uuid, their_device_id),
		FOREIGN KEY (our_aci_uuid) REFERENCES signalmeow_device(aci_uuid) ON DELETE CASCADE ON UPDATE CASCADE
	)`)
	if err != nil {
		return err
	}
	_, err = tx.Exec(`
		CREATE TABLE signalmeow_profile_keys (
		  our_aci_uuid		TEXT	NOT NULL,
		  their_aci_uuid	TEXT	NOT NULL,
		  key				bytea   NOT NULL,

		  PRIMARY KEY (our_aci_uuid, their_aci_uuid),
		  FOREIGN KEY (our_aci_uuid) REFERENCES signalmeow_device(aci_uuid) ON DELETE CASCADE ON UPDATE CASCADE
	    )
	`)
	if err != nil {
		return err
	}
	_, err = tx.Exec(`CREATE TABLE signalmeow_sender_keys (
		our_aci_uuid		TEXT	NOT NULL,
		sender_uuid			TEXT	NOT NULL,
		sender_device_id	INTEGER	NOT NULL,
		distribution_id		TEXT	NOT NULL,
		key_record			bytea   NOT NULL,

		PRIMARY KEY (our_aci_uuid, sender_uuid, sender_device_id, distribution_id),
		FOREIGN KEY (our_aci_uuid) REFERENCES signalmeow_device(aci_uuid) ON DELETE CASCADE ON UPDATE CASCADE
	)`)
	if err != nil {
		return err
	}
	return nil
}

func upgradeV2(tx *sql.Tx, _ *StoreContainer) error {
	_, err := tx.Exec(`CREATE TABLE signalmeow_groups (
		our_aci_uuid        TEXT    NOT NULL,
		group_identifier    TEXT    NOT NULL,
		master_key          TEXT    NOT NULL,

		PRIMARY KEY (our_aci_uuid, group_identifier)
	)`)
	if err != nil {
		return err
	}
	return nil
}

func upgradeV3(tx *sql.Tx, _ *StoreContainer) error {
	_, err := tx.Exec(`
		CREATE TABLE signalmeow_contacts (
			our_aci_uuid        TEXT    NOT NULL,
			aci_uuid            TEXT    NOT NULL,
			e164_number         TEXT,
			contact_name        TEXT,
			contact_avatar_hash TEXT,
			profile_key         TEXT,
			profile_name        TEXT,
			profile_about       TEXT,
			profile_about_emoji TEXT,
			profile_avatar_hash TEXT,
		PRIMARY KEY (our_aci_uuid, aci_uuid),
		FOREIGN KEY (our_aci_uuid) REFERENCES signalmeow_device(aci_uuid) ON DELETE CASCADE ON UPDATE CASCADE
	)`)
	if err != nil {
		return err
	}
	return nil
}

func upgradeV4(tx *sql.Tx, _ *StoreContainer) error {
	_, err := tx.Exec(`
		ALTER TABLE signalmeow_contacts
		ALTER COLUMN profile_key TYPE bytea USING profile_key::bytea
	`)
	if err != nil {
		return err
	}
	_, err = tx.Exec(`
		UPDATE signalmeow_contacts
		SET profile_key=key
		FROM signalmeow_profile_keys
		WHERE signalmeow_contacts.aci_uuid=signalmeow_profile_keys.their_aci_uuid
	`)
	if err != nil {
		return err
	}
	return nil
}
