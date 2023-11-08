package signalmeow

import (
	"context"
	"database/sql"
	"errors"
)

var _ ContactStore = (*SQLStore)(nil)

type ContactStore interface {
	LoadContact(ctx context.Context, theirUuid string) (*Contact, error)
	LoadContactByE164(ctx context.Context, e164 string) (*Contact, error)
	StoreContact(ctx context.Context, contact Contact) error
	AllContacts(ctx context.Context) ([]Contact, error)
}

func scanContact(row scannable) (*Contact, error) {
	var contact Contact
	err := row.Scan(
		&contact.UUID,
		&contact.E164,
		&contact.ContactName,
		&contact.ContactAvatarHash,
		&contact.ProfileKey,
		&contact.ProfileName,
		&contact.ProfileAbout,
		&contact.ProfileAboutEmoji,
		&contact.ProfileAvatarHash,
	)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, nil
	} else if err != nil {
		return nil, err
	}
	return &contact, err
}

var commonSelectQuery = `
	SELECT
	  aci_uuid,
	  e164_number,
	  contact_name,
	  contact_avatar_hash,
	  profile_key,
	  profile_name,
	  profile_about,
	  profile_about_emoji,
	  profile_avatar_hash
	FROM signalmeow_contacts
	`

func (s *SQLStore) LoadContact(ctx context.Context, theirUuid string) (*Contact, error) {
	contactQuery := commonSelectQuery +
		`WHERE our_aci_uuid = $1 AND aci_uuid = $2`
	return scanContact(s.db.QueryRow(contactQuery, s.AciUuid, theirUuid))
}

func (s *SQLStore) LoadContactByE164(ctx context.Context, e164 string) (*Contact, error) {
	contactQuery := commonSelectQuery +
		`WHERE our_aci_uuid = $1 AND e164_number = $2`
	return scanContact(s.db.QueryRow(contactQuery, s.AciUuid, e164))
}

func (s *SQLStore) AllContacts(ctx context.Context) ([]Contact, error) {
	contactQuery := commonSelectQuery +
		`WHERE our_aci_uuid = $1`
	rows, err := s.db.Query(contactQuery, s.AciUuid)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var contacts []Contact
	for rows.Next() {
		contact, err := scanContact(rows)
		if err != nil {
			return nil, err
		}
		contacts = append(contacts, *contact)
	}
	return contacts, nil
}

func (s *SQLStore) StoreContact(ctx context.Context, contact Contact) error {
	storeContactQuery := `
		INSERT INTO signalmeow_contacts (
			our_aci_uuid,
			aci_uuid,
			e164_number,
			contact_name,
			contact_avatar_hash,
			profile_key,
			profile_name,
			profile_about,
			profile_about_emoji,
			profile_avatar_hash
		)
		VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10)
		ON CONFLICT (our_aci_uuid, aci_uuid) DO UPDATE SET
			e164_number = excluded.e164_number,
			contact_name = excluded.contact_name,
			contact_avatar_hash = excluded.contact_avatar_hash,
			profile_key = excluded.profile_key,
			profile_name = excluded.profile_name,
			profile_about = excluded.profile_about,
			profile_about_emoji = excluded.profile_about_emoji,
			profile_avatar_hash = excluded.profile_avatar_hash
	`
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		tx.Rollback()
		return err
	}
	_, err = tx.Exec(
		storeContactQuery,
		s.AciUuid,
		contact.UUID,
		contact.E164,
		contact.ContactName,
		contact.ContactAvatarHash,
		contact.ProfileKey,
		contact.ProfileName,
		contact.ProfileAbout,
		contact.ProfileAboutEmoji,
		contact.ProfileAvatarHash,
	)
	if err != nil {
		tx.Rollback()
		return err
	}
	err = tx.Commit()
	return err
}
