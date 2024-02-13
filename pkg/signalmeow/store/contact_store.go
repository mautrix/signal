// mautrix-signal - A Matrix-signal puppeting bridge.
// Copyright (C) 2023 Scott Weber
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU Affero General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.
//
// This program is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
// GNU Affero General Public License for more details.
//
// You should have received a copy of the GNU Affero General Public License
// along with this program.  If not, see <https://www.gnu.org/licenses/>.

package store

import (
	"context"
	"database/sql"
	"errors"

	"github.com/google/uuid"
	"go.mau.fi/util/dbutil"

	"go.mau.fi/mautrix-signal/pkg/libsignalgo"
	"go.mau.fi/mautrix-signal/pkg/signalmeow/types"
)

type ContactStore interface {
	LoadContact(ctx context.Context, theirUUID uuid.UUID) (*types.Contact, error)
	LoadContactByE164(ctx context.Context, e164 string) (*types.Contact, error)
	LoadContactWithLatestOtherProfile(ctx context.Context, contact *types.Contact) (*types.Contact, error)
	StoreContact(ctx context.Context, contact types.Contact) error
	AllContacts(ctx context.Context) ([]*types.Contact, error)
	UpdatePhone(ctx context.Context, theirUUID uuid.UUID, newE164 string) error
}

var _ ContactStore = (*SQLStore)(nil)

const (
	getAllContactsQuery = `
		SELECT
			aci_uuid,
			e164_number,
			contact_name,
			contact_avatar_hash,
			profile_key,
			profile_name,
			profile_about,
			profile_about_emoji,
			profile_avatar_path,
			profile_avatar_hash,
			profile_fetch_ts
		FROM signalmeow_contacts
	`
	getAllContactsOfUserQuery = getAllContactsQuery + `WHERE our_aci_uuid = $1`
	getContactByUUIDQuery     = getAllContactsQuery + `WHERE our_aci_uuid = $1 AND aci_uuid = $2`
	getContactByPhoneQuery    = getAllContactsQuery + `WHERE our_aci_uuid = $1 AND e164_number = $2`

	getContactWithLatestOtherProfileQuery = getAllContactsQuery + `
		WHERE our_aci_uuid <> $1 AND aci_uuid = $2 AND LENGTH(COALESCE(profile_key, '')) > 0
		ORDER BY profile_fetch_ts LIMIT 1
	`

	upsertContactQuery = `
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
			profile_avatar_path,
			profile_avatar_hash,
			profile_fetch_ts
		)
		VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12)
		ON CONFLICT (our_aci_uuid, aci_uuid) DO UPDATE SET
			e164_number = excluded.e164_number,
			contact_name = excluded.contact_name,
			contact_avatar_hash = excluded.contact_avatar_hash,
			profile_key = excluded.profile_key,
			profile_name = excluded.profile_name,
			profile_about = excluded.profile_about,
			profile_about_emoji = excluded.profile_about_emoji,
			profile_avatar_path = excluded.profile_avatar_path,
			profile_avatar_hash = excluded.profile_avatar_hash,
			profile_fetch_ts = excluded.profile_fetch_ts
	`
	upsertContactPhoneQuery = `
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
			profile_avatar_path,
			profile_avatar_hash,
			profile_fetch_ts
		)
		VALUES ($1, $2, $3, '', '', NULL, '', '', '', '', '', 0)
		ON CONFLICT (our_aci_uuid, aci_uuid) DO UPDATE
			SET e164_number = excluded.e164_number
	`
)

func scanContact(row dbutil.Scannable) (*types.Contact, error) {
	var contact types.Contact
	var profileKey []byte
	err := row.Scan(
		&contact.UUID,
		&contact.E164,
		&contact.ContactName,
		&contact.ContactAvatar.Hash,
		&profileKey,
		&contact.ProfileName,
		&contact.ProfileAbout,
		&contact.ProfileAboutEmoji,
		&contact.ProfileAvatarPath,
		&contact.ProfileAvatarHash,
		&contact.ProfileFetchTs,
	)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, nil
	} else if err != nil {
		return nil, err
	}
	if len(profileKey) != 0 {
		profileKeyConverted := libsignalgo.ProfileKey(profileKey)
		contact.ProfileKey = &profileKeyConverted
	}
	return &contact, err
}

func (s *SQLStore) LoadContact(ctx context.Context, theirUUID uuid.UUID) (*types.Contact, error) {
	return scanContact(s.db.QueryRow(ctx, getContactByUUIDQuery, s.ACI, theirUUID))
}

func (s *SQLStore) LoadContactByE164(ctx context.Context, e164 string) (*types.Contact, error) {
	return scanContact(s.db.QueryRow(ctx, getContactByPhoneQuery, s.ACI, e164))
}

func (s *SQLStore) LoadContactWithLatestOtherProfile(ctx context.Context, contact *types.Contact) (*types.Contact, error) {
	return scanContact(s.db.QueryRow(ctx, getContactWithLatestOtherProfileQuery, s.ACI, contact.UUID))
}

func (s *SQLStore) AllContacts(ctx context.Context) ([]*types.Contact, error) {
	rows, err := s.db.Query(ctx, getAllContactsOfUserQuery, s.ACI)
	if err != nil {
		return nil, err
	}
	return dbutil.NewRowIter(rows, scanContact).AsList()
}

func (s *SQLStore) StoreContact(ctx context.Context, contact types.Contact) error {
	_, err := s.db.Exec(
		ctx,
		upsertContactQuery,
		s.ACI,
		contact.UUID,
		contact.E164,
		contact.ContactName,
		contact.ContactAvatar.Hash,
		contact.ProfileKey.Slice(),
		contact.ProfileName,
		contact.ProfileAbout,
		contact.ProfileAboutEmoji,
		contact.ProfileAvatarPath,
		contact.ProfileAvatarHash,
		contact.ProfileFetchTs,
	)
	return err
}

func (s *SQLStore) UpdatePhone(ctx context.Context, theirUUID uuid.UUID, newE164 string) error {
	_, err := s.db.Exec(
		ctx, upsertContactPhoneQuery, s.ACI, theirUUID, newE164,
	)
	return err
}
