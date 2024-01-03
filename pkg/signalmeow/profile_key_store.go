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

package signalmeow

import (
	"context"
	"database/sql"
	"errors"

	"github.com/google/uuid"

	"go.mau.fi/util/dbutil"

	"go.mau.fi/mautrix-signal/pkg/libsignalgo"
)

var _ ProfileKeyStore = (*SQLStore)(nil)

type ProfileKeyStore interface {
	// LoadProfileKey loads the profile key for the given address.
	// If the address is not found, nil is returned.
	LoadProfileKey(ctx context.Context, theirACI uuid.UUID) (*libsignalgo.ProfileKey, error)
	StoreProfileKey(ctx context.Context, theirACI uuid.UUID, key libsignalgo.ProfileKey) error
	MyProfileKey(ctx context.Context) (*libsignalgo.ProfileKey, error)
}

const (
	loadProfileKeyQuery  = `SELECT key FROM signalmeow_profile_keys WHERE our_aci_uuid=$1 AND their_aci_uuid=$2`
	storeProfileKeyQuery = `INSERT INTO signalmeow_profile_keys (our_aci_uuid, their_aci_uuid, key) VALUES ($1, $2, $3) ON CONFLICT (our_aci_uuid, their_aci_uuid) DO UPDATE SET key=excluded.key`
)

func scanProfileKey(row dbutil.Scannable) (*libsignalgo.ProfileKey, error) {
	var record []byte
	err := row.Scan(&record)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, nil
	} else if err != nil {
		return nil, err
	}
	profileKey := libsignalgo.ProfileKey(record)
	return &profileKey, err
}

func (s *SQLStore) LoadProfileKey(ctx context.Context, theirACI uuid.UUID) (*libsignalgo.ProfileKey, error) {
	return scanProfileKey(s.db.Conn(ctx).QueryRowContext(ctx, loadProfileKeyQuery, s.ACI, theirACI))
}

func (s *SQLStore) MyProfileKey(ctx context.Context) (*libsignalgo.ProfileKey, error) {
	return scanProfileKey(s.db.Conn(ctx).QueryRowContext(ctx, loadProfileKeyQuery, s.ACI, s.ACI))
}

func (s *SQLStore) StoreProfileKey(ctx context.Context, theirACI uuid.UUID, key libsignalgo.ProfileKey) error {
	_, err := s.db.Conn(ctx).ExecContext(ctx, storeProfileKeyQuery, s.ACI, theirACI, key.Slice())
	return err
}
