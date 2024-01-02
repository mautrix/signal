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

	"go.mau.fi/mautrix-signal/pkg/signalmeow/types"
)

var _ GroupStore = (*SQLStore)(nil)

type dbGroup struct {
	OurAciUuid      string
	GroupIdentifier types.GroupIdentifier
	GroupMasterKey  SerializedGroupMasterKey
}

type GroupStore interface {
	MasterKeyFromGroupIdentifier(groupIdentifier types.GroupIdentifier, ctx context.Context) (SerializedGroupMasterKey, error)
	StoreMasterKey(groupIdentifier types.GroupIdentifier, key SerializedGroupMasterKey, ctx context.Context) error
}

func scanGroup(row scannable) (*dbGroup, error) {
	var g dbGroup
	err := row.Scan(&g.OurAciUuid, &g.GroupIdentifier, &g.GroupMasterKey)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, nil
	} else if err != nil {
		return nil, err
	}
	return &g, nil
}

func (s *SQLStore) MasterKeyFromGroupIdentifier(groupIdentifier types.GroupIdentifier, ctx context.Context) (SerializedGroupMasterKey, error) {
	loadGroupQuery := `SELECT our_aci_uuid, group_identifier, master_key FROM signalmeow_groups WHERE our_aci_uuid=$1 AND group_identifier=$2`
	g, err := scanGroup(s.db.QueryRow(loadGroupQuery, s.AciUuid, groupIdentifier))
	if err != nil {
		return "", err
	}
	if g == nil {
		return "", nil
	}
	return g.GroupMasterKey, nil
}

func (s *SQLStore) StoreMasterKey(groupIdentifier types.GroupIdentifier, key SerializedGroupMasterKey, ctx context.Context) error {
	// Insert, or update if already exists
	storeMasterKeyQuery := `
		INSERT INTO signalmeow_groups (our_aci_uuid, group_identifier, master_key)
		VALUES ($1, $2, $3)
		ON CONFLICT (our_aci_uuid, group_identifier) DO UPDATE SET
		master_key = excluded.master_key;
	`

	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		tx.Rollback()
		return err
	}
	_, err = tx.Exec(storeMasterKeyQuery, s.AciUuid, groupIdentifier, key)
	if err != nil {
		tx.Rollback()
		return err
	}
	err = tx.Commit()
	return err
}
