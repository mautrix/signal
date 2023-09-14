package signalmeow

import (
	"context"
	"database/sql"
	"errors"
)

var _ GroupStore = (*SQLStore)(nil)

type dbGroup struct {
	OurAciUuid      string
	GroupIdentifier GroupIdentifier
	GroupMasterKey  SerializedGroupMasterKey
}

type GroupStore interface {
	MasterKeyFromGroupIdentifier(groupIdentifier GroupIdentifier, ctx context.Context) (SerializedGroupMasterKey, error)
	StoreMasterKey(groupIdentifier GroupIdentifier, key SerializedGroupMasterKey, ctx context.Context) error
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

func (s *SQLStore) MasterKeyFromGroupIdentifier(groupIdentifier GroupIdentifier, ctx context.Context) (SerializedGroupMasterKey, error) {
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

func (s *SQLStore) StoreMasterKey(groupIdentifier GroupIdentifier, key SerializedGroupMasterKey, ctx context.Context) error {
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
