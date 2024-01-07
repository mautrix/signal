// mautrix-signal - A Matrix-signal puppeting bridge.
// Copyright (C) 2023 Scott Weber, Tulir Asokan
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

package database

import (
	"context"
	"database/sql"

	"github.com/google/uuid"
	"go.mau.fi/util/dbutil"
	"maunium.net/go/mautrix/id"

	"go.mau.fi/mautrix-signal/pkg/signalmeow/types"
)

const (
	portalBaseSelect = `
		SELECT chat_id, receiver, mxid, name, topic, avatar_path, avatar_hash, avatar_url,
		       name_set, avatar_set, topic_set, revision, encrypted, relay_user_id, expiration_time
		FROM portal
	`
	getPortalByMXIDQuery       = portalBaseSelect + `WHERE mxid=$1`
	getPortalByChatIDQuery     = portalBaseSelect + `WHERE chat_id=$1 AND receiver=$2`
	getPortalsByReceiver       = portalBaseSelect + `WHERE receiver=$1`
	getPortalsByUser           = portalBaseSelect + `WHERE chat_id=$1`
	getAllPortalsWithMXIDQuery = portalBaseSelect + `WHERE mxid IS NOT NULL`
	getChatsNotInSpaceQuery    = `
		SELECT chat_id FROM portal
		    LEFT JOIN user_portal ON portal.chat_id=user_portal.portal_chat_id AND portal.receiver=user_portal.portal_receiver
		WHERE mxid<>'' AND receiver=$1 AND (user_portal.in_space=false OR user_portal.in_space IS NULL)
	`
	insertPortalQuery = `
		INSERT INTO portal (
			chat_id, receiver, mxid, name, topic, avatar_path, avatar_hash, avatar_url,
			name_set, avatar_set, topic_set, revision, encrypted, relay_user_id, expiration_time
		) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, $15)
	`
	updatePortalQuery = `
		UPDATE portal SET
			mxid=$3, name=$4, topic=$5, avatar_path=$6, avatar_hash=$7, avatar_url=$8,
			name_set=$9, avatar_set=$10, topic_set=$11, revision=$12, encrypted=$13, relay_user_id=$14, expiration_time=$15
		WHERE chat_id=$1 AND receiver=$2
	`
	deletePortalQuery = `DELETE FROM portal WHERE chat_id=$1 AND receiver=$2`
)

type PortalQuery struct {
	*dbutil.QueryHelper[*Portal]
}

type PortalKey struct {
	ChatID   string
	Receiver uuid.UUID
}

func (pk *PortalKey) UserID() uuid.UUID {
	parsed, _ := uuid.Parse(pk.ChatID)
	return parsed
}

func (pk *PortalKey) GroupID() types.GroupIdentifier {
	if len(pk.ChatID) == 44 {
		return types.GroupIdentifier(pk.ChatID)
	}
	return ""
}

func NewPortalKey(chatID string, receiver uuid.UUID) PortalKey {
	return PortalKey{
		ChatID:   chatID,
		Receiver: receiver,
	}
}

type Portal struct {
	qh *dbutil.QueryHelper[*Portal]

	PortalKey
	MXID           id.RoomID
	Name           string
	Topic          string
	AvatarPath     string
	AvatarHash     string
	AvatarURL      id.ContentURI
	NameSet        bool
	AvatarSet      bool
	TopicSet       bool
	Revision       uint32
	Encrypted      bool
	RelayUserID    id.UserID
	ExpirationTime uint32
}

func newPortal(qh *dbutil.QueryHelper[*Portal]) *Portal {
	return &Portal{qh: qh}
}

func (pq *PortalQuery) GetByMXID(ctx context.Context, mxid id.RoomID) (*Portal, error) {
	return pq.QueryOne(ctx, getPortalByMXIDQuery, mxid)
}

func (pq *PortalQuery) GetByChatID(ctx context.Context, pk PortalKey) (*Portal, error) {
	return pq.QueryOne(ctx, getPortalByChatIDQuery, pk.ChatID, pk.Receiver)
}

func (pq *PortalQuery) FindPrivateChatsWith(ctx context.Context, userID uuid.UUID) ([]*Portal, error) {
	return pq.QueryMany(ctx, getPortalsByUser, userID.String())
}

func (pq *PortalQuery) FindPrivateChatsOf(ctx context.Context, receiver uuid.UUID) ([]*Portal, error) {
	return pq.QueryMany(ctx, getPortalsByReceiver, receiver)
}

func (pq *PortalQuery) GetAllWithMXID(ctx context.Context) ([]*Portal, error) {
	return pq.QueryMany(ctx, getAllPortalsWithMXIDQuery)
}

func (pq *PortalQuery) FindPrivateChatsNotInSpace(ctx context.Context, receiver uuid.UUID) ([]PortalKey, error) {
	rows, err := pq.GetDB().Query(ctx, getChatsNotInSpaceQuery, receiver)
	if err != nil {
		return nil, err
	}
	return dbutil.NewRowIter(rows, func(rows dbutil.Scannable) (key PortalKey, err error) {
		err = rows.Scan(&key.ChatID)
		key.Receiver = receiver
		return
	}).AsList()
}

func (p *Portal) Scan(row dbutil.Scannable) (*Portal, error) {
	var mxid sql.NullString
	err := row.Scan(
		&p.ChatID,
		&p.Receiver,
		&mxid,
		&p.Name,
		&p.Topic,
		&p.AvatarPath,
		&p.AvatarHash,
		&p.AvatarURL,
		&p.NameSet,
		&p.AvatarSet,
		&p.TopicSet,
		&p.Revision,
		&p.Encrypted,
		&p.RelayUserID,
		&p.ExpirationTime,
	)
	if err != nil {
		return nil, err
	}
	p.MXID = id.RoomID(mxid.String)
	return p, nil
}

func (p *Portal) sqlVariables() []any {
	return []any{
		p.ChatID,
		p.Receiver,
		dbutil.StrPtr(p.MXID),
		p.Name,
		p.Topic,
		p.AvatarPath,
		p.AvatarHash,
		&p.AvatarURL,
		p.NameSet,
		p.AvatarSet,
		p.TopicSet,
		p.Revision,
		p.Encrypted,
		p.RelayUserID,
		p.ExpirationTime,
	}
}

func (p *Portal) Insert(ctx context.Context) error {
	return p.qh.Exec(ctx, insertPortalQuery, p.sqlVariables()...)
}

func (p *Portal) Update(ctx context.Context) error {
	return p.qh.Exec(ctx, updatePortalQuery, p.sqlVariables()...)
}

func (p *Portal) Delete(ctx context.Context) error {
	return p.qh.Exec(ctx, deletePortalQuery, p.ChatID, p.Receiver)
}
