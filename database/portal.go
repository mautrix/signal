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
	"maunium.net/go/mautrix/id"

	"go.mau.fi/util/dbutil"

	"go.mau.fi/mautrix-signal/pkg/signalmeow"
)

const (
	portalBaseSelect = `
		SELECT chat_id, receiver, mxid, name, topic, avatar_hash, avatar_url, name_set, avatar_set,
		       revision, encrypted, relay_user_id, expiration_time
		FROM portal
	`
	getPortalByMXIDQuery       = portalBaseSelect + `WHERE mxid=$1`
	getPortalByChatIDQuery     = portalBaseSelect + `WHERE chat_id=$1 AND receiver=$2`
	getPortalsByReceiver       = portalBaseSelect + `WHERE receiver=$1`
	getAllPortalsWithMXIDQuery = portalBaseSelect + `WHERE mxid IS NOT NULL`
	insertPortalQuery          = `
		INSERT INTO portal (
			chat_id, receiver, mxid, name, topic, avatar_hash, avatar_url, name_set, avatar_set,
			revision, encrypted, relay_user_id, expiration_time
		) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13)
	`
	updatePortalQuery = `
		UPDATE portal SET
			mxid=$3, name=$4, topic=$5, avatar_hash=$6, avatar_url=$7, name_set=$8,
			avatar_set=$9, revision=$10, encrypted=$11, relay_user_id=$12,
			expiration_time=$13
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

func (pk *PortalKey) GroupID() signalmeow.GroupIdentifier {
	if len(pk.ChatID) == 44 {
		return signalmeow.GroupIdentifier(pk.ChatID)
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
	AvatarHash     string
	AvatarURL      id.ContentURI
	NameSet        bool
	AvatarSet      bool
	Revision       int
	Encrypted      bool
	RelayUserID    id.UserID
	ExpirationTime int
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

func (pq *PortalQuery) FindPrivateChatsOf(ctx context.Context, receiver uuid.UUID) ([]*Portal, error) {
	return pq.QueryMany(ctx, getPortalsByReceiver, receiver)
}

func (pq *PortalQuery) GetAllWithMXID(ctx context.Context) ([]*Portal, error) {
	return pq.QueryMany(ctx, getAllPortalsWithMXIDQuery)
}

func (p *Portal) Scan(row dbutil.Scannable) (*Portal, error) {
	var mxid sql.NullString
	err := row.Scan(
		&p.ChatID,
		&p.Receiver,
		&mxid,
		&p.Name,
		&p.Topic,
		&p.AvatarHash,
		&p.AvatarURL,
		&p.NameSet,
		&p.AvatarSet,
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
		p.AvatarHash,
		p.AvatarURL,
		p.NameSet,
		p.AvatarSet,
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
