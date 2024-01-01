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
)

const (
	puppetBaseSelect = `
        SELECT uuid, number, name, name_quality, avatar_hash, avatar_url, name_set, avatar_set,
               contact_info_set, is_registered, custom_mxid, access_token
        FROM puppet
	`
	getPuppetBySignalIDQuery   = puppetBaseSelect + `WHERE uuid=$1`
	getPuppetByNumberQuery     = puppetBaseSelect + `WHERE number=$1`
	getPuppetByCustomMXIDQuery = puppetBaseSelect + `WHERE custom_mxid=$1`
	getPuppetsWithCustomMXID   = puppetBaseSelect + `WHERE custom_mxid<>''`
	updatePuppetQuery          = `
		UPDATE puppet SET
			number=$2, name=$3, name_quality=$4, avatar_hash=$5, avatar_url=$6,
			name_set=$7, avatar_set=$8, contact_info_set=$9, is_registered=$10,
			custom_mxid=$11, access_token=$12
		WHERE uuid=$1
	`
	insertPuppetQuery = `
		INSERT INTO puppet (
			uuid, number, name, name_quality, avatar_hash, avatar_url,
			name_set, avatar_set, contact_info_set, is_registered,
			custom_mxid, access_token
		)
		VALUES (
			$1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12
		)
	`
)

type PuppetQuery struct {
	*dbutil.QueryHelper[*Puppet]
}

type Puppet struct {
	qh *dbutil.QueryHelper[*Puppet]

	SignalID    uuid.UUID
	Number      string
	Name        string
	NameQuality int
	AvatarHash  string
	AvatarURL   id.ContentURI
	NameSet     bool
	AvatarSet   bool

	IsRegistered bool

	CustomMXID     id.UserID
	AccessToken    string
	ContactInfoSet bool
}

func newPuppet(qh *dbutil.QueryHelper[*Puppet]) *Puppet {
	return &Puppet{qh: qh}
}

func (pq *PuppetQuery) GetBySignalID(ctx context.Context, signalID uuid.UUID) (*Puppet, error) {
	return pq.QueryOne(ctx, getPuppetBySignalIDQuery, signalID)
}

func (pq *PuppetQuery) GetByNumber(ctx context.Context, number string) (*Puppet, error) {
	return pq.QueryOne(ctx, getPuppetByNumberQuery, number)
}

func (pq *PuppetQuery) GetByCustomMXID(ctx context.Context, mxid id.UserID) (*Puppet, error) {
	return pq.QueryOne(ctx, getPuppetByCustomMXIDQuery, mxid)
}

func (pq *PuppetQuery) GetAllWithCustomMXID(ctx context.Context) ([]*Puppet, error) {
	return pq.QueryMany(ctx, getPuppetsWithCustomMXID)
}

func (p *Puppet) Scan(row dbutil.Scannable) (*Puppet, error) {
	var number, customMXID sql.NullString
	err := row.Scan(
		&p.SignalID,
		&number,
		&p.Name,
		&p.NameQuality,
		&p.AvatarHash,
		&p.AvatarURL,
		&p.NameSet,
		&p.AvatarSet,
		&p.ContactInfoSet,
		&p.IsRegistered,
		&customMXID,
		&p.AccessToken,
	)
	if err != nil {
		return nil, nil
	}
	p.Number = number.String
	p.CustomMXID = id.UserID(customMXID.String)
	return p, nil
}

func (p *Puppet) sqlVariables() []any {
	return []any{
		p.SignalID,
		dbutil.StrPtr(p.Number),
		p.Name,
		p.NameQuality,
		p.AvatarHash,
		&p.AvatarURL,
		p.NameSet,
		p.AvatarSet,
		p.ContactInfoSet,
		p.IsRegistered,
		dbutil.StrPtr(p.CustomMXID),
		p.AccessToken,
	}
}

func (p *Puppet) Insert(ctx context.Context) error {
	return p.qh.Exec(ctx, insertPuppetQuery, p.sqlVariables()...)
}

func (p *Puppet) Update(ctx context.Context) error {
	return p.qh.Exec(ctx, updatePuppetQuery, p.sqlVariables()...)
}
