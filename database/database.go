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

package database

import (
	_ "embed"

	_ "github.com/lib/pq"
	_ "github.com/mattn/go-sqlite3"
	"go.mau.fi/util/dbutil"
	"maunium.net/go/maulogger/v2"

	"go.mau.fi/mautrix-signal/database/upgrades"
)

type Database struct {
	*dbutil.Database

	User                *UserQuery
	Portal              *PortalQuery
	Puppet              *PuppetQuery
	Message             *MessageQuery
	Reaction            *ReactionQuery
	DisappearingMessage *DisappearingMessageQuery
}

func New(baseDB *dbutil.Database, log maulogger.Logger) *Database {
	db := &Database{Database: baseDB}
	db.UpgradeTable = upgrades.Table
	db.User = &UserQuery{
		db:  db,
		log: log.Sub("User"),
	}
	db.Portal = &PortalQuery{
		db:  db,
		log: log.Sub("Portal"),
	}
	db.Puppet = &PuppetQuery{
		db:  db,
		log: log.Sub("Puppet"),
	}
	db.Message = &MessageQuery{
		db:  db,
		log: log.Sub("Message"),
	}
	db.Reaction = &ReactionQuery{
		db:  db,
		log: log.Sub("Reaction"),
	}
	db.DisappearingMessage = &DisappearingMessageQuery{
		db:  db,
		log: log.Sub("DisappearingMessage"),
	}
	return db
}

func strPtr(val string) *string {
	if val == "" {
		return nil
	}
	return &val
}
