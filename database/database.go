package database

import (
	_ "embed"

	_ "github.com/lib/pq"
	_ "github.com/mattn/go-sqlite3"
	"maunium.net/go/maulogger/v2"

	"go.mau.fi/mautrix-signal/database/upgrades"
	"go.mau.fi/util/dbutil"
)

type Database struct {
	*dbutil.Database

	User     *UserQuery
	Portal   *PortalQuery
	Puppet   *PuppetQuery
	Message  *MessageQuery
	Reaction *ReactionQuery
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
	return db
}

func strPtr(val string) *string {
	if val == "" {
		return nil
	}
	return &val
}
