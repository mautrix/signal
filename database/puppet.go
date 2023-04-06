package database

import (
	"database/sql"

	log "maunium.net/go/maulogger/v2"

	"maunium.net/go/mautrix/id"
	"maunium.net/go/mautrix/util/dbutil"
)

const (
	puppetSelect = "SELECT id, name, name_set, avatar, avatar_url, avatar_set," +
		" custom_mxid, access_token, next_batch" +
		" FROM puppet "
)

type PuppetQuery struct {
	db  *Database
	log log.Logger
}

func (pq *PuppetQuery) New() *Puppet {
	return &Puppet{
		db:  pq.db,
		log: pq.log,
	}
}

func (pq *PuppetQuery) Get(id string) *Puppet {
	return pq.get(puppetSelect+" WHERE id=$1", id)
}

func (pq *PuppetQuery) GetByCustomMXID(mxid id.UserID) *Puppet {
	return pq.get(puppetSelect+" WHERE custom_mxid=$1", mxid)
}

func (pq *PuppetQuery) get(query string, args ...interface{}) *Puppet {
	return pq.New().Scan(pq.db.QueryRow(query, args...))
}

func (pq *PuppetQuery) GetAll() []*Puppet {
	return pq.getAll(puppetSelect)
}

func (pq *PuppetQuery) GetAllWithCustomMXID() []*Puppet {
	return pq.getAll(puppetSelect + " WHERE custom_mxid<>''")
}

func (pq *PuppetQuery) getAll(query string, args ...interface{}) []*Puppet {
	rows, err := pq.db.Query(query, args...)
	if err != nil || rows == nil {
		return nil
	}
	defer rows.Close()

	var puppets []*Puppet
	for rows.Next() {
		puppets = append(puppets, pq.New().Scan(rows))
	}

	return puppets
}

type Puppet struct {
	db  *Database
	log log.Logger

	ID        string
	Name      string
	NameSet   bool
	Avatar    string
	AvatarURL id.ContentURI
	AvatarSet bool

	CustomMXID  id.UserID
	AccessToken string
	NextBatch   string
}

func (p *Puppet) Scan(row dbutil.Scannable) *Puppet {
	var avatarURL string
	var customMXID, accessToken, nextBatch sql.NullString

	err := row.Scan(&p.ID, &p.Name, &p.NameSet, &p.Avatar, &avatarURL, &p.AvatarSet,
		&customMXID, &accessToken, &nextBatch)

	if err != nil {
		if err != sql.ErrNoRows {
			p.log.Errorln("Database scan failed:", err)
			panic(err)
		}

		return nil
	}

	p.AvatarURL, _ = id.ParseContentURI(avatarURL)
	p.CustomMXID = id.UserID(customMXID.String)
	p.AccessToken = accessToken.String
	p.NextBatch = nextBatch.String

	return p
}

func (p *Puppet) Insert() {
	query := `
		INSERT INTO puppet (id, name, name_set, avatar, avatar_url, avatar_set, custom_mxid, access_token, next_batch)
		VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9)
	`
	_, err := p.db.Exec(query, p.ID, p.Name, p.NameSet, p.Avatar, p.AvatarURL.String(), p.AvatarSet,
		strPtr(string(p.CustomMXID)), strPtr(p.AccessToken), strPtr(p.NextBatch))

	if err != nil {
		p.log.Warnfln("Failed to insert %s: %v", p.ID, err)
		panic(err)
	}
}

func (p *Puppet) Update() {
	query := `
		UPDATE puppet SET name=$1, name_set=$2, avatar=$3, avatar_url=$4, avatar_set=$5,
		                  custom_mxid=$6, access_token=$7, next_batch=$8
		WHERE id=$9
	`
	_, err := p.db.Exec(query, p.Name, p.NameSet, p.Avatar, p.AvatarURL.String(), p.AvatarSet,
		strPtr(string(p.CustomMXID)), strPtr(p.AccessToken), strPtr(p.NextBatch),
		p.ID)

	if err != nil {
		p.log.Warnfln("Failed to update %s: %v", p.ID, err)
		panic(err)
	}
}
