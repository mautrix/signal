package database

import (
	"database/sql"
	"errors"
	"fmt"

	log "maunium.net/go/maulogger/v2"

	"maunium.net/go/mautrix/id"
	"maunium.net/go/mautrix/util/dbutil"
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

type Puppet struct {
	db  *Database
	log log.Logger

	SignalID    string
	Number      *string
	Name        string
	NameQuality int
	AvatarHash  string
	AvatarURL   id.ContentURI
	NameSet     bool
	AvatarSet   bool

	IsRegistered bool

	CustomMXID     id.UserID
	AccessToken    string
	NextBatch      string
	BaseURL        string
	ContactInfoSet bool
}

func (p *Puppet) values() []interface{} {
	return []interface{}{
		p.SignalID,
		p.Number,
		p.Name,
		p.NameQuality,
		p.AvatarHash,
		p.AvatarURL.String(),
		p.NameSet,
		p.AvatarSet,
		p.ContactInfoSet,
		p.IsRegistered,
		p.CustomMXID.String(),
		p.AccessToken,
		p.NextBatch,
		p.BaseURL,
	}
}

func (p *Puppet) Scan(row dbutil.Scannable) *Puppet {
	var number, name, avatarHash, avatarURL, customMXID, accessToken, nextBatch, baseURL sql.NullString
	err := row.Scan(
		&p.SignalID,
		&number,
		&name,
		&p.NameQuality,
		&avatarHash,
		&avatarURL,
		&p.NameSet,
		&p.AvatarSet,
		&p.ContactInfoSet,
		&p.IsRegistered,
		&customMXID,
		&accessToken,
		&nextBatch,
		&baseURL,
	)
	if err != nil {
		if !errors.Is(err, sql.ErrNoRows) {
			p.log.Warnfln("Error scanning puppet row: %w", err)
		}
		return nil
	}
	parsedAvatarURL, err := id.ParseContentURI(avatarURL.String)
	if err != nil {
		p.log.Warnfln("Error parsing avatar URL: %w", err)
		p.AvatarURL = id.ContentURI{}
	} else {
		p.AvatarURL = parsedAvatarURL
	}

	p.Number = &number.String
	p.Name = name.String
	p.AvatarHash = avatarHash.String
	p.CustomMXID = id.UserID(customMXID.String)
	p.AccessToken = accessToken.String
	p.NextBatch = nextBatch.String
	p.BaseURL = baseURL.String
	return p
}

func (p *Puppet) deleteExistingNumber(tx *dbutil.LoggingTxn) error {
	if p.Number == nil || *p.Number == "" {
		return nil
	}
	_, err := tx.Exec("UPDATE puppet SET number=null WHERE number=$1 AND uuid<>$2", p.Number, p.SignalID)
	return err
}

func (p *Puppet) Insert() error {
	q := `
	INSERT INTO puppet (uuid, number, name, name_quality, avatar_hash, avatar_url,
						name_set, avatar_set, contact_info_set, is_registered,
						custom_mxid, access_token, next_batch, base_url)
	VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10,
			$11, $12, $13, $14)
	`
	tx, err := p.db.Begin()
	if err != nil {
		return fmt.Errorf("error starting transaction: %w", err)
	}
	defer tx.Rollback()
	err = p.deleteExistingNumber(tx)
	if err != nil {
		return fmt.Errorf("error deleting existing number: %w", err)
	}
	_, err = tx.Exec(q, p.values()...)
	if err != nil {
		return fmt.Errorf("error inserting puppet: %w", err)
	}
	err = tx.Commit()
	if err != nil {
		return fmt.Errorf("error committing transaction: %w", err)
	}
	return nil
}

func (p *Puppet) UpdateNumber() error {
	q := "UPDATE puppet SET number=$1 WHERE uuid=$2"
	tx, err := p.db.Begin()
	if err != nil {
		return fmt.Errorf("error starting transaction: %w", err)
	}
	defer tx.Rollback()
	err = p.deleteExistingNumber(tx)
	if err != nil {
		return fmt.Errorf("error deleting existing number: %w", err)
	}
	_, err = tx.Exec(q, p.Number, p.SignalID)
	if err != nil {
		return fmt.Errorf("error updating puppet number: %w", err)
	}
	err = tx.Commit()
	if err != nil {
		return fmt.Errorf("error committing transaction: %w", err)
	}
	return nil
}

func (p *Puppet) Update() error {
	q := `
	UPDATE puppet SET
		number=$2, name=$3, name_quality=$4, avatar_hash=$5, avatar_url=$6,
		name_set=$7, avatar_set=$8, contact_info_set=$9, is_registered=$10,
		custom_mxid=$11, access_token=$12, next_batch=$13, base_url=$14
	WHERE uuid=$1
	`
	// check for db
	if p.db == nil {
		return fmt.Errorf("no database connection")
	}
	_, err := p.db.Exec(q, p.values()...)
	if err != nil {
		return fmt.Errorf("error updating puppet: %w", err)
	}
	return nil
}

const (
	selectBase = `
        SELECT uuid, number, name, name_quality, avatar_hash, avatar_url, name_set, avatar_set,
               contact_info_set, is_registered, custom_mxid, access_token, next_batch, base_url
        FROM puppet
	`
)

func (pq *PuppetQuery) GetBySignalID(signalID string) *Puppet {
	q := selectBase + " WHERE uuid=$1"
	row := pq.db.QueryRow(q, signalID)
	return pq.New().Scan(row)
}

func (pq *PuppetQuery) GetByNumber(number string) *Puppet {
	q := selectBase + " WHERE number=$1"
	row := pq.db.QueryRow(q, number)
	return pq.New().Scan(row)
}

func (pq *PuppetQuery) GetByCustomMXID(mxid id.UserID) *Puppet {
	q := selectBase + " WHERE custom_mxid=$1"
	row := pq.db.QueryRow(q, mxid.String())
	return pq.New().Scan(row)
}

func (pq *PuppetQuery) GetAllWithCustomMXID() ([]*Puppet, error) {
	q := selectBase + " WHERE custom_mxid IS NOT NULL AND custom_mxid <> ''"
	rows, err := pq.db.Query(q)
	if err != nil {
		return nil, fmt.Errorf("error getting all puppets with custom mxid: %w", err)
	}
	defer rows.Close()
	puppets := []*Puppet{}
	for rows.Next() {
		pq.New().Scan(rows)
		puppets = append(puppets, pq.New().Scan(rows))
	}
	return puppets, nil
}
