package database

import (
	"database/sql"
	"errors"
	"fmt"

	"go.mau.fi/util/dbutil"
	log "maunium.net/go/maulogger/v2"
	"maunium.net/go/mautrix/id"
)

type PortalQuery struct {
	db  *Database
	log log.Logger
}

func (pq *PortalQuery) New() *Portal {
	return &Portal{
		db:  pq.db,
		log: pq.log,
	}
}

type PortalKey struct {
	ChatID   string
	Receiver string
}

func NewPortalKey(chatID, receiver string) PortalKey {
	return PortalKey{
		ChatID:   chatID,
		Receiver: receiver,
	}
}

func (key PortalKey) String() string {
	return fmt.Sprintf("%s:%s", key.ChatID, key.Receiver)
}

type Portal struct {
	db  *Database
	log log.Logger

	ChatID         string
	Receiver       string
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

func (p *Portal) values() []interface{} {
	return []interface{}{
		p.ChatID,
		p.Receiver,
		p.MXID,
		p.Name,
		p.Topic,
		p.AvatarHash,
		p.AvatarURL.String(),
		p.NameSet,
		p.AvatarSet,
		p.Revision,
		p.Encrypted,
		p.RelayUserID,
		p.ExpirationTime,
	}
}

func (p *Portal) Scan(row dbutil.Scannable) *Portal {
	if row == nil {
		p.log.Debugln("nil row passed to Portal.Scan")
		return nil
	}
	var chatID, receiver, mxid, name, topic, avatarHash, avatarURL, relayUserID sql.NullString
	var expirationTime sql.NullInt64
	err := row.Scan(
		&chatID,
		&receiver,
		&mxid,
		&name,
		&topic,
		&avatarHash,
		&avatarURL,
		&p.NameSet,
		&p.AvatarSet,
		&p.Revision,
		&p.Encrypted,
		&relayUserID,
		&expirationTime,
	)
	if err != nil {
		if !errors.Is(err, sql.ErrNoRows) {
			p.log.Warnfln("Error scanning portal row: %w", err)
		} else {
			p.log.Debugln("No portal row found")
		}
		return nil
	}
	p.ChatID = chatID.String
	p.Receiver = receiver.String
	p.MXID = id.RoomID(mxid.String)
	p.Name = name.String
	p.Topic = topic.String
	p.AvatarHash = avatarHash.String
	p.RelayUserID = id.UserID(relayUserID.String)
	p.ExpirationTime = int(expirationTime.Int64)
	parsedAvatarURL, err := id.ParseContentURI(avatarURL.String)
	if err != nil {
		p.log.Warnfln("Error parsing avatar URL: %w", err)
		p.AvatarURL = id.ContentURI{}
	} else {
		p.AvatarURL = parsedAvatarURL
	}
	return p
}

func (p *Portal) SetPortalKey(pk PortalKey) {
	p.ChatID = pk.ChatID
	p.Receiver = pk.Receiver
}

func (p *Portal) Key() PortalKey {
	return PortalKey{
		ChatID:   p.ChatID,
		Receiver: p.Receiver,
	}
}

func (p *Portal) Insert() error {
	q := `
	INSERT INTO portal (
		chat_id, receiver, mxid, name, topic, avatar_hash, avatar_url, name_set, avatar_set,
		revision, encrypted, relay_user_id, expiration_time
	) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13)
	`
	_, err := p.db.Exec(q, p.values()...)
	return err
}

func (p *Portal) Update() error {
	q := `
	UPDATE portal SET mxid=$3, name=$4, topic=$5, avatar_hash=$6, avatar_url=$7, name_set=$8,
	                  avatar_set=$9, revision=$10, encrypted=$11, relay_user_id=$12,
	                  expiration_time=$13
	WHERE chat_id=$1 AND receiver=$2
	`
	_, err := p.db.Exec(q, p.values()...)
	return err
}

const (
	portalColumns = `
        chat_id, receiver, mxid, name, topic, avatar_hash, avatar_url, name_set, avatar_set,
        revision, encrypted, relay_user_id, expiration_time
	`
)

func (pq *PortalQuery) GetByMXID(mxid id.RoomID) *Portal {
	q := fmt.Sprintf("SELECT %s FROM portal WHERE mxid=$1", portalColumns)
	log.Debugfln("mxid: %s", mxid.String())
	log.Debugfln("QUERY: %s", q)
	row := pq.db.QueryRow(q, mxid.String())
	log.Debugfln("ROW: %s", row)
	p := pq.New()
	return p.Scan(row)
}

func (pq *PortalQuery) GetByChatID(pk PortalKey) *Portal {
	q := fmt.Sprintf("SELECT %s FROM portal WHERE chat_id=$1 AND receiver=$2", portalColumns)
	log.Debugfln("QUERY: %s", q)
	row := pq.db.QueryRow(q, pk.ChatID, pk.Receiver)
	log.Debugfln("ROW: %s", row)
	p := pq.New()
	return p.Scan(row)
}

func (pq *PortalQuery) FindPrivateChatsOf(receiver string) []*Portal {
	q := fmt.Sprintf("SELECT %s FROM portal WHERE receiver=$1", portalColumns)
	rows, err := pq.db.Query(q, receiver)
	log.Debugfln("receiver: %s", receiver)
	log.Debugfln("QUERY: %s", q)
	if err != nil {
		pq.log.Warnfln("Error querying private chats of %s: %w", receiver, err)
		return nil
	}
	defer rows.Close()
	var portals []*Portal
	for rows.Next() {
		p := pq.New()
		if p.Scan(rows) != nil {
			portals = append(portals, p)
		}
	}
	return portals
}

func (pq *PortalQuery) FindPrivateChatsWith(otherUser string) []*Portal {
	q := fmt.Sprintf("SELECT %s FROM portal WHERE chat_id=$1 AND receiver<>''", portalColumns)
	rows, err := pq.db.Query(q, otherUser)
	log.Debugfln("otherUser: %s", otherUser)
	log.Debugfln("QUERY: %s", q)
	if err != nil {
		pq.log.Warnfln("Error querying private chats with %s: %w", otherUser, err)
		return nil
	}
	defer rows.Close()
	var portals []*Portal
	for rows.Next() {
		p := pq.New()
		if p.Scan(rows) != nil {
			portals = append(portals, p)
		}
	}
	return portals
}

func (pq *PortalQuery) AllWithRoom() []*Portal {
	q := fmt.Sprintf("SELECT %s FROM portal WHERE mxid IS NOT NULL", portalColumns)
	rows, err := pq.db.Query(q)
	log.Debugfln("BY ISTESF QUERY: %s", q)
	if err != nil {
		pq.log.Warnfln("Error querying all portals with room: %w", err)
		return nil
	}
	defer rows.Close()
	var portals []*Portal
	for rows.Next() {
		p := pq.New()
		if p.Scan(rows) != nil {
			portals = append(portals, p)
		}
	}
	return portals
}

func (pq *PortalQuery) GetAll() []*Portal {
	q := fmt.Sprintf("SELECT %s FROM portal", portalColumns)
	rows, err := pq.db.Query(q)
	log.Debugfln("ALLQUERY: %s", q)
	if err != nil {
		pq.log.Warnfln("Error querying all portals: %w", err)
		return nil
	}
	defer rows.Close()
	var portals []*Portal
	for rows.Next() {
		p := pq.New()
		if p.Scan(rows) != nil {
			portals = append(portals, p)
		}
	}
	return portals
}
