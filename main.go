package main

import (
	_ "embed"
	"fmt"
	"os"
	"runtime"
	"strings"

	"sync"

	"github.com/rs/zerolog"
	"go.mau.fi/mautrix-signal/config"
	"go.mau.fi/mautrix-signal/database"
	meowstore "go.mau.fi/mautrix-signal/pkg/signalmeow/store"
	"maunium.net/go/mautrix"
	"maunium.net/go/mautrix/bridge"
	"maunium.net/go/mautrix/bridge/commands"
	"maunium.net/go/mautrix/event"
	"maunium.net/go/mautrix/format"
	"maunium.net/go/mautrix/id"
	"maunium.net/go/mautrix/util/configupgrade"
)

//go:embed example-config.yaml
var ExampleConfig string

// Information to find out exactly which commit the bridge was built from.
// These are filled at build time with the -X linker flag.
var (
	Tag       = "unknown"
	Commit    = "unknown"
	BuildTime = "unknown"
)

type SignalBridge struct {
	bridge.Bridge

	Config    *config.Config
	DB        *database.Database
	MeowStore *meowstore.StoreContainer

	//provisioning *ProvisioningAPI

	usersByMXID     map[id.UserID]*User
	usersBySignalID map[string]*User
	usersLock       sync.Mutex

	managementRooms     map[id.RoomID]*User
	managementRoomsLock sync.Mutex

	portalsByMXID map[id.RoomID]*Portal
	portalsByID   map[database.PortalKey]*Portal
	portalsLock   sync.Mutex

	puppets             map[string]*Puppet
	puppetsByCustomMXID map[id.UserID]*Puppet
	puppetsByNumber     map[string]*Puppet
	puppetsLock         sync.Mutex
}

var _ bridge.ChildOverride = (*SignalBridge)(nil)

func (br *SignalBridge) GetExampleConfig() string {
	return ExampleConfig
}

func (br *SignalBridge) GetConfigPtr() interface{} {
	br.Config = &config.Config{
		BaseConfig: &br.Bridge.Config,
	}
	br.Config.BaseConfig.Bridge = &br.Config.Bridge
	return br.Config
}

func (br *SignalBridge) Init() {
	br.CommandProcessor = commands.NewProcessor(&br.Bridge)
	br.RegisterCommands()

	br.DB = database.New(br.Bridge.DB, br.Log.Sub("Database"))
	br.MeowStore = meowstore.NewWithDB(br.DB.RawDB, br.DB.Dialect.String())
	//signalLog = br.ZLog.With().Str("component", "discordgo").Logger()

	// TODO move this to mautrix-go?
	zerolog.CallerMarshalFunc = func(pc uintptr, file string, line int) string {
		files := strings.Split(file, "/")
		file = files[len(files)-1]
		name := runtime.FuncForPC(pc).Name()
		fns := strings.Split(name, ".")
		name = fns[len(fns)-1]
		return fmt.Sprintf("%s:%d:%s()", file, line, name)
	}
}

func (br *SignalBridge) Start() {
	err := br.MeowStore.Upgrade()
	if err != nil {
		br.Log.Fatalln("Failed to upgrade signalmeow database: %v", err)
		os.Exit(15)
	}
	go br.StartUsers()
}

func (br *SignalBridge) Stop() {
	for _, user := range br.usersByMXID {
		br.Log.Debugln("Disconnecting", user.MXID)
		user.Disconnect()
	}
}

func (br *SignalBridge) GetIPortal(mxid id.RoomID) bridge.Portal {
	p := br.GetPortalByMXID(mxid)
	if p == nil {
		return nil
	}
	return p
}

func (br *SignalBridge) GetIUser(mxid id.UserID, create bool) bridge.User {
	p := br.GetUserByMXID(mxid)
	if p == nil {
		return nil
	}
	return p
}

func (br *SignalBridge) IsGhost(mxid id.UserID) bool {
	_, isGhost := br.ParsePuppetMXID(mxid)
	return isGhost
}

func (br *SignalBridge) GetIGhost(mxid id.UserID) bridge.Ghost {
	p := br.GetPuppetByMXID(mxid)
	if p == nil {
		return nil
	}
	return p
}

func (br *SignalBridge) CreatePrivatePortal(roomID id.RoomID, brInviter bridge.User, brGhost bridge.Ghost) {
	inviter := brInviter.(*User)
	puppet := brGhost.(*Puppet)
	key := database.NewPortalKey(inviter.SignalID, puppet.SignalID)
	portal := br.GetPortalByChatID(key)

	if len(portal.MXID) == 0 {
		br.createPrivatePortalFromInvite(roomID, inviter, puppet, portal)
		return
	}

	ok := portal.ensureUserInvited(inviter)
	if !ok {
		br.Log.Warnfln("Failed to invite %s to existing private chat portal %s with %s. Redirecting portal to new room...", inviter.MXID, portal.MXID, puppet.SignalID)
		br.createPrivatePortalFromInvite(roomID, inviter, puppet, portal)
		return
	}
	intent := puppet.DefaultIntent()
	errorMessage := fmt.Sprintf("You already have a private chat portal with me at [%[1]s](https://matrix.to/#/%[1]s)", portal.MXID)
	errorContent := format.RenderMarkdown(errorMessage, true, false)
	_, _ = intent.SendMessageEvent(roomID, event.EventMessage, errorContent)
	br.Log.Debugfln("Leaving private chat room %s as %s after accepting invite from %s as we already have chat with the user", roomID, puppet.MXID, inviter.MXID)
	_, _ = intent.LeaveRoom(roomID)
}

func (br *SignalBridge) createPrivatePortalFromInvite(roomID id.RoomID, inviter *User, puppet *Puppet, portal *Portal) {
	// TODO check if room is already encrypted
	var existingEncryption event.EncryptionEventContent
	var encryptionEnabled bool
	err := portal.MainIntent().StateEvent(roomID, event.StateEncryption, "", &existingEncryption)
	if err != nil {
		portal.log.Warnfln("Failed to check if encryption is enabled in private chat room %s", roomID)
	} else {
		encryptionEnabled = existingEncryption.Algorithm == id.AlgorithmMegolmV1
	}
	portal.MXID = roomID
	//portal.Topic = PrivateChatTopic
	portal.Name = puppet.Name
	portal.AvatarURL = puppet.AvatarURL
	portal.AvatarHash = puppet.AvatarHash
	portal.AvatarSet = puppet.AvatarSet
	portal.log.Infofln("Created private chat portal in %s after invite from %s", roomID, inviter.MXID)
	intent := puppet.DefaultIntent()

	if br.Config.Bridge.Encryption.Default || encryptionEnabled {
		_, err := intent.InviteUser(roomID, &mautrix.ReqInviteUser{UserID: br.Bot.UserID})
		if err != nil {
			portal.log.Warnln("Failed to invite bridge bot to enable e2be:", err)
		}
		err = br.Bot.EnsureJoined(roomID)
		if err != nil {
			portal.log.Warnln("Failed to join as bridge bot to enable e2be:", err)
		}
		if !encryptionEnabled {
			_, err = intent.SendStateEvent(roomID, event.StateEncryption, "", portal.getEncryptionEventContent())
			if err != nil {
				portal.log.Warnln("Failed to enable e2be:", err)
			}
		}
		br.AS.StateStore.SetMembership(roomID, inviter.MXID, event.MembershipJoin)
		br.AS.StateStore.SetMembership(roomID, puppet.MXID, event.MembershipJoin)
		br.AS.StateStore.SetMembership(roomID, br.Bot.UserID, event.MembershipJoin)
		portal.Encrypted = true
	}
	_, _ = portal.MainIntent().SetRoomTopic(portal.MXID, portal.Topic)
	if portal.shouldSetDMRoomMetadata() {
		_, err = portal.MainIntent().SetRoomName(portal.MXID, portal.Name)
		portal.NameSet = err == nil
		_, err = portal.MainIntent().SetRoomAvatar(portal.MXID, portal.AvatarURL)
		portal.AvatarSet = err == nil
	}
	portal.Update()
	portal.UpdateBridgeInfo()
	_, _ = intent.SendNotice(roomID, "Private chat portal created")
}
func main() {
	br := &SignalBridge{
		usersByMXID:     make(map[id.UserID]*User),
		usersBySignalID: make(map[string]*User),

		managementRooms: make(map[id.RoomID]*User),

		portalsByMXID: make(map[id.RoomID]*Portal),
		portalsByID:   make(map[database.PortalKey]*Portal),

		puppets:             make(map[string]*Puppet),
		puppetsByCustomMXID: make(map[id.UserID]*Puppet),
	}
	br.Bridge = bridge.Bridge{
		Name:         "mautrix-signal",
		URL:          "https://github.com/mautrix/signalgo",
		Description:  "A Matrix-Signal puppeting bridge.",
		Version:      "0.1.0",
		ProtocolName: "Signal",

		CryptoPickleKey: "maunium.net/go/mautrix-signal",

		ConfigUpgrader: &configupgrade.StructUpgrader{
			SimpleUpgrader: configupgrade.SimpleUpgrader(config.DoUpgrade),
			Blocks:         config.SpacedBlocks,
			Base:           ExampleConfig,
		},

		Child: br,
	}
	br.InitVersion(Tag, Commit, BuildTime)

	br.Main()
}
