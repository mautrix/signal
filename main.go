package main

import (
	_ "embed"
	"fmt"
	"runtime"
	"strings"

	"sync"

	"github.com/rs/zerolog"
	"go.mau.fi/mautrix-signal/config"
	"go.mau.fi/mautrix-signal/database"
	"maunium.net/go/mautrix/bridge"
	"maunium.net/go/mautrix/bridge/commands"
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

	Config *config.Config
	DB     *database.Database

	//provisioning *ProvisioningAPI

	usersByMXID map[id.UserID]*User
	usersByID   map[string]*User
	usersLock   sync.Mutex

	managementRooms     map[id.RoomID]*User
	managementRoomsLock sync.Mutex

	portalsByMXID map[id.RoomID]*Portal
	portalsByID   map[database.PortalKey]*Portal
	portalsLock   sync.Mutex

	puppets             map[string]*Puppet
	puppetsByCustomMXID map[id.UserID]*Puppet
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

func (br *SignalBridge) CreatePrivatePortal(id id.RoomID, user bridge.User, ghost bridge.Ghost) {
	//TODO implement
}

func main() {
	br := &SignalBridge{
		usersByMXID: make(map[id.UserID]*User),
		usersByID:   make(map[string]*User),

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
