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

package main

import (
	"context"
	_ "embed"
	"fmt"
	"os"
	"sync"

	"github.com/rs/zerolog"
	"go.mau.fi/util/configupgrade"
	"go.mau.fi/util/dbutil"
	"maunium.net/go/mautrix"
	"maunium.net/go/mautrix/bridge"
	"maunium.net/go/mautrix/bridge/commands"
	"maunium.net/go/mautrix/event"
	"maunium.net/go/mautrix/format"
	"maunium.net/go/mautrix/id"

	"go.mau.fi/mautrix-signal/config"
	"go.mau.fi/mautrix-signal/database"
	"go.mau.fi/mautrix-signal/pkg/signalmeow"
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
	Metrics   *MetricsHandler
	MeowStore *signalmeow.StoreContainer

	provisioning *ProvisioningAPI

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

	disappearingMessagesManager *DisappearingMessagesManager
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

	signalmeow.SetLogger(br.ZLog.With().Str("component", "signalmeow").Logger().Level(zerolog.DebugLevel))
	//signalmeow.SetLogger(br.ZLog.With().Str("component", "signalmeow").Caller().Logger())

	br.DB = database.New(br.Bridge.DB, br.Log.Sub("Database"))
	br.MeowStore = signalmeow.NewStore(br.Bridge.DB, dbutil.ZeroLogger(br.ZLog.With().Str("db_section", "signalmeow").Logger()))

	ss := br.Config.Bridge.Provisioning.SharedSecret
	if len(ss) > 0 && ss != "disable" {
		br.provisioning = &ProvisioningAPI{bridge: br, log: br.ZLog.With().Str("component", "provisioning").Logger()}
	}
	br.disappearingMessagesManager = &DisappearingMessagesManager{
		DB:     br.DB,
		Log:    br.ZLog.With().Str("component", "disappearingMessagesManager").Logger(),
		Bridge: br,
	}

	br.Metrics = NewMetricsHandler(br.Config.Metrics.Listen, br.Log.Sub("Metrics"), br.DB)
	br.MatrixHandler.TrackEventDuration = br.Metrics.TrackMatrixEvent
}

func (br *SignalBridge) Start() {
	err := br.MeowStore.Upgrade()
	if err != nil {
		br.Log.Fatalln("Failed to upgrade signalmeow database: %v", err)
		os.Exit(15)
	}
	if br.provisioning != nil {
		br.Log.Debugln("Initializing provisioning API")
		br.provisioning.Init()
	}
	go br.StartUsers()
	if br.Config.Metrics.Enabled {
		go br.Metrics.Start()
	}
	go br.disappearingMessagesManager.StartDisappearingLoop(context.TODO())
}

func (br *SignalBridge) Stop() {
	br.Metrics.Stop()
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
	br.Log.Debugln("CreatePrivatePortal", roomID, brInviter, brGhost)
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
		br.ZLog.Warn().Msgf("Failed to invite %s to existing private chat portal %s with %s. Redirecting portal to new room...", inviter.MXID, portal.MXID, puppet.SignalID)
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
	portal.log.Info().Msgf("Creating private chat portal in %s after invite from %s", roomID, inviter.MXID)
	// TODO check if room is already encrypted
	var existingEncryption event.EncryptionEventContent
	var encryptionEnabled bool
	err := portal.MainIntent().StateEvent(roomID, event.StateEncryption, "", &existingEncryption)
	if err != nil {
		portal.log.Warn().Msgf("Failed to check if encryption is enabled in private chat room %s", roomID)
	} else {
		encryptionEnabled = existingEncryption.Algorithm == id.AlgorithmMegolmV1
	}
	portal.MXID = roomID
	//portal.Topic = PrivateChatTopic
	portal.Name = puppet.Name
	portal.AvatarURL = puppet.AvatarURL
	portal.AvatarHash = puppet.AvatarHash
	portal.AvatarSet = puppet.AvatarSet
	portal.log.Info().Msgf("Created private chat portal in %s after invite from %s", roomID, inviter.MXID)
	intent := puppet.DefaultIntent()

	if br.Config.Bridge.Encryption.Default || encryptionEnabled {
		_, err := intent.InviteUser(roomID, &mautrix.ReqInviteUser{UserID: br.Bot.UserID})
		if err != nil {
			portal.log.Warn().Msgf("Failed to invite bridge bot to enable e2be: %v", err)
		}
		err = br.Bot.EnsureJoined(roomID)
		if err != nil {
			portal.log.Warn().Msgf("Failed to join as bridge bot to enable e2be: %v", err)
		}
		if !encryptionEnabled {
			_, err = intent.SendStateEvent(roomID, event.StateEncryption, "", portal.getEncryptionEventContent())
			if err != nil {
				portal.log.Warn().Msgf("Failed to enable e2be: %v", err)
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
		puppetsByNumber:     make(map[string]*Puppet),
	}
	br.Bridge = bridge.Bridge{
		Name:              "mautrix-signal",
		URL:               "https://github.com/mautrix/signalgo",
		Description:       "A Matrix-Signal puppeting bridge.",
		Version:           "0.1.0",
		ProtocolName:      "Signal",
		BeeperServiceName: "signal",
		BeeperNetworkName: "signal",

		CryptoPickleKey: "mautrix.bridge.e2ee",

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
