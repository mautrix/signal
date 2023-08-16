package main

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/google/uuid"
	"github.com/rs/zerolog"
	"go.mau.fi/mautrix-signal/database"
	"go.mau.fi/mautrix-signal/pkg/signalmeow"
	"maunium.net/go/mautrix"
	"maunium.net/go/mautrix/appservice"
	"maunium.net/go/mautrix/bridge"
	"maunium.net/go/mautrix/bridge/bridgeconfig"
	"maunium.net/go/mautrix/bridge/status"
	"maunium.net/go/mautrix/event"
	"maunium.net/go/mautrix/id"
)

var (
	ErrNotConnected = errors.New("not connected")
	ErrNotLoggedIn  = errors.New("not logged in")
)

type User struct {
	*database.User

	sync.Mutex

	bridge *SignalBridge
	log    zerolog.Logger

	PermissionLevel bridgeconfig.PermissionLevel

	SignalDevice *signalmeow.Device

	BridgeState     *bridge.BridgeStateQueue
	bridgeStateLock sync.Mutex
	wasDisconnected bool
	wasLoggedOut    bool
}

var _ bridge.User = (*User)(nil)
var _ status.BridgeStateFiller = (*User)(nil)

// ** bridge.User Interface **

func (user *User) GetPermissionLevel() bridgeconfig.PermissionLevel {
	return user.PermissionLevel
}

func (user *User) IsLoggedIn() bool {
	user.Lock()
	defer user.Unlock()

	return user.SignalUsername != ""
}

func (user *User) GetManagementRoomID() id.RoomID {
	return user.ManagementRoom
}

func (user *User) SetManagementRoom(roomID id.RoomID) {
	user.bridge.managementRoomsLock.Lock()
	defer user.bridge.managementRoomsLock.Unlock()

	existing, ok := user.bridge.managementRooms[roomID]
	if ok {
		existing.ManagementRoom = ""
		existing.Update()
	}

	user.ManagementRoom = roomID
	user.bridge.managementRooms[user.ManagementRoom] = user
	err := user.Update()
	if err != nil {
		user.log.Error().Err(err).Msg("Error setting management room")
	}
}

func (user *User) GetIDoublePuppet() bridge.DoublePuppet {
	p := user.bridge.GetPuppetByCustomMXID(user.MXID)
	if p == nil || p.CustomIntent() == nil {
		return nil
	}
	return p
}

func (user *User) GetIGhost() bridge.Ghost {
	p := user.bridge.GetPuppetBySignalID(user.SignalID)
	if p == nil {
		return nil
	}
	return p
}

// ** User creation and fetching **

func (br *SignalBridge) loadUser(dbUser *database.User, mxid *id.UserID) *User {
	if dbUser == nil {
		if mxid == nil {
			return nil
		}
		dbUser = br.DB.User.New()
		dbUser.MXID = *mxid
		err := dbUser.Insert()
		if err != nil {
			br.ZLog.Err(err).Msg("Error creating user %s")
			return nil
		}
	}

	user := br.NewUser(dbUser)
	br.usersByMXID[user.MXID] = user
	if user.SignalID != "" {
		br.usersBySignalID[user.SignalID] = user
	}
	if user.ManagementRoom != "" {
		br.managementRoomsLock.Lock()
		br.managementRooms[user.ManagementRoom] = user
		br.managementRoomsLock.Unlock()
	}
	// Ensure a puppet is created for this user
	newPuppet := br.GetPuppetBySignalID(user.SignalID)
	if newPuppet != nil && newPuppet.CustomMXID == "" {
		newPuppet.CustomMXID = user.MXID
		err := newPuppet.Update()
		if err != nil {
			br.ZLog.Err(err).Msg("Error updating puppet for user %s")
		}
	}
	return user
}

func (br *SignalBridge) GetUserByMXID(userID id.UserID) *User {
	if userID == br.Bot.UserID || br.IsGhost(userID) {
		return nil
	}
	br.usersLock.Lock()
	defer br.usersLock.Unlock()

	user, ok := br.usersByMXID[userID]
	if !ok {
		return br.loadUser(br.DB.User.GetByMXID(userID), &userID)
	}
	return user
}

func (br *SignalBridge) GetUserBySignalID(id string) *User {
	br.usersLock.Lock()
	defer br.usersLock.Unlock()

	user, ok := br.usersBySignalID[id]
	if !ok {
		return br.loadUser(br.DB.User.GetBySignalID(id), nil)
	}
	return user
}

func (br *SignalBridge) NewUser(dbUser *database.User) *User {
	user := &User{
		User:   dbUser,
		bridge: br,
		log:    br.ZLog.With().Str("user_id", string(dbUser.MXID)).Logger(),

		PermissionLevel: br.Config.Bridge.Permissions.Get(dbUser.MXID),
	}
	user.BridgeState = br.NewBridgeStateQueue(user)
	return user
}

func (user *User) ensureInvited(intent *appservice.IntentAPI, roomID id.RoomID, isDirect bool) (ok bool) {
	extraContent := make(map[string]interface{})
	if isDirect {
		extraContent["is_direct"] = true
	}
	customPuppet := user.bridge.GetPuppetByCustomMXID(user.MXID)
	if customPuppet != nil && customPuppet.CustomIntent() != nil {
		extraContent["fi.mau.will_auto_accept"] = true
	}
	_, err := intent.InviteUser(roomID, &mautrix.ReqInviteUser{UserID: user.MXID}, extraContent)
	var httpErr mautrix.HTTPError
	if err != nil && errors.As(err, &httpErr) && httpErr.RespError != nil && strings.Contains(httpErr.RespError.Err, "is already in the room") {
		user.bridge.StateStore.SetMembership(roomID, user.MXID, event.MembershipJoin)
		ok = true
		return
	} else if err != nil {
		user.log.Warn().Err(err).Msgf("Failed to invite user to %s", roomID)
	} else {
		ok = true
	}

	if customPuppet != nil && customPuppet.CustomIntent() != nil {
		err = customPuppet.CustomIntent().EnsureJoined(roomID, appservice.EnsureJoinedParams{IgnoreCache: true})
		if err != nil {
			user.log.Warn().Err(err).Msgf("Failed to auto-join %s", roomID)
			ok = false
		} else {
			ok = true
		}
	}
	return
}

func (user *User) syncChatDoublePuppetDetails(portal *Portal, justCreated bool) {
	doublePuppet := portal.bridge.GetPuppetByCustomMXID(user.MXID)
	if doublePuppet == nil {
		return
	}
	if doublePuppet == nil || doublePuppet.CustomIntent() == nil || len(portal.MXID) == 0 {
		return
	}

	// TODO: Get chat setting from Signal and sync them here
	//if justCreated || !user.bridge.Config.Bridge.TagOnlyOnCreate {
	//	chat, err := user.SignalDevice.Store.ChatSettings.GetChatSettings(portal.Key().ChatID)
	//	if err != nil {
	//		user.log.Warn().Err(err).Msgf("Failed to get settings of %s", portal.Key().ChatID)
	//		return
	//	}
	//	intent := doublePuppet.CustomIntent()
	//	if portal.Key.JID == types.StatusBroadcastJID && justCreated {
	//		if user.bridge.Config.Bridge.MuteStatusBroadcast {
	//			user.updateChatMute(intent, portal, time.Now().Add(365*24*time.Hour))
	//		}
	//		if len(user.bridge.Config.Bridge.StatusBroadcastTag) > 0 {
	//			user.updateChatTag(intent, portal, user.bridge.Config.Bridge.StatusBroadcastTag, true)
	//		}
	//		return
	//	} else if !chat.Found {
	//		return
	//	}
	//	user.updateChatMute(intent, portal, chat.MutedUntil)
	//	user.updateChatTag(intent, portal, user.bridge.Config.Bridge.ArchiveTag, chat.Archived)
	//	user.updateChatTag(intent, portal, user.bridge.Config.Bridge.PinnedTag, chat.Pinned)
	//}
}

// ** status.BridgeStateFiller methods **

func (user *User) GetMXID() id.UserID {
	return user.MXID
}
func (user *User) GetRemoteID() string {
	return user.SignalID
}

func (user *User) GetRemoteName() string {
	//if user.Session != nil && user.Session.State != nil && user.Session.State.User != nil {
	//return fmt.Sprintf("%s#%s", user.Session.State.User.Username, user.Session.State.User.Discriminator)
	//}
	return user.SignalID
}

// ** Startup, connection and shutdown methods **

func (br *SignalBridge) getAllLoggedInUsers() []*User {
	br.usersLock.Lock()
	defer br.usersLock.Unlock()

	dbUsers, err := br.DB.User.AllLoggedIn()
	if err != nil {
		br.ZLog.Error().Err(err).Msg("Error fetching all logged in users")
		return nil
	}
	users := make([]*User, len(dbUsers))

	for idx, dbUser := range dbUsers {
		user, ok := br.usersByMXID[dbUser.MXID]
		if !ok {
			user = br.loadUser(dbUser, nil)
		}
		users[idx] = user
	}
	return users
}

func (user *User) startupTryConnect(retryCount int) {
	user.BridgeState.Send(status.BridgeState{StateEvent: status.StateConnecting})
	err := user.Connect()
	if err != nil {
		user.log.Error().Err(err).Msg("Error connecting on startup")
		//closeErr := &websocket.CloseError{}
		if errors.Is(err, ErrNotLoggedIn) {
			user.log.Warn().Msg("Not logged in, skipping startup retry")
			user.BridgeState.Send(status.BridgeState{StateEvent: status.StateLoggedOut})
		} else if retryCount < 6 {
			user.BridgeState.Send(status.BridgeState{StateEvent: status.StateTransientDisconnect, Error: "unknown-websocket-error", Message: err.Error()})
			retryInSeconds := 2 << retryCount
			user.log.Debug().Int("retry_in_seconds", retryInSeconds).Msg("Sleeping and retrying connection")
			time.Sleep(time.Duration(retryInSeconds) * time.Second)
			user.startupTryConnect(retryCount + 1)
		} else {
			user.BridgeState.Send(status.BridgeState{StateEvent: status.StateUnknownError, Error: "unknown-websocket-error", Message: err.Error()})
		}
	}
}

func (br *SignalBridge) StartUsers() {
	br.ZLog.Debug().Msg("Starting users")

	usersWithToken := br.getAllLoggedInUsers()
	for _, u := range usersWithToken {
		go u.startupTryConnect(0)
	}
	if len(usersWithToken) == 0 {
		br.SendGlobalBridgeState(status.BridgeState{StateEvent: status.StateUnconfigured}.Fill(nil))
	}

	br.ZLog.Debug().Msg("Starting custom puppets")
	for _, customPuppet := range br.GetAllPuppetsWithCustomMXID() {
		go func(puppet *Puppet) {
			br.ZLog.Debug().Str("user_id", puppet.CustomMXID.String()).Msg("Starting custom puppet")

			if err := puppet.StartCustomMXID(true); err != nil {
				puppet.log.Error().Err(err).Msg("Failed to start custom puppet")
			}
		}(customPuppet)
	}
}

func (user *User) Login() (<-chan signalmeow.ProvisioningResponse, error) {
	user.Lock()
	defer user.Unlock()

	provChan := signalmeow.PerformProvisioning(user.bridge.MeowStore)

	return provChan, nil
}

func (user *User) Connect() error {
	user.Lock()
	defer user.Unlock()

	if user.SignalID == "" {
		return ErrNotLoggedIn
	}

	user.log.Debug().Msg("(stub) Connecting to Signal")

	device, err := user.bridge.MeowStore.DeviceByAci(user.SignalID)
	if err != nil {
		user.log.Err(err).Msg("store.DeviceByAci error")
		return err
	}
	if device == nil {
		user.log.Err(err).Msgf("no device found for aci %s", user.SignalID)
		return err
	}

	user.SignalDevice = device
	// TODO: hook up remote-netework handlers here
	device.Connection.IncomingSignalMessageHandler = user.incomingMessageHandler

	ctx := context.Background()
	connectErr := signalmeow.StartReceiveLoops(ctx, user.SignalDevice)

	return connectErr
}

func updatePuppetWithSignalProfile(ctx context.Context, user *User, puppet *Puppet) error {
	profile, err := signalmeow.RetrieveProfileByID(context.Background(), user.SignalDevice, puppet.SignalID)
	if err != nil {
		user.log.Err(err).Msg("error retrieving profile")
		return err
	}
	if profile.Name != puppet.Name {
		puppet.Name = profile.Name
		err = puppet.DefaultIntent().SetDisplayName(profile.Name)
		if err != nil {
			user.log.Err(err).Msg("error setting display name")
			return err
		} else {
			puppet.NameSet = true
			err = puppet.Update()
			if err != nil {
				user.log.Err(err).Msg("error updating puppet")
				return err
			}
		}
	}
	return nil
}

func ensureGroupPuppetsAreJoinedToPortal(ctx context.Context, user *User, portal *Portal) error {
	// Check if ChatID is a groupID (not a UUID), otherwise do nothing
	// TODO: do better than passing around strings and seeing if they are UUIDs or not
	if _, err := uuid.Parse(portal.ChatID); err == nil {
		return nil
	}
	user.log.Info().Msgf("Ensuring everyone is joined to room %s, groupID: %s", portal.MXID, portal.ChatID)
	group, err := signalmeow.RetrieveGroupByID(ctx, user.SignalDevice, signalmeow.GroupID(portal.ChatID))
	if err != nil {
		user.log.Err(err).Msg("error retrieving group")
		return err
	}
	for _, member := range group.Members {
		if member.UserId == user.SignalID {
			continue
		}
		memberPuppet := portal.bridge.GetPuppetBySignalID(member.UserId)
		if memberPuppet == nil {
			user.log.Err(err).Msgf("no puppet found for signalID %s", member.UserId)
			continue
		}
		_ = updatePuppetWithSignalProfile(context.Background(), user, memberPuppet)
		err = memberPuppet.DefaultIntent().EnsureJoined(portal.MXID)
		if err != nil {
			user.log.Err(err).Msg("error ensuring joined")
		}
	}
	return nil
}

func (user *User) incomingMessageHandler(incomingMessage signalmeow.IncomingSignalMessage) error {
	switch incomingMessage.MessageType() {
	case signalmeow.IncomingSignalMessageTypeText:
		m := incomingMessage.(signalmeow.IncomingSignalMessageText)
		var chatID string
		var senderPuppet *Puppet

		// Get and update the puppet for this message
		if m.SenderUUID == user.SignalID {
			// This is a message sent by us on another device
			user.log.Debug().Msgf("Text message received to %s (group: %v) at %v", m.RecipientUUID, m.GroupID, m.Timestamp)
			chatID = m.RecipientUUID
			senderPuppet = user.bridge.GetPuppetByCustomMXID(user.MXID)
		} else {
			user.log.Debug().Msgf("Text message received from %s (group: %v) at %v", m.SenderUUID, m.GroupID, m.Timestamp)
			chatID = m.SenderUUID
			senderPuppet = user.bridge.GetPuppetBySignalID(m.SenderUUID)
			err := updatePuppetWithSignalProfile(context.Background(), user, senderPuppet)
			if err != nil {
				user.log.Err(err).Msg("error updating puppet")
			}
			if m.GroupID != nil {
				chatID = string(*m.GroupID)
			}
		}

		// Get and update the portal for this message
		portal := user.GetPortalByChatID(chatID)
		if portal == nil {
			err := fmt.Errorf("no portal found for chatID %s", chatID)
			user.log.Err(err).Msg("error getting portal")
			return err
		}
		updatePortal := false
		if m.GroupID != nil {
			group, err := signalmeow.RetrieveGroupByID(context.Background(), user.SignalDevice, *m.GroupID)
			if err != nil {
				user.log.Err(err).Msg("error retrieving group")
			}
			if portal.Name != group.Title || portal.Topic != group.Description {
				portal.Name = group.Title
				portal.Topic = group.Description
				updatePortal = true
			}

			// ensure everyone is invited to the group
			_ = ensureGroupPuppetsAreJoinedToPortal(context.Background(), user, portal)
		} else {
			if portal.shouldSetDMRoomMetadata() {
				portal.Name = senderPuppet.Name
				updatePortal = true
			}
		}
		if updatePortal {
			_, err := portal.MainIntent().SetRoomName(portal.MXID, portal.Name)
			if err != nil {
				user.log.Err(err).Msg("error setting room name")
			}
			portal.NameSet = err == nil
			_, err = portal.MainIntent().SetRoomTopic(portal.MXID, portal.Topic)
			if err != nil {
				user.log.Err(err).Msg("error setting room topic")
			}
			err = portal.Update()
			if err != nil {
				user.log.Err(err).Msg("error updating portal")
			}
			portal.UpdateBridgeInfo()
		}
		portalSignalMessage := portalSignalMessage{
			user:      user,
			msg:       m.Content,
			sender:    senderPuppet,
			timestamp: m.Timestamp,
		}
		portal.signalMessages <- portalSignalMessage
	default:
		user.log.Warn().Msgf("Unknown message type received %v", incomingMessage.MessageType())
	}

	return nil
}

func (user *User) GetPortalByChatID(signalID string) *Portal {
	pk := database.PortalKey{
		ChatID:   signalID,
		Receiver: user.SignalUsername,
	}
	return user.bridge.GetPortalByChatID(pk)
}

func (user *User) Disconnect() error {
	user.Lock()
	defer user.Unlock()
	if user.SignalDevice == nil {
		return ErrNotConnected
	}

	user.log.Info().Msg("Disconnecting session manually")
	// TODO: don't reach in so far to disconnect user
	err := user.SignalDevice.Connection.AuthedWS.Close()
	if err != nil {
		return err
	}
	user.SignalDevice = nil
	return nil
}

// ** Misc Methods **

// Used in CreateMatrixRoom in portal.go
func (user *User) UpdateDirectChats(chats map[id.UserID][]id.RoomID) {
	if !user.bridge.Config.Bridge.SyncDirectChatList {
		return
	}

	puppet := user.bridge.GetPuppetByMXID(user.MXID)
	if puppet == nil {
		return
	}

	intent := puppet.CustomIntent()
	if intent == nil {
		return
	}

	method := http.MethodPatch
	if chats == nil {
		chats = user.getDirectChats()
		method = http.MethodPut
	}

	user.log.Debug().Msg("Updating m.direct list on homeserver")

	var err error
	if user.bridge.Config.Homeserver.Software == bridgeconfig.SoftwareAsmux {
		urlPath := intent.BuildURL(mautrix.ClientURLPath{"unstable", "com.beeper.asmux", "dms"})
		_, err = intent.MakeFullRequest(mautrix.FullRequest{
			Method:      method,
			URL:         urlPath,
			Headers:     http.Header{"X-Asmux-Auth": {user.bridge.AS.Registration.AppToken}},
			RequestJSON: chats,
		})
	} else {
		existingChats := map[id.UserID][]id.RoomID{}

		err = intent.GetAccountData(event.AccountDataDirectChats.Type, &existingChats)
		if err != nil {
			user.log.Warn().Err(err).Msg("Failed to get m.direct event to update it")
			return
		}

		for userID, rooms := range existingChats {
			if _, ok := user.bridge.ParsePuppetMXID(userID); !ok {
				// This is not a ghost user, include it in the new list
				chats[userID] = rooms
			} else if _, ok := chats[userID]; !ok && method == http.MethodPatch {
				// This is a ghost user, but we're not replacing the whole list, so include it too
				chats[userID] = rooms
			}
		}

		err = intent.SetAccountData(event.AccountDataDirectChats.Type, &chats)
	}

	if err != nil {
		user.log.Warn().Err(err).Msg("Failed to update m.direct event")
	}
}

func (user *User) getDirectChats() map[id.UserID][]id.RoomID {
	chats := map[id.UserID][]id.RoomID{}

	privateChats := user.bridge.DB.Portal.FindPrivateChatsOf(user.SignalID)
	for _, portal := range privateChats {
		if portal.MXID != "" {
			puppetMXID := user.bridge.FormatPuppetMXID(portal.Key().Receiver)

			chats[puppetMXID] = []id.RoomID{portal.MXID}
		}
	}

	return chats
}
