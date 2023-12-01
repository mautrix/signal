package main

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
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

	user.CleanUpExtraGhosts()

	return user
}

// ** Clean up any old ghosts that might have been left behind **
func (user *User) CleanUpExtraGhosts() {
	br := user.bridge

	// Get all the matrix rooms this user is in
	dbPortals := br.DB.Portal.AllWithRoom()
	portals := br.dbPortalsToPortals(dbPortals)

	for _, portal := range portals {
		if portal.MXID == "" {
			continue
		}
		members, err := portal.MainIntent().JoinedMembers(portal.MXID)
		if err != nil {
			user.log.Err(err).Msgf("Error getting joined members for %s", portal.MXID)
			continue
		}
		membersMap := members.Joined

		// Ingore Signal bot if it's in the room
		delete(membersMap, br.Bot.UserID)

		user.log.Debug().Msgf("Checking room %s for ghosts, found %d members", portal.MXID, len(membersMap))

		// If there are 2 or fewer members, skip it
		if len(membersMap) <= 2 {
			continue
		}

		// Check membership list for our custom ghost
		_, customGhostOk := membersMap[user.MXID]
		user.log.Debug().Msgf("Found custom ghost %s in %s: %v", user.MXID, portal.MXID, customGhostOk)

		// Check membership list for another ghost with our SignalID
		puppetMXID := user.bridge.FormatPuppetMXID(user.SignalID)
		_, signalGhostOk := membersMap[puppetMXID]
		user.log.Debug().Msgf("Found signal ghost %s in %s: %v", puppetMXID, portal.MXID, signalGhostOk)

		// If we have both, we need to remove the other ghost
		extraGhostCount := 0
		kickedGhostCount := 0
		if customGhostOk && signalGhostOk {
			extraGhostCount++
			kickUserReq := mautrix.ReqKickUser{
				UserID: puppetMXID,
				Reason: "You have been replaced by a new ghost",
			}
			_, err := portal.MainIntent().KickUser(portal.MXID, &kickUserReq)
			if err != nil {
				user.log.Err(err).Msgf("Error leaving room %s", portal.MXID)
			} else {
				kickedGhostCount++
			}
		}
		if extraGhostCount > 0 {
			user.log.Info().Msgf("Found %d extra ghosts in %s, kicked %d", extraGhostCount, portal.MXID, kickedGhostCount)
		}
	}
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
		user.log.Debug().Msgf("adding will_auto_accept for %s", user.MXID)
		extraContent["fi.mau.will_auto_accept"] = true
	} else {
		user.log.Debug().Msgf("NOT adding will_auto_accept for %s", user.MXID)
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
		user.log.Debug().Msgf("ensuring joined for %s", user.MXID)
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
	return user.SignalUsername
}

// ** Startup, connection and shutdown methods **

func (br *SignalBridge) getAllLoggedInUsers() []*User {
	br.usersLock.Lock()
	defer br.usersLock.Unlock()

	dbUsers := br.DB.User.AllLoggedIn()
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

	// Make sure user has the Signal device populated
	user.populateSignalDevice()

	user.log.Debug().Msg("Connecting to Signal")
	ctx := context.Background()
	statusChan, err := signalmeow.StartReceiveLoops(ctx, user.SignalDevice)

	if err != nil {
		user.log.Error().Err(err).Msg("Error connecting on startup")
		if errors.Is(err, ErrNotLoggedIn) {
			user.log.Warn().Msg("Not logged in, clearing Signal device keys")
			user.BridgeState.Send(status.BridgeState{StateEvent: status.StateBadCredentials, Message: "You have been logged out of Signal, please reconnect"})
			user.clearKeysAndDisconnect()
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

	if statusChan == nil {
		user.log.Error().Msg("statusChan is nil after Connect")
		return
	}
	// After Connect returns, all bridge states are triggered by events on the statusChan
	go func() {
		var peekedConnectionStatus signalmeow.SignalConnectionStatus
		for {
			var connectionStatus signalmeow.SignalConnectionStatus
			if peekedConnectionStatus.Event != signalmeow.SignalConnectionEventNone {
				user.log.Debug().Msgf("Using peeked connectionStatus event: %v", peekedConnectionStatus.Event)
				connectionStatus = peekedConnectionStatus
				peekedConnectionStatus = signalmeow.SignalConnectionStatus{}
			} else {
				var ok bool
				connectionStatus, ok = <-statusChan
				if !ok {
					user.log.Debug().Msg("statusChan channel closed")
					return
				}
			}

			err := connectionStatus.Err
			switch connectionStatus.Event {
			case signalmeow.SignalConnectionEventConnected:
				user.log.Debug().Msg("Sending Connected BridgeState")
				user.BridgeState.Send(status.BridgeState{StateEvent: status.StateConnected})

			case signalmeow.SignalConnectionEventDisconnected:
				user.log.Debug().Msg("Received SignalConnectionEventDisconnected")

				// Debounce: wait 7s before sending TransientDisconnect, in case we get a reconnect
				// We should wait until the next message comes in, or 7 seconds has passed.
				// - If a disconnected event comes in, just loop again, unless it's been more than 7 seconds.
				// - If a non-disconnected event comes in, store it in peekedConnectionStatus,
				//   break out of this loop and go back to the top of the goroutine to handle it in the switch.
				// - If 7 seconds passes without any non-disconnect messages, send the TransientDisconnect.
				//   (Why 7 seconds? It was 5 at first, but websockets min retry is 5 seconds,
				//     so it would send TransientDisconnect right before reconnecting. 7 seems to work well.)
				debounceTimer := time.NewTimer(7 * time.Second)
			PeekLoop:
				for {
					var ok bool
					select {
					case peekedConnectionStatus, ok = <-statusChan:
						// Handle channel closing
						if !ok {
							user.log.Debug().Msg("connectionStatus channel closed")
							return
						}
						// If it's another Disconnected event, just keep looping
						if peekedConnectionStatus.Event == signalmeow.SignalConnectionEventDisconnected {
							peekedConnectionStatus = signalmeow.SignalConnectionStatus{}
							continue
						}
						// If it's a non-disconnect event, break out of the PeekLoop and handle it in the switch
						break PeekLoop
					case <-debounceTimer.C:
						// Time is up, so break out of the loop and send the TransientDisconnect
						break PeekLoop
					}
				}
				// We're out of the PeekLoop, so either we got a non-disconnect event, or it's been 7 seconds (or both).
				// We want to send TransientDisconnect if it's been 7 seconds, but not if the latest event was something
				// other than Disconnected
				if !debounceTimer.Stop() { // If the timer has already expired
					// Send TransientDisconnect only if the latest event is a disconnect or no event
					// (peekedConnectionStatus could be something else if the timer and the event race)
					if peekedConnectionStatus.Event == signalmeow.SignalConnectionEventDisconnected ||
						peekedConnectionStatus.Event == signalmeow.SignalConnectionEventNone {
						user.log.Debug().Msg("Sending TransientDisconnect BridgeState")
						if err == nil {
							user.BridgeState.Send(status.BridgeState{StateEvent: status.StateTransientDisconnect})
						} else {
							user.BridgeState.Send(status.BridgeState{StateEvent: status.StateTransientDisconnect, Error: "unknown-websocket-error", Message: err.Error()})
						}
					}
				}

			case signalmeow.SignalConnectionEventLoggedOut:
				user.log.Debug().Msg("Sending BadCredentials BridgeState")
				if err == nil {
					user.BridgeState.Send(status.BridgeState{StateEvent: status.StateBadCredentials, Message: "You have been logged out of Signal, please reconnect"})
				} else {
					user.BridgeState.Send(status.BridgeState{StateEvent: status.StateBadCredentials, Message: err.Error()})
				}
				user.clearKeysAndDisconnect()

			case signalmeow.SignalConnectionEventError:
				user.log.Debug().Msg("Sending UnknownError BridgeState")
				user.BridgeState.Send(status.BridgeState{StateEvent: status.StateUnknownError, Error: "unknown-websocket-error", Message: err.Error()})

			case signalmeow.SignalConnectionCleanShutdown:
				if user.SignalDevice.IsDeviceLoggedIn() {
					user.log.Debug().Msg("Clean Shutdown - sending no BridgeState")
				} else {
					user.log.Debug().Msg("Clean Shutdown, but logged out - Sending BadCredentials BridgeState")
					user.BridgeState.Send(status.BridgeState{StateEvent: status.StateBadCredentials, Message: "You have been logged out of Signal, please reconnect"})
				}
			}
		}
	}()
}

func (user *User) clearKeysAndDisconnect() {
	// We need to clear out keys associated with the Signal device that no longer has valid credentials
	user.log.Debug().Msg("Clearing out Signal device keys")
	err := user.SignalDevice.ClearKeysAndDisconnect()
	if err != nil {
		user.log.Err(err).Msg("Error clearing device keys")
	}
}

func (br *SignalBridge) StartUsers() {
	br.ZLog.Debug().Msg("Starting users")

	usersWithToken := br.getAllLoggedInUsers()
	numUsersStarting := 0
	for _, u := range usersWithToken {
		device := u.populateSignalDevice()
		if device == nil {
			br.ZLog.Warn().Str("user_id", u.MXID.String()).Msg("No device found for user, skipping Connect")
			continue
		}
		go u.Connect()
		numUsersStarting++
	}
	if numUsersStarting == 0 {
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

	provChan := signalmeow.PerformProvisioning(context.TODO(), user.bridge.MeowStore)

	return provChan, nil
}

func (user *User) Connect() {
	user.startupTryConnect(0)
}

func (user *User) populateSignalDevice() *signalmeow.Device {
	user.Lock()
	defer user.Unlock()

	if user.SignalID == "" {
		return nil
	}

	device, err := user.bridge.MeowStore.DeviceByAci(user.SignalID)
	if err != nil {
		user.log.Err(err).Msgf("problem looking up aci %s", user.SignalID)
		return nil
	}
	if device == nil {
		user.log.Err(ErrNotLoggedIn).Msgf("no device found for aci %s", user.SignalID)
		return nil
	}

	user.SignalDevice = device
	device.Connection.IncomingSignalMessageHandler = user.incomingMessageHandler
	return device
}

func updatePuppetWithSignalContact(ctx context.Context, user *User, puppet *Puppet, newContactAvatar *signalmeow.ContactAvatar) error {
	contact, newProfileAvatar, err := user.SignalDevice.ContactByIDWithProfileAvatar(puppet.SignalID)
	if err != nil {
		user.log.Err(err).Msg("updatePuppetWithSignalContact: error retrieving contact")
		return err
	}

	contactName := contact.PreferredName()
	if contactName != puppet.Name {
		user.log.Debug().Msgf("updatePuppetWithSignalContact: updating puppet name to %s", contactName)
		puppet.Name = contactName
		err = puppet.DefaultIntent().SetDisplayName(contactName)
		if err != nil {
			user.log.Err(err).Msg("updatePuppetWithSignalContact: error setting display name")
			return err
		}
		puppet.NameSet = true
		err = puppet.Update()
		if err != nil {
			user.log.Err(err).Msg("updatePuppetWithSignalContact: error updating puppet with new name")
			return err
		}
	}

	if contact.PreferredAvatarHash() == "" && puppet.AvatarSet {
		user.log.Debug().Msg("updatePuppetWithSignalContact: clearing avatar")
		puppet.AvatarSet = false
		puppet.AvatarURL = id.ContentURI{}
		puppet.AvatarHash = ""
		err = puppet.DefaultIntent().SetAvatarURL(id.ContentURI{})
		if err != nil {
			user.log.Err(err).Msg("updatePuppetWithSignalContact: error clearing avatar url")
			return err
		}
		err = puppet.Update()
		if err != nil {
			user.log.Err(err).Msg("updatePuppetWithSignalContact: error updating puppet while clearing avatar")
			return err
		}
		return nil
	}

	// If avatar is set, we must have a new avatar image, so update it
	var newAvatar *signalmeow.ContactAvatar
	if newContactAvatar != nil {
		user.log.Debug().Msg("updatePuppetWithSignalContact: using newContactAvatar")
		newAvatar = newContactAvatar
	} else if newProfileAvatar != nil {
		user.log.Debug().Msg("updatePuppetWithSignalContact: using newProfileAvatar")
		newAvatar = newProfileAvatar
	}
	if newAvatar != nil {
		user.log.Debug().Msg("updatePuppetWithSignalContact: uploading avatar")
		avatarURL, err := puppet.DefaultIntent().UploadBytes(newAvatar.Image, newAvatar.ContentType)
		if err != nil {
			user.log.Err(err).Msg("updatePuppetWithSignalContact: error uploading avatar")
			return err
		}
		puppet.AvatarURL = avatarURL.ContentURI
		puppet.AvatarSet = true
		puppet.AvatarHash = newAvatar.Hash

		err = puppet.DefaultIntent().SetAvatarURL(avatarURL.ContentURI)
		if err != nil {
			user.log.Err(err).Msg("updatePuppetWithSignalContact: error setting avatar url")
			return err
		}
		err = puppet.Update()
		if err != nil {
			user.log.Err(err).Msg("updatePuppetWithSignalContact: error updating puppet with new avatar")
			return err
		}
	}
	return nil
}

func ensureGroupPuppetsAreJoinedToPortal(ctx context.Context, user *User, portal *Portal) error {
	// Ensure our puppet is joined to the room
	err := portal.MainIntent().EnsureJoined(portal.MXID)
	if err != nil {
		user.log.Err(err).Msg("error ensuring joined")
		return err
	}

	// Check if ChatID is a groupID (not a UUID), otherwise do nothing else
	// TODO: do better than passing around strings and seeing if they are UUIDs or not
	if _, err := uuid.Parse(portal.ChatID); err == nil {
		return nil
	}
	user.log.Info().Msgf("Ensuring everyone is joined to room %s, groupID: %s", portal.MXID, portal.ChatID)
	group, err := signalmeow.RetrieveGroupByID(ctx, user.SignalDevice, signalmeow.GroupIdentifier(portal.ChatID))
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
		_ = updatePuppetWithSignalContact(context.TODO(), user, memberPuppet, nil)
		err = memberPuppet.DefaultIntent().EnsureJoined(portal.MXID)
		if err != nil {
			user.log.Err(err).Msg("error ensuring joined")
		}
	}
	return nil
}

func (user *User) incomingMessageHandler(incomingMessage signalmeow.IncomingSignalMessage) error {
	// Handle things common to all message types
	m := incomingMessage.Base()
	var chatID string
	var senderPuppet *Puppet

	isSyncMessage := m.SenderUUID == user.SignalID

	// Get and update the puppet for this message
	user.tryAutomaticDoublePuppeting()
	if isSyncMessage {
		// This is a message sent by us on another device
		user.log.Debug().Msgf("Message received to %s (group: %v)", m.RecipientUUID, m.GroupID)
		chatID = m.RecipientUUID
		senderPuppet = user.bridge.GetPuppetByCustomMXID(user.MXID)
		if senderPuppet == nil {
			senderPuppet = user.bridge.GetPuppetBySignalID(m.SenderUUID)
			if senderPuppet == nil {
				err := fmt.Errorf("no puppet found for me (%s)", user.MXID)
				user.log.Err(err).Msg("error getting puppet")
				//return err
			}
		}
	} else {
		user.log.Debug().Msgf("Message received from %s (group: %v)", m.SenderUUID, m.GroupID)
		chatID = m.SenderUUID
		senderPuppet = user.bridge.GetPuppetBySignalID(m.SenderUUID)
		if senderPuppet == nil {
			err := fmt.Errorf("no puppet found for sender: %s", m.SenderUUID)
			user.log.Err(err).Msg("error getting puppet")
			//return err
		}

		// If this is a contact change, it might have a new contact avatar, and if it does
		// we'll need to pull it out there, since we can't get it any other time
		var newAvatar *signalmeow.ContactAvatar
		if incomingMessage.MessageType() == signalmeow.IncomingSignalMessageTypeContactChange {
			contactChangeMessage := incomingMessage.(signalmeow.IncomingSignalMessageContactChange)
			newAvatar = contactChangeMessage.Avatar
		}

		err := updatePuppetWithSignalContact(context.TODO(), user, senderPuppet, newAvatar)
		if err != nil {
			user.log.Err(err).Msg("error updating puppet with signal contact")
		}
		if m.GroupID != nil {
			chatID = string(*m.GroupID)
		}
	}

	// If this is a receipt, the chatID/portal is the room where the message was read
	if incomingMessage.MessageType() == signalmeow.IncomingSignalMessageTypeReceipt {
		receiptMessage := incomingMessage.(signalmeow.IncomingSignalMessageReceipt)
		timestamp := receiptMessage.OriginalTimestamp
		sender := receiptMessage.OriginalSender
		dbMessage := user.bridge.DB.Message.FindBySenderAndTimestamp(sender, timestamp)
		if dbMessage == nil {
			user.log.Warn().Msgf("Receipt received for unknown message %v %d", user.SignalID, timestamp)
			return nil
		}
		chatID = dbMessage.SignalChatID
	}

	// Get and update the portal for this message
	portal := user.GetPortalByChatID(chatID)
	if portal == nil {
		err := fmt.Errorf("no portal found for chatID %s", chatID)
		user.log.Err(err).Msg("error getting portal")
		return err
	}

	// If this is an expireTimer change, update the portal and return (only for DMs, group expireTimer changes are handled below)
	if incomingMessage.MessageType() == signalmeow.IncomingSignalMessageTypeExpireTimerChange {
		expireTimerMessage := incomingMessage.(signalmeow.IncomingSignalMessageExpireTimerChange)
		portal.log.Debug().Msgf("Updating expiration time to %d (DM)", expireTimerMessage.NewExpireTimer)
		if portal.ExpirationTime != int(expireTimerMessage.NewExpireTimer) {
			portal.ExpirationTime = int(expireTimerMessage.NewExpireTimer)
			err := portal.Update()
			if err != nil {
				user.log.Err(err).Msg("error updating exipration time in portal")
			}
		}
		portal.HandleNewDisappearingMessageTime(expireTimerMessage.NewExpireTimer)
		return nil
	}

	// Don't bother with portal updates for receipts or typing notifications
	// (esp. read receipts - they don't have GroupID set so it breaks)
	if !(incomingMessage.MessageType() == signalmeow.IncomingSignalMessageTypeReceipt || incomingMessage.MessageType() == signalmeow.IncomingSignalMessageTypeTyping) {
		updatePortal := false
		if m.GroupID != nil {
			group, avatarImage, err := signalmeow.RetrieveGroupAndAvatarByID(context.Background(), user.SignalDevice, *m.GroupID)
			if err != nil {
				user.log.Err(err).Msg("error retrieving group")
				return err
			}
			if portal.Name != group.Title || portal.Topic != group.Description {
				portal.Name = group.Title
				portal.Topic = group.Description
				updatePortal = true
			}
			if portal.ExpirationTime != int(group.DisappearingMessagesDuration) {
				portal.ExpirationTime = int(group.DisappearingMessagesDuration)
				updatePortal = true
				portal.log.Debug().Msgf("Updating expiration time to %d (group)", group.DisappearingMessagesDuration)
				portal.HandleNewDisappearingMessageTime(group.DisappearingMessagesDuration)
			}
			// avatarImage is only not nil if there's a new avatar to set
			if avatarImage != nil {
				user.log.Debug().Msg("Uploading new group avatar")
				avatarURL, err := portal.MainIntent().UploadBytes(avatarImage, http.DetectContentType(avatarImage))
				if err != nil {
					user.log.Err(err).Msg("error uploading group avatar")
					return err
				}
				portal.AvatarURL = avatarURL.ContentURI
				portal.AvatarSet = true
				hash := sha256.Sum256(avatarImage)
				portal.AvatarHash = hex.EncodeToString(hash[:])
				updatePortal = true
			}

			// ensure everyone is invited to the group
			_ = ensureGroupPuppetsAreJoinedToPortal(context.Background(), user, portal)
		} else {
			if portal.shouldSetDMRoomMetadata() {
				if senderPuppet.Name != portal.Name {
					portal.Name = senderPuppet.Name
					updatePortal = true
				}
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
			_, err = portal.MainIntent().SetRoomAvatar(portal.MXID, portal.AvatarURL)
			if err != nil {
				user.log.Err(err).Msg("error setting room avatar")
			}
			portal.AvatarSet = err == nil
			err = portal.Update()
			if err != nil {
				user.log.Err(err).Msg("error updating portal")
			}
			portal.UpdateBridgeInfo()
		}
		if incomingMessage.MessageType() == signalmeow.IncomingSignalMessageTypeGroupChange ||
			incomingMessage.MessageType() == signalmeow.IncomingSignalMessageTypeContactChange {
			// This was just a group or contact change message, and we changed the group, so we're done
			return nil
		}
	}

	// We've updated puppets and portals, now send the message along to the portal
	portalSignalMessage := portalSignalMessage{
		user:    user,
		sender:  senderPuppet,
		message: incomingMessage,
		sync:    isSyncMessage,
	}
	portal.signalMessages <- portalSignalMessage

	return nil
}

func (user *User) GetPortalByChatID(signalID string) *Portal {
	pk := database.PortalKey{
		ChatID:   signalID,
		Receiver: user.SignalUsername,
	}
	return user.bridge.GetPortalByChatID(pk)
}

func (user *User) disconnectNoLock() (*signalmeow.Device, error) {
	if user.SignalDevice == nil {
		return nil, ErrNotConnected
	}

	disconnectedDevice := user.SignalDevice
	err := signalmeow.StopReceiveLoops(user.SignalDevice)
	user.SignalDevice = nil
	return disconnectedDevice, err
}
func (user *User) Disconnect() error {
	user.Lock()
	defer user.Unlock()
	user.log.Info().Msg("Disconnecting session manually")
	_, err := user.disconnectNoLock()
	return err
}

func (user *User) Logout() error {
	user.Lock()
	defer user.Unlock()
	user.log.Info().Msg("Logging out of session")
	loggedOutDevice, err := user.disconnectNoLock()
	user.bridge.MeowStore.DeleteDevice(&loggedOutDevice.Data)
	user.bridge.GetPuppetByCustomMXID(user.MXID).ClearCustomMXID()
	return err
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
