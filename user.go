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
	"errors"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/google/uuid"
	"github.com/rs/zerolog"
	"golang.org/x/exp/maps"
	"maunium.net/go/mautrix"
	"maunium.net/go/mautrix/appservice"
	"maunium.net/go/mautrix/bridge"
	"maunium.net/go/mautrix/bridge/bridgeconfig"
	"maunium.net/go/mautrix/bridge/status"
	"maunium.net/go/mautrix/event"
	"maunium.net/go/mautrix/id"

	"go.mau.fi/mautrix-signal/database"
	"go.mau.fi/mautrix-signal/pkg/signalmeow"
	"go.mau.fi/mautrix-signal/pkg/signalmeow/events"
	signalpb "go.mau.fi/mautrix-signal/pkg/signalmeow/protobuf"
)

var (
	ErrNotConnected = errors.New("not connected")
	ErrNotLoggedIn  = errors.New("not logged in")
)

func (br *SignalBridge) GetUserByMXID(userID id.UserID) *User {
	return br.maybeGetUserByMXID(userID, &userID)
}

func (br *SignalBridge) GetUserByMXIDIfExists(userID id.UserID) *User {
	return br.maybeGetUserByMXID(userID, nil)
}

func (br *SignalBridge) maybeGetUserByMXID(userID id.UserID, userIDPtr *id.UserID) *User {
	if userID == br.Bot.UserID || br.IsGhost(userID) {
		return nil
	}
	br.usersLock.Lock()
	defer br.usersLock.Unlock()

	user, ok := br.usersByMXID[userID]
	if !ok {
		dbUser, err := br.DB.User.GetByMXID(context.TODO(), userID)
		if err != nil {
			br.ZLog.Err(err).Msg("Failed to get user from database")
			return nil
		}
		return br.loadUser(context.TODO(), dbUser, userIDPtr)
	}
	return user
}

func (br *SignalBridge) GetUserBySignalID(id uuid.UUID) *User {
	br.usersLock.Lock()
	defer br.usersLock.Unlock()

	user, ok := br.usersBySignalID[id]
	if !ok {
		dbUser, err := br.DB.User.GetBySignalID(context.TODO(), id)
		if err != nil {
			br.ZLog.Err(err).Msg("Failed to get user from database")
			return nil
		}
		return br.loadUser(context.TODO(), dbUser, nil)
	}
	return user
}

func (br *SignalBridge) GetAllLoggedInUsers() []*User {
	br.usersLock.Lock()
	defer br.usersLock.Unlock()

	dbUsers, err := br.DB.User.GetAllLoggedIn(context.TODO())
	if err != nil {
		br.ZLog.Err(err).Msg("Error getting all logged in users")
		return nil
	}
	users := make([]*User, len(dbUsers))

	for idx, dbUser := range dbUsers {
		user, ok := br.usersByMXID[dbUser.MXID]
		if !ok {
			user = br.loadUser(context.TODO(), dbUser, nil)
		}
		users[idx] = user
	}
	return users
}

func (br *SignalBridge) loadUser(ctx context.Context, dbUser *database.User, mxid *id.UserID) *User {
	if dbUser == nil {
		if mxid == nil {
			return nil
		}
		dbUser = br.DB.User.New()
		dbUser.MXID = *mxid
		err := dbUser.Insert(ctx)
		if err != nil {
			br.ZLog.Err(err).Msg("Error creating user %s")
			return nil
		}
	}

	user := br.NewUser(dbUser)
	br.usersByMXID[user.MXID] = user
	if user.SignalID != uuid.Nil {
		br.usersBySignalID[user.SignalID] = user
	}
	if user.ManagementRoom != "" {
		br.managementRoomsLock.Lock()
		br.managementRooms[user.ManagementRoom] = user
		br.managementRoomsLock.Unlock()
	}
	return user
}

func (br *SignalBridge) NewUser(dbUser *database.User) *User {
	user := &User{
		User:   dbUser,
		bridge: br,
		log:    br.ZLog.With().Stringer("user_id", dbUser.MXID).Logger(),

		PermissionLevel: br.Config.Bridge.Permissions.Get(dbUser.MXID),
	}
	user.Admin = user.PermissionLevel >= bridgeconfig.PermissionLevelAdmin
	user.BridgeState = br.NewBridgeStateQueue(user)
	return user
}

type User struct {
	*database.User

	sync.Mutex

	bridge *SignalBridge
	log    zerolog.Logger

	Admin           bool
	PermissionLevel bridgeconfig.PermissionLevel

	Client *signalmeow.Client

	BridgeState     *bridge.BridgeStateQueue
	bridgeStateLock sync.Mutex

	spaceMembershipChecked bool
	spaceCreateLock        sync.Mutex
}

var (
	_ bridge.User              = (*User)(nil)
	_ status.BridgeStateFiller = (*User)(nil)
)

func (user *User) GetPermissionLevel() bridgeconfig.PermissionLevel {
	return user.PermissionLevel
}

func (user *User) IsLoggedIn() bool {
	user.Lock()
	defer user.Unlock()

	return user.Client != nil && user.Client.IsLoggedIn()
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
		err := existing.Update(context.TODO())
		if err != nil {
			existing.log.Err(err).Msg("Failed to update user when removing management room")
		}
	}

	user.ManagementRoom = roomID
	user.bridge.managementRooms[user.ManagementRoom] = user
	err := user.Update(context.TODO())
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

func (user *User) ensureInvited(ctx context.Context, intent *appservice.IntentAPI, roomID id.RoomID, isDirect bool) (ok bool) {
	log := user.log.With().Str("action", "ensure_invited").Stringer("room_id", roomID).Logger()
	if user.bridge.StateStore.IsMembership(ctx, roomID, user.MXID, event.MembershipJoin) {
		ok = true
		return
	}
	extraContent := make(map[string]interface{})
	if isDirect {
		extraContent["is_direct"] = true
	}
	customPuppet := user.bridge.GetPuppetByCustomMXID(user.MXID)
	if customPuppet != nil && customPuppet.CustomIntent() != nil {
		log.Debug().Msg("adding will_auto_accept to invite content")
		extraContent["fi.mau.will_auto_accept"] = true
	} else {
		log.Debug().Msg("NOT adding will_auto_accept to invite content")
	}
	_, err := intent.InviteUser(ctx, roomID, &mautrix.ReqInviteUser{UserID: user.MXID}, extraContent)
	var httpErr mautrix.HTTPError
	if err != nil && errors.As(err, &httpErr) && httpErr.RespError != nil && strings.Contains(httpErr.RespError.Err, "is already in the room") {
		err = user.bridge.StateStore.SetMembership(ctx, roomID, user.MXID, event.MembershipJoin)
		if err != nil {
			log.Warn().Err(err).Msg("Failed to update membership in state store")
		}
		ok = true
		return
	} else if err != nil {
		log.Warn().Err(err).Msg("Failed to invite user to room")
	} else {
		ok = true
	}

	if customPuppet != nil && customPuppet.CustomIntent() != nil {
		log.Debug().Msg("ensuring custom puppet is joined")
		err = customPuppet.CustomIntent().EnsureJoined(ctx, roomID, appservice.EnsureJoinedParams{IgnoreCache: true})
		if err != nil {
			log.Warn().Err(err).Msg("Failed to auto-join custom puppet")
			ok = false
		} else {
			ok = true
		}
	}
	return
}

func (user *User) GetSpaceRoom(ctx context.Context) id.RoomID {
	if !user.bridge.Config.Bridge.PersonalFilteringSpaces {
		return ""
	}

	if len(user.SpaceRoom) == 0 {
		user.spaceCreateLock.Lock()
		defer user.spaceCreateLock.Unlock()
		if len(user.SpaceRoom) > 0 {
			return user.SpaceRoom
		}

		resp, err := user.bridge.Bot.CreateRoom(ctx, &mautrix.ReqCreateRoom{
			Visibility: "private",
			Name:       "Signal",
			Topic:      "Your Signal bridged chats",
			InitialState: []*event.Event{{
				Type: event.StateRoomAvatar,
				Content: event.Content{
					Parsed: &event.RoomAvatarEventContent{
						URL: user.bridge.Config.AppService.Bot.ParsedAvatar,
					},
				},
			}},
			CreationContent: map[string]interface{}{
				"type": event.RoomTypeSpace,
			},
			PowerLevelOverride: &event.PowerLevelsEventContent{
				Users: map[id.UserID]int{
					user.bridge.Bot.UserID: 9001,
					user.MXID:              50,
				},
			},
		})

		if err != nil {
			user.log.Err(err).Msg("Failed to auto-create space room")
		} else {
			user.SpaceRoom = resp.RoomID
			err = user.Update(context.TODO())
			if err != nil {
				user.log.Err(err).Msg("Failed to save user in database after creating space room")
			}
			user.ensureInvited(ctx, user.bridge.Bot, user.SpaceRoom, false)
		}
	} else if !user.spaceMembershipChecked {
		user.ensureInvited(ctx, user.bridge.Bot, user.SpaceRoom, false)
	}
	user.spaceMembershipChecked = true

	return user.SpaceRoom
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
	//	chat, err := user.Client.Store.ChatSettings.GetChatSettings(portal.Key().ChatID)
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

func (user *User) GetMXID() id.UserID {
	return user.MXID
}
func (user *User) GetRemoteID() string {
	return user.SignalID.String()
}
func (user *User) GetRemoteName() string {
	return user.SignalUsername
}

func (user *User) startupTryConnect(retryCount int) {
	user.BridgeState.Send(status.BridgeState{StateEvent: status.StateConnecting})

	// Make sure user has the Signal device populated
	user.populateSignalDevice()

	user.log.Debug().Msg("Connecting to Signal")
	ctx := user.log.WithContext(context.Background())
	statusChan, err := user.Client.StartReceiveLoops(ctx)

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
				user.log.Debug().
					Str("peeked_connection_status_event", peekedConnectionStatus.Event.String()).
					Msg("Using peeked connectionStatus event")
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
				if managementRoom := user.GetManagementRoomID(); managementRoom != "" {
					_, _ = user.bridge.Bot.SendText(ctx, managementRoom, "You've been logged out of Signal")
				}

			case signalmeow.SignalConnectionEventError:
				user.log.Debug().Msg("Sending UnknownError BridgeState")
				user.BridgeState.Send(status.BridgeState{StateEvent: status.StateUnknownError, Error: "unknown-websocket-error", Message: err.Error()})

			case signalmeow.SignalConnectionCleanShutdown:
				if user.Client.IsLoggedIn() {
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
	err := user.Client.ClearKeysAndDisconnect(context.TODO())
	if err != nil {
		user.log.Err(err).Msg("Error clearing device keys")
	}
}

func (br *SignalBridge) StartUsers() {
	br.ZLog.Debug().Msg("Starting users")

	usersWithToken := br.GetAllLoggedInUsers()
	numUsersStarting := 0
	for _, u := range usersWithToken {
		device := u.populateSignalDevice()
		if device == nil || !device.IsLoggedIn() {
			br.ZLog.Warn().Stringer("user_id", u.MXID).Msg("No device found for user, skipping Connect and sending BadCredentials BridgeState")
			u.BridgeState.Send(status.BridgeState{StateEvent: status.StateBadCredentials, Message: "You have been logged out of Signal, please reconnect"})
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
			br.ZLog.Debug().Stringer("user_id", puppet.CustomMXID).Msg("Starting custom puppet")

			if err := puppet.StartCustomMXID(true); err != nil {
				puppet.log.Error().Err(err).Msg("Failed to start custom puppet")
			}
		}(customPuppet)
	}
}

func (user *User) Login() (<-chan signalmeow.ProvisioningResponse, error) {
	user.Lock()
	defer user.Unlock()

	provChan := signalmeow.PerformProvisioning(context.TODO(), user.bridge.MeowStore, user.bridge.Config.Signal.DeviceName)

	return provChan, nil
}

func (user *User) Connect() {
	user.startupTryConnect(0)
}

func (user *User) populateSignalDevice() *signalmeow.Client {
	user.Lock()
	defer user.Unlock()
	log := user.log.With().
		Str("action", "populate signal device").
		Str("signal_id", user.SignalID.String()).
		Logger()

	if user.SignalID == uuid.Nil {
		return nil
	}
	// TODO clear client on logout properly so that populating can skip creating if it already exists
	/*else if user.Client != nil {
		return user.Client
	}*/

	device, err := user.bridge.MeowStore.DeviceByACI(context.TODO(), user.SignalID)
	if err != nil {
		log.Err(err).Msg("Failed to get device from database")
		return nil
	} else if device == nil {
		log.Err(ErrNotLoggedIn).Msg("No device found for user")
		return nil
	}

	user.Client = &signalmeow.Client{
		Store:        device,
		EventHandler: user.eventHandler,
	}
	go user.tryAutomaticDoublePuppeting()
	return user.Client
}

func (user *User) handleReceipt(evt *events.Receipt) {
	log := user.log.With().
		Str("action", "handle receipt").
		Str("receipt_type", evt.Content.GetType().String()).
		Str("sender_uuid", evt.Sender.String()).
		Logger()
	ctx := log.WithContext(context.TODO())
	messages, err := user.bridge.DB.Message.GetManyBySignalID(ctx, user.SignalID, evt.Content.GetTimestamp(), user.SignalID, false)
	if err != nil {
		log.Err(err).Msg("Failed to get receipt target messages from database")
		return
	}
	sender := user.bridge.GetPuppetBySignalID(evt.Sender)
	missingMessageIDMap := make(map[uint64]struct{}, len(evt.Content.GetTimestamp()))
	for _, msg := range evt.Content.GetTimestamp() {
		missingMessageIDMap[msg] = struct{}{}
	}
	foundMessageIDs := make([]uint64, len(messages))
	switch evt.Content.GetType() {
	case signalpb.ReceiptMessage_READ:
		messageMap := make(map[string]*database.Message)
		for i, msg := range messages {
			foundMessageIDs[i] = msg.Timestamp
			delete(missingMessageIDMap, msg.Timestamp)
			// The database returns messages from newest to oldest, so only include the first message per chat
			_, ok := messageMap[msg.SignalChatID]
			if !ok {
				messageMap[msg.SignalChatID] = msg
			}
		}
		log.Debug().
			Uints64("found_message_ids", foundMessageIDs).
			Uints64("not_found_message_ids", maps.Keys(missingMessageIDMap)).
			Int("chat_count", len(messageMap)).
			Msg("Received read receipt")
		for _, msg := range messageMap {
			portal := user.GetPortalByChatID(msg.SignalChatID)
			if portal == nil {
				continue
			}
			err = portal.SendReadReceipt(ctx, sender, msg)
			if err != nil {
				log.Err(err).Msg("Failed to send read receipt")
			}
		}
	case signalpb.ReceiptMessage_DELIVERY:
		messageMap := make(map[string][]*database.Message)
		for i, msg := range messages {
			foundMessageIDs[i] = msg.Timestamp
			delete(missingMessageIDMap, msg.Timestamp)
			messageMap[msg.SignalChatID] = append(messageMap[msg.SignalChatID], msg)
		}
		log.Debug().
			Uints64("found_message_ids", foundMessageIDs).
			Uints64("not_found_message_ids", maps.Keys(missingMessageIDMap)).
			Int("chat_count", len(messageMap)).
			Msg("Received delivery receipt")
		for _, msgs := range messageMap {
			portal := user.GetPortalByChatID(msgs[0].SignalChatID)
			if portal == nil {
				continue
			}
			// There should always only be 1 part, but use the last part to be safe
			portal.MarkDelivered(ctx, msgs[len(msgs)-1])
		}
	}
}

func (user *User) handleReadSelf(evt *events.ReadSelf) {
	ctx := context.TODO()
	messagesByChat := map[string]*database.Message{}
	for _, part := range evt.Messages {
		log := user.log.With().
			Str("action", "handle read self").
			Str("sender_uuid", part.GetSenderAci()).
			Uint64("msg_timestamp", part.GetTimestamp()).
			Logger()
		ctx := log.WithContext(context.TODO())
		if senderUUID, err := uuid.Parse(part.GetSenderAci()); err != nil {
			log.Err(err).Msg("Failed to parse sender UUID")
		} else if msg, err := user.bridge.DB.Message.GetLastPartBySignalIDWithUnknownReceiver(ctx, senderUUID, part.GetTimestamp(), user.SignalID); err != nil {
			log.Err(err).Msg("Failed to get message from database")
		} else if msg == nil {
			log.Warn().Msg("Message not found in database")
		} else if existingMsg, ok := messagesByChat[msg.SignalChatID]; ok && existingMsg.Timestamp > msg.Timestamp {
			log.Trace().
				Str("chat_id", msg.SignalChatID).
				Uint64("newer_msg", existingMsg.Timestamp).
				Msg("Receipt event contains a newer message, skipping this one")
		} else {
			log.Trace().Str("chat_id", msg.SignalChatID).Msg("Received own read receipt")
			messagesByChat[msg.SignalChatID] = msg
		}
	}
	puppet := user.bridge.GetPuppetBySignalID(user.SignalID)
	for _, msg := range messagesByChat {
		portal := user.GetPortalByChatID(msg.SignalChatID)
		if portal == nil {
			continue
		}
		user.log.Debug().
			Str("action", "handle read self").
			Str("chat_id", msg.SignalChatID).
			Uint64("msg_timestamp", msg.Timestamp).
			Str("msg_mxid", msg.MXID.String()).
			Msg("Bridging own read receipt")
		portal.ScheduleDisappearing()
		user.SetLastReadTS(ctx, portal.PortalKey, msg.Timestamp)
		err := portal.SendReadReceipt(ctx, puppet, msg)
		if err != nil {
			user.log.Err(err).Stringer("mxid", msg.MXID).Msg("Failed to send read receipt")
		}
	}
}

func (user *User) handleContactList(evt *events.ContactList) {
	ctx := user.log.With().Str("action", "handle contact list").Logger().WithContext(context.TODO())
	for _, contact := range evt.Contacts {
		puppet := user.bridge.GetPuppetBySignalID(contact.UUID)
		if puppet == nil {
			return
		}
		puppet.UpdateInfo(ctx, user, contact)
	}
}

func (user *User) eventHandler(rawEvt events.SignalEvent) {
	switch evt := rawEvt.(type) {
	case *events.ChatEvent:
		portal := user.GetPortalByChatID(evt.Info.ChatID)
		if portal != nil {
			portal.signalMessages <- portalSignalMessage{user: user, evt: evt}
		} else {
			user.log.Warn().Str("chat_id", evt.Info.ChatID).Msg("Couldn't get portal, dropping message")
		}
	case *events.Receipt:
		user.handleReceipt(evt)
	case *events.ReadSelf:
		user.handleReadSelf(evt)
	case *events.Call:
		portal := user.GetPortalByChatID(evt.Info.ChatID)
		content := &event.MessageEventContent{MsgType: event.MsgNotice}
		if evt.IsRinging {
			content.Body = "Incoming call"
			if portal.IsPrivateChat() {
				content.MsgType = event.MsgText
			}
		} else {
			content.Body = "Call ended"
		}
		portal.sendMainIntentMessage(context.TODO(), content)
	case *events.ContactList:
		user.handleContactList(evt)
	default:
		user.log.Warn().Type("event_type", evt).Msg("Unrecognized event type from signalmeow")
	}
}

func (user *User) GetPortalByChatID(signalID string) *Portal {
	pk := database.PortalKey{
		ChatID:   signalID,
		Receiver: user.SignalID,
	}
	return user.bridge.GetPortalByChatID(pk)
}

func (user *User) disconnectNoLock() (*signalmeow.Client, error) {
	if user.Client == nil {
		return nil, ErrNotConnected
	}

	disconnectedDevice := user.Client
	err := user.Client.StopReceiveLoops()
	user.Client = nil
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
	user.bridge.MeowStore.DeleteDevice(context.TODO(), &loggedOutDevice.Store.DeviceData)
	user.bridge.GetPuppetByCustomMXID(user.MXID).ClearCustomMXID()
	return err
}

func (user *User) UpdateDirectChats(ctx context.Context, chats map[id.UserID][]id.RoomID) {
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
		_, err = intent.MakeFullRequest(ctx, mautrix.FullRequest{
			Method:      method,
			URL:         urlPath,
			Headers:     http.Header{"X-Asmux-Auth": {user.bridge.AS.Registration.AppToken}},
			RequestJSON: chats,
		})
	} else {
		existingChats := map[id.UserID][]id.RoomID{}

		err = intent.GetAccountData(ctx, event.AccountDataDirectChats.Type, &existingChats)
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

		err = intent.SetAccountData(ctx, event.AccountDataDirectChats.Type, &chats)
	}

	if err != nil {
		user.log.Warn().Err(err).Msg("Failed to update m.direct event")
	}
}

func (user *User) getDirectChats() map[id.UserID][]id.RoomID {
	chats := map[id.UserID][]id.RoomID{}

	privateChats, err := user.bridge.DB.Portal.FindPrivateChatsOf(context.TODO(), user.SignalID)
	if err != nil {
		user.log.Err(err).Msg("Failed to get private chats")
		return chats
	}
	for _, portal := range privateChats {
		if portal.MXID != "" {
			puppetMXID := user.bridge.FormatPuppetMXID(portal.UserID())

			chats[puppetMXID] = []id.RoomID{portal.MXID}
		}
	}

	return chats
}
