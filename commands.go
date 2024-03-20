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
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"strconv"
	"strings"

	"github.com/google/uuid"
	"github.com/rs/zerolog"
	"github.com/rs/zerolog/log"
	"github.com/skip2/go-qrcode"
	"maunium.net/go/mautrix"
	"maunium.net/go/mautrix/bridge/commands"
	"maunium.net/go/mautrix/event"
	"maunium.net/go/mautrix/id"

	"go.mau.fi/mautrix-signal/pkg/signalmeow"
	"go.mau.fi/mautrix-signal/pkg/signalmeow/types"
)

var (
	HelpSectionConnectionManagement = commands.HelpSection{Name: "Connection management", Order: 11}
	HelpSectionCreatingPortals      = commands.HelpSection{Name: "Creating portals", Order: 15}
	HelpSectionPortalManagement     = commands.HelpSection{Name: "Portal management", Order: 20}
	HelpSectionInvites              = commands.HelpSection{Name: "Group invites", Order: 25}
	HelpSectionMiscellaneous        = commands.HelpSection{Name: "Miscellaneous", Order: 30}
)

type WrappedCommandEvent struct {
	*commands.Event
	Bridge *SignalBridge
	User   *User
	Portal *Portal
}

func (br *SignalBridge) RegisterCommands() {
	proc := br.CommandProcessor.(*commands.Processor)
	proc.AddHandlers(
		cmdPing,
		cmdLogin,
		cmdSetDeviceName,
		cmdPM,
		cmdResolvePhone,
		cmdSyncSpace,
		cmdDeleteSession,
		cmdSetRelay,
		cmdUnsetRelay,
		cmdDeletePortal,
		cmdDeleteAllPortals,
		cmdCleanupLostPortals,
		cmdInviteLink,
		cmdResetInviteLink,
		cmdCreate,
	)
}

func wrapCommand(handler func(*WrappedCommandEvent)) func(*commands.Event) {
	return func(ce *commands.Event) {
		user := ce.User.(*User)
		var portal *Portal
		if ce.Portal != nil {
			portal = ce.Portal.(*Portal)
		}
		br := ce.Bridge.Child.(*SignalBridge)
		handler(&WrappedCommandEvent{ce, br, user, portal})
	}
}

var cmdSetRelay = &commands.FullHandler{
	Func: wrapCommand(fnSetRelay),
	Name: "set-relay",
	Help: commands.HelpMeta{
		Section:     HelpSectionPortalManagement,
		Description: "Relay messages in this room through your Signal account.",
	},
	RequiresPortal: true,
	RequiresLogin:  true,
}

func fnSetRelay(ce *WrappedCommandEvent) {
	if !ce.Bridge.Config.Bridge.Relay.Enabled {
		ce.Reply("Relay mode is not enabled on this instance of the bridge")
	} else if ce.Bridge.Config.Bridge.Relay.AdminOnly && !ce.User.Admin {
		ce.Reply("Only bridge admins are allowed to enable relay mode on this instance of the bridge")
	} else {
		ce.Portal.RelayUserID = ce.User.MXID
		ce.Portal.Update(ce.Ctx)
		ce.Reply("Messages from non-logged-in users in this room will now be bridged through your Signal account")
	}
}

var cmdUnsetRelay = &commands.FullHandler{
	Func: wrapCommand(fnUnsetRelay),
	Name: "unset-relay",
	Help: commands.HelpMeta{
		Section:     HelpSectionPortalManagement,
		Description: "Stop relaying messages in this room.",
	},
	RequiresPortal: true,
}

func fnUnsetRelay(ce *WrappedCommandEvent) {
	if !ce.Bridge.Config.Bridge.Relay.Enabled {
		ce.Reply("Relay mode is not enabled on this instance of the bridge")
	} else if ce.Bridge.Config.Bridge.Relay.AdminOnly && !ce.User.Admin {
		ce.Reply("Only bridge admins are allowed to enable relay mode on this instance of the bridge")
	} else {
		ce.Portal.RelayUserID = ""
		ce.Portal.Update(ce.Ctx)
		ce.Reply("Messages from non-logged-in users will no longer be bridged in this room")
	}
}

var cmdDeleteSession = &commands.FullHandler{
	Func: wrapCommand(fnDeleteSession),
	Name: "delete-session",
	Help: commands.HelpMeta{
		Section:     HelpSectionConnectionManagement,
		Description: "Disconnect from Signal, clearing sessions but keeping other data. Reconnect with `login`",
	},
}

func fnDeleteSession(ce *WrappedCommandEvent) {
	if !ce.User.IsLoggedIn() {
		ce.Reply("You're not logged in")
		return
	}
	ce.User.Client.ClearKeysAndDisconnect(ce.Ctx)
	ce.Reply("Disconnected from Signal")
}

var cmdPing = &commands.FullHandler{
	Func: wrapCommand(fnPing),
	Name: "ping",
	Help: commands.HelpMeta{
		Section:     commands.HelpSectionAuth,
		Description: "Check your connection to Signal",
	},
}

func fnPing(ce *WrappedCommandEvent) {
	if ce.User.SignalID == uuid.Nil {
		ce.Reply("You're not logged in")
	} else if !ce.User.IsLoggedIn() {
		ce.Reply("You were logged in at some point, but are not anymore")
	} else if !ce.User.Client.IsConnected() {
		ce.Reply("You're logged into Signal, but not connected to the server")
	} else {
		ce.Reply("You're logged into Signal and probably connected to the server")
	}
}

var cmdSetDeviceName = &commands.FullHandler{
	Func: wrapCommand(fnSetDeviceName),
	Name: "set-device-name",
	Help: commands.HelpMeta{
		Section:     HelpSectionConnectionManagement,
		Description: "Set the name of this device in Signal",
		Args:        "<name>",
	},
	RequiresLogin: true,
}

func fnSetDeviceName(ce *WrappedCommandEvent) {
	if len(ce.Args) == 0 {
		ce.Reply("**Usage:** `set-device-name <name>`")
		return
	}

	name := strings.Join(ce.Args, " ")
	err := ce.User.Client.UpdateDeviceName(ce.Ctx, name)
	if err != nil {
		ce.Reply("Error setting device name: %v", err)
		return
	}
	ce.Reply("Device name updated")
}

var cmdPM = &commands.FullHandler{
	Func: wrapCommand(fnPM),
	Name: "pm",
	Help: commands.HelpMeta{
		Section:     HelpSectionCreatingPortals,
		Description: "Open a private chat with the given phone number.",
		Args:        "<_international phone number_>",
	},
	RequiresLogin: true,
}

var numberCleaner = strings.NewReplacer("-", "", " ", "", "(", "", ")", "", "+", "")

func fnPM(ce *WrappedCommandEvent) {
	if len(ce.Args) == 0 {
		ce.Reply("**Usage:** `pm <international phone number>`")
		return
	}
	number, err := strconv.ParseUint(numberCleaner.Replace(strings.Join(ce.Args, "")), 10, 64)
	if err != nil {
		ce.Reply("Failed to parse number")
		return
	}

	user := ce.User
	var targetUUID uuid.UUID

	if contact, err := user.Client.ContactByE164(ce.Ctx, fmt.Sprintf("+%d", number)); err != nil {
		ce.Reply("Error looking up number in local contact list: %v", err)
		return
	} else if contact != nil {
		targetUUID = contact.UUID
	} else if resp, err := user.Client.LookupPhone(ce.Ctx, number); err != nil {
		ce.ZLog.Err(err).Uint64("e164", number).Msg("Failed to lookup number on server")
		ce.Reply("Error looking up number on server: %v", err)
		return
	} else if resp[number].ACI == uuid.Nil {
		if resp[number].PNI == uuid.Nil {
			ce.Reply("+%d doesn't seem to be on Signal", number)
		} else {
			ce.Reply("Server only returned PNI (%s) for +%d, but the bridge doesn't know what to do with it", resp[number].PNI, number)
		}
		return
	} else {
		targetUUID = resp[number].ACI
		err = user.Client.Store.ContactStore.UpdatePhone(ce.Ctx, targetUUID, fmt.Sprintf("+%d", number))
		if err != nil {
			ce.ZLog.Warn().Err(err).Msg("Failed to update phone number in user's contact store")
		}
	}
	ce.ZLog.Debug().
		Uint64("e164", number).
		Stringer("uuid", targetUUID).
		Msg("Found DM target user")

	portal := user.GetPortalByChatID(targetUUID.String())
	if portal == nil {
		ce.Reply("Couldn't get portal with %s/+%d", targetUUID, number)
		return
	} else if portal.MXID != "" {
		ok := portal.ensureUserInvited(ce.Ctx, ce.User)
		if ok {
			ce.Reply("You already have a portal with +%d at [%s](%s)", number, portal.MXID, portal.MXID.URI(portal.bridge.Config.Homeserver.Domain).MatrixToURL())
			return
		}
		ce.ZLog.Warn().Stringer("existing_room_id", portal.MXID).Msg("Ensuring user is invited to existing room failed, creating new room")
		portal.Cleanup(ce.Ctx, false)
		portal.MXID = ""
	}

	if err = portal.CreateMatrixRoom(ce.Ctx, user, 0); err != nil {
		ce.ZLog.Err(err).Msg("Failed to create portal room")
		ce.Reply("Error creating Matrix room for portal to +%d", number)
	} else {
		ce.Reply("Created portal room [%s](%s) with +%d and invited you to it.", portal.MXID, portal.MXID.URI(portal.bridge.Config.Homeserver.Domain).MatrixToURL(), number)
	}
}

var cmdResolvePhone = &commands.FullHandler{
	Func: wrapCommand(fnResolvePhone),
	Name: "resolve-phone",
	Help: commands.HelpMeta{
		Section:     HelpSectionCreatingPortals,
		Description: "Look up phone numbers on the Signal servers.",
		Args:        "<numbers...>",
	},
	RequiresLogin: true,
}

func fnResolvePhone(ce *WrappedCommandEvent) {
	numbers := make([]uint64, len(ce.Args))
	for i, arg := range ce.Args {
		var err error
		numbers[i], err = strconv.ParseUint(numberCleaner.Replace(arg), 10, 64)
		if err != nil {
			ce.Reply("Failed to parse number %s: %v", arg, err)
			return
		}
	}
	resp, err := ce.User.Client.LookupPhone(ce.Ctx, numbers...)
	if err != nil {
		ce.Reply("Failed to look up: %v", err)
	} else {
		var out strings.Builder
		for _, phone := range numbers {
			result, found := resp[phone]
			if found {
				_, _ = fmt.Fprintf(&out, "+%d: %s / %s\n", phone, result.ACI, result.PNI)
				if result.ACI != uuid.Nil {
					err = ce.User.Client.Store.ContactStore.UpdatePhone(ce.Ctx, result.ACI, fmt.Sprintf("+%d", phone))
					if err != nil {
						ce.ZLog.Warn().Err(err).Msg("Failed to update phone number in user's contact store")
					}
				}
			} else {
				_, _ = fmt.Fprintf(&out, "+%d: not found\n", phone)
			}
		}
		ce.Reply(strings.TrimSpace(out.String()))
	}
}

var cmdSyncSpace = &commands.FullHandler{
	Func: wrapCommand(fnSyncSpace),
	Name: "sync-space",
	Help: commands.HelpMeta{
		Section:     HelpSectionMiscellaneous,
		Description: "Synchronize your personal filtering space",
	},
	RequiresLogin: true,
}

func fnSyncSpace(ce *WrappedCommandEvent) {
	if !ce.Bridge.Config.Bridge.PersonalFilteringSpaces {
		ce.Reply("Personal filtering spaces are not enabled on this instance of the bridge")
		return
	}
	ctx := ce.Ctx
	dmKeys, err := ce.Bridge.DB.Portal.FindPrivateChatsNotInSpace(ctx, ce.User.SignalID)
	if err != nil {
		ce.ZLog.Err(err).Msg("Failed to get private chat keys")
		ce.Reply("Failed to get private chat IDs from database")
		return
	}
	count := 0
	allPortals := ce.Bridge.GetAllPortalsWithMXID()
	for _, portal := range allPortals {
		if portal.IsPrivateChat() {
			continue
		}
		if ce.Bridge.StateStore.IsInRoom(ctx, portal.MXID, ce.User.MXID) && portal.addToPersonalSpace(ctx, ce.User) {
			count++
		}
	}
	for _, key := range dmKeys {
		portal := ce.Bridge.GetPortalByChatID(key)
		portal.addToPersonalSpace(ctx, ce.User)
		count++
	}
	plural := "s"
	if count == 1 {
		plural = ""
	}
	ce.Reply("Added %d room%s to space", count, plural)
}

var cmdLogin = &commands.FullHandler{
	Func: wrapCommand(fnLogin),
	Name: "login",
	Help: commands.HelpMeta{
		Section:     commands.HelpSectionAuth,
		Description: "Link the bridge to your Signal account as a web client.",
	},
}

func fnLogin(ce *WrappedCommandEvent) {
	if ce.User.IsLoggedIn() {
		if ce.User.Client.IsConnected() {
			ce.Reply("You're already logged in")
		} else {
			ce.Reply("You're already logged in, but not connected 🤔")
		}
		return
	}

	var qrEventID, msgEventID id.EventID
	var signalID uuid.UUID
	var signalPhone string

	// First get the provisioning URL
	provChan, err := ce.User.Login()
	if err != nil {
		ce.ZLog.Err(err).Msg("Failure logging in")
		ce.Reply("Failure logging in: %v", err)
		return
	}

	resp := <-provChan
	if resp.Err != nil || resp.State == signalmeow.StateProvisioningError {
		ce.Reply("Error getting provisioning URL: %v", resp.Err)
		return
	}
	if resp.State == signalmeow.StateProvisioningURLReceived {
		qrEventID, msgEventID = ce.User.sendQR(ce, resp.ProvisioningURL, qrEventID, msgEventID)
	} else {
		ce.Reply("Unexpected state: %v", resp.State)
		return
	}

	// Next, get the results of finishing registration
	resp = <-provChan
	_, _ = ce.Bot.RedactEvent(ce.Ctx, ce.RoomID, qrEventID)
	_, _ = ce.Bot.RedactEvent(ce.Ctx, ce.RoomID, msgEventID)
	if resp.Err != nil || resp.State == signalmeow.StateProvisioningError {
		if resp.Err != nil && strings.HasSuffix(resp.Err.Error(), " EOF") {
			ce.Reply("Logging in timed out, please try again.")
		} else {
			ce.Reply("Error finishing registration: %v", resp.Err)
		}
		return
	}
	if resp.State == signalmeow.StateProvisioningDataReceived {
		signalID = resp.ProvisioningData.ACI
		signalPhone = resp.ProvisioningData.Number
	} else {
		ce.Reply("Unexpected state: %v", resp.State)
		return
	}

	// Finally, get the results of generating and registering prekeys
	resp = <-provChan
	if resp.Err != nil || resp.State == signalmeow.StateProvisioningError {
		ce.Reply("Error with prekeys: %v", resp.Err)
		return
	} else if resp.State != signalmeow.StateProvisioningPreKeysRegistered {
		ce.Reply("Unexpected state: %v", resp.State)
		return
	}

	if signalID == uuid.Nil {
		ce.Reply("Problem logging in - No SignalID received")
		return
	}
	ce.User.saveSignalID(ce.Ctx, signalID, signalPhone)

	// Connect to Signal
	ce.User.Connect()
	ce.Reply("Successfully logged in as %s (UUID: %s)", ce.User.SignalUsername, ce.User.SignalID)
}

func (user *User) sendQR(ce *WrappedCommandEvent, code string, prevQR, prevMsg id.EventID) (qr, msg id.EventID) {
	content, ok := user.uploadQR(ce, code)
	if !ok {
		return prevQR, prevMsg
	}
	if len(prevQR) != 0 {
		content.SetEdit(prevQR)
	}
	resp, err := ce.Bot.SendMessageEvent(ce.Ctx, ce.RoomID, event.EventMessage, &content)
	if err != nil {
		ce.ZLog.Err(err).Msg("Failed to send QR code to user")
	} else if len(prevQR) == 0 {
		prevQR = resp.EventID
	}
	content = event.MessageEventContent{
		MsgType:       event.MsgNotice,
		Body:          fmt.Sprintf("Raw linking URI: %s", code),
		Format:        event.FormatHTML,
		FormattedBody: fmt.Sprintf("Raw linking URI: <code>%s</code>", code),
	}
	if len(prevMsg) != 0 {
		content.SetEdit(prevMsg)
	}
	resp, err = ce.Bot.SendMessageEvent(ce.Ctx, ce.RoomID, event.EventMessage, &content)
	if err != nil {
		ce.ZLog.Err(err).Msg("Failed to send raw code to user")
	} else if len(prevMsg) == 0 {
		prevMsg = resp.EventID
	}
	return prevQR, prevMsg
}

func (user *User) uploadQR(ce *WrappedCommandEvent, code string) (event.MessageEventContent, bool) {
	const size = 512
	qrCode, err := qrcode.Encode(code, qrcode.Low, size)
	if err != nil {
		ce.ZLog.Err(err).Msg("Failed to encode QR code")
		ce.Reply("Failed to encode QR code: %v", err)
		return event.MessageEventContent{}, false
	}

	bot := user.bridge.AS.BotClient()

	resp, err := bot.UploadBytes(ce.Ctx, qrCode, "image/png")
	if err != nil {
		ce.ZLog.Err(err).Msg("Failed to upload QR code")
		ce.Reply("Failed to upload QR code: %v", err)
		return event.MessageEventContent{}, false
	}
	return event.MessageEventContent{
		MsgType: event.MsgImage,
		Info: &event.FileInfo{
			MimeType: "image/png",
			Width:    size,
			Height:   size,
			Size:     len(qrCode),
		},
		Body: "qr.png",
		URL:  resp.ContentURI.CUString(),
	}, true
}

func canDeletePortal(ctx context.Context, portal *Portal, userID id.UserID) bool {
	if len(portal.MXID) == 0 {
		return false
	}

	members, err := portal.MainIntent().JoinedMembers(ctx, portal.MXID)
	if err != nil {
		portal.log.Err(err).
			Stringer("user_id", userID).
			Msg("Failed to get joined members to check if user can delete portal")
		return false
	}
	for otherUser := range members.Joined {
		_, isPuppet := portal.bridge.ParsePuppetMXID(otherUser)
		if isPuppet || otherUser == portal.bridge.Bot.UserID || otherUser == userID {
			continue
		}
		user := portal.bridge.GetUserByMXID(otherUser)
		if user != nil && user.IsLoggedIn() {
			return false
		}
	}
	return true
}

var cmdDeletePortal = &commands.FullHandler{
	Func: wrapCommand(fnDeletePortal),
	Name: "delete-portal",
	Help: commands.HelpMeta{
		Section:     HelpSectionPortalManagement,
		Description: "Delete the current portal. If the portal is used by other people, this is limited to bridge admins.",
	},
	RequiresPortal: true,
}

func fnDeletePortal(ce *WrappedCommandEvent) {
	if !ce.User.Admin && !canDeletePortal(ce.Ctx, ce.Portal, ce.User.MXID) {
		ce.Reply("Only bridge admins can delete portals with other Matrix users")
		return
	}

	ce.Portal.log.Info().Stringer("user_id", ce.User.MXID).Msg("User requested deletion of portal")
	ce.Portal.Delete()
	ce.Portal.Cleanup(ce.Ctx, false)
}

var cmdDeleteAllPortals = &commands.FullHandler{
	Func: wrapCommand(fnDeleteAllPortals),
	Name: "delete-all-portals",
	Help: commands.HelpMeta{
		Section:     HelpSectionPortalManagement,
		Description: "Delete all portals.",
	},
}

func fnDeleteAllPortals(ce *WrappedCommandEvent) {
	portals := ce.Bridge.GetAllPortalsWithMXID()
	var portalsToDelete []*Portal

	if ce.User.Admin {
		portalsToDelete = portals
	} else {
		portalsToDelete = portals[:0]
		for _, portal := range portals {
			if canDeletePortal(ce.Ctx, portal, ce.User.MXID) {
				portalsToDelete = append(portalsToDelete, portal)
			}
		}
	}
	if len(portalsToDelete) == 0 {
		ce.Reply("Didn't find any portals to delete")
		return
	}

	leave := func(portal *Portal) {
		if len(portal.MXID) > 0 {
			_, _ = portal.MainIntent().KickUser(ce.Ctx, portal.MXID, &mautrix.ReqKickUser{
				Reason: "Deleting portal",
				UserID: ce.User.MXID,
			})
		}
	}
	customPuppet := ce.Bridge.GetPuppetByCustomMXID(ce.User.MXID)
	if customPuppet != nil && customPuppet.CustomIntent() != nil {
		intent := customPuppet.CustomIntent()
		leave = func(portal *Portal) {
			if len(portal.MXID) > 0 {
				_, _ = intent.LeaveRoom(ce.Ctx, portal.MXID)
				_, _ = intent.ForgetRoom(ce.Ctx, portal.MXID)
			}
		}
	}
	ce.Reply("Found %d portals, deleting...", len(portalsToDelete))
	for _, portal := range portalsToDelete {
		portal.Delete()
		leave(portal)
	}
	ce.Reply("Finished deleting portal info. Now cleaning up rooms in background.")

	backgroundCtx := context.TODO()
	go func() {
		for _, portal := range portalsToDelete {
			portal.Cleanup(backgroundCtx, false)
		}
		ce.Reply("Finished background cleanup of deleted portal rooms.")
	}()
}

var cmdCleanupLostPortals = &commands.FullHandler{
	Func: wrapCommand(fnCleanupLostPortals),
	Name: "cleanup-lost-portals",
	Help: commands.HelpMeta{
		Section:     HelpSectionPortalManagement,
		Description: "Clean up portals that were discarded due to the receiver not being logged into the bridge",
	},
	RequiresAdmin: true,
}

func fnCleanupLostPortals(ce *WrappedCommandEvent) {
	portals, err := ce.Bridge.DB.LostPortal.GetAll(ce.Ctx)
	if err != nil {
		ce.Reply("Failed to get portals: %v", err)
		return
	} else if len(portals) == 0 {
		ce.Reply("No lost portals found")
		return
	}

	ce.Reply("Found %d lost portals, deleting...", len(portals))
	for _, portal := range portals {
		dmUUID, err := uuid.Parse(portal.ChatID)
		intent := ce.Bot
		if err == nil {
			intent = ce.Bridge.GetPuppetBySignalID(dmUUID).DefaultIntent()
		}
		ce.Bridge.CleanupRoom(ce.Ctx, ce.ZLog, intent, portal.MXID, false)
		err = portal.Delete(ce.Ctx)
		if err != nil {
			ce.ZLog.Err(err).Msg("Failed to delete lost portal from database after cleanup")
		}
	}
	ce.Reply("Finished cleaning up portals")
}

var cmdInviteLink = &commands.FullHandler{
	Func: wrapCommand(fnInviteLink),
	Name: "invite-link",
	Help: commands.HelpMeta{
		Section:     HelpSectionPortalManagement,
		Description: "Get the invite link for the corresponding Signal Group",
	},
	RequiresLogin: true,
}

func fnInviteLink(ce *WrappedCommandEvent) {
	if ce.Portal == nil {
		ce.Reply("This is not a portal room")
		return
	}
	if ce.Portal.IsPrivateChat() {
		ce.Reply("Invite Links are not available for private chats")
		return
	}
	inviteLinkPassword, err := ce.Portal.GetInviteLink(ce.Ctx, ce.User)
	if err != nil {
		ce.Reply("Error getting invite link %w", err)
		return
	}
	ce.Reply(inviteLinkPassword)
}

var cmdResetInviteLink = &commands.FullHandler{
	Func: wrapCommand(fnResetInviteLink),
	Name: "reset-invite-link",
	Help: commands.HelpMeta{
		Section:     HelpSectionPortalManagement,
		Description: "Generate a new invite link password",
	},
	RequiresLogin: true,
}

func fnResetInviteLink(ce *WrappedCommandEvent) {
	if ce.Portal == nil {
		ce.Reply("This is not a portal room")
		return
	}
	if ce.Portal.IsPrivateChat() {
		ce.Reply("Invite Links are not available for private chats")
		return
	}
	err := ce.Portal.ResetInviteLink(ce.Ctx, ce.User)
	if err != nil {
		ce.Reply("Error setting new invite link %w", err)
	}
	inviteLink, err := ce.Portal.GetInviteLink(ce.Ctx, ce.User)
	if err != nil {
		ce.Reply("Error getting new invite link %w", err)
		return
	}
	ce.Reply(inviteLink)
}

var cmdCreate = &commands.FullHandler{
	Func: wrapCommand(fnCreate),
	Name: "create",
	Help: commands.HelpMeta{
		Section:     HelpSectionCreatingPortals,
		Description: "Create a Signal group chat for the current Matrix room.",
	},
	RequiresLogin: true,
}

func fnCreate(ce *WrappedCommandEvent) {
	if ce.Portal != nil {
		ce.Reply("This is already a portal room")
		return
	}

	roomState, err := ce.Bot.State(ce.Ctx, ce.RoomID)
	if err != nil {
		ce.Reply("Failed to get room state: %w", err)
		return
	}
	members := roomState[event.StateMember]
	powerLevelsRaw, ok := roomState[event.StatePowerLevels][""]
	if !ok {
		ce.Reply("Failed to get room power levels")
		return
	}
	powerLevelsRaw.Content.ParseRaw(event.StatePowerLevels)
	powerLevels := powerLevelsRaw.Content.AsPowerLevels()
	joinRulesRaw, ok := roomState[event.StateJoinRules][""]
	if !ok {
		ce.Reply("Failed to get join rules")
		return
	}
	joinRulesRaw.Content.ParseRaw(event.StateJoinRules)
	joinRule := joinRulesRaw.Content.AsJoinRules().JoinRule
	roomNameEventRaw, ok := roomState[event.StateRoomName][""]
	if !ok {
		ce.Reply("Failed to get room name")
		return
	}
	roomNameEventRaw.Content.ParseRaw(event.StateRoomName)
	roomName := roomNameEventRaw.Content.AsRoomName().Name
	if len(roomName) == 0 {
		ce.Reply("Please set a name for the room first")
		return
	}
	roomTopic := ""
	roomTopicEvent, ok := roomState[event.StateTopic][""]
	if ok {
		roomTopicEvent.Content.ParseRaw(event.StateTopic)
		roomTopic = roomTopicEvent.Content.AsTopic().Topic
	}
	roomAvatarEvent, ok := roomState[event.StateRoomAvatar][""]
	var avatarHash string
	var avatarURL id.ContentURI
	var avatarBytes []byte
	if ok {
		roomAvatarEvent.Content.ParseRaw(event.StateRoomAvatar)
		avatarURL = roomAvatarEvent.Content.AsRoomAvatar().URL
		if !avatarURL.IsEmpty() {
			avatarBytes, err = ce.Bot.DownloadBytes(ce.Ctx, avatarURL)
			if err != nil {
				ce.ZLog.Err(err).Stringer("Failed to download updated avatar %s", avatarURL)
				return
			}
			hash := sha256.Sum256(avatarBytes)
			avatarHash = hex.EncodeToString(hash[:])
			log.Debug().Stringers("%s set the group avatar to %s", []fmt.Stringer{ce.User.MXID, avatarURL})
		}
	}
	var encryptionEvent *event.EncryptionEventContent
	encryptionEventContent, ok := roomState[event.StateEncryption][""]
	if ok {
		encryptionEventContent.Content.ParseRaw(event.StateEncryption)
		encryptionEvent = encryptionEventContent.Content.AsEncryption()
	}
	var participants []*signalmeow.GroupMember
	var bannedMembers []*signalmeow.BannedMember
	participantDedup := make(map[uuid.UUID]bool)
	participantDedup[uuid.Nil] = true
	for key, member := range members {
		mxid := id.UserID(key)
		member.Content.ParseRaw(event.StateMember)
		content := member.Content.AsMember()
		membership := content.Membership
		var uuid uuid.UUID
		puppet := ce.Bridge.GetPuppetByMXID(mxid)
		if puppet != nil {
			uuid = puppet.SignalID
		} else {
			user := ce.Bridge.GetUserByMXID(mxid)
			if user != nil && user.IsLoggedIn() {
				uuid = user.SignalID
			}
		}
		role := signalmeow.GroupMember_DEFAULT
		if powerLevels.GetUserLevel(mxid) >= 50 {
			role = signalmeow.GroupMember_ADMINISTRATOR
		}
		if !participantDedup[uuid] {
			participantDedup[uuid] = true
			// invites should be added on signal and then auto-joined
			// joined members that need to be pending-Members should have their signal invite auto-accepted
			if membership == event.MembershipJoin || membership == event.MembershipInvite {
				participants = append(participants, &signalmeow.GroupMember{
					UserID: uuid,
					Role:   role,
				})
			} else if membership == event.MembershipBan {
				bannedMembers = append(bannedMembers, &signalmeow.BannedMember{
					UserID: uuid,
				})
			}
		}
	}
	addFromInviteLinkAccess := signalmeow.AccessControl_UNSATISFIABLE
	if joinRule == event.JoinRulePublic {
		addFromInviteLinkAccess = signalmeow.AccessControl_ANY
	} else if joinRule == event.JoinRuleKnock {
		addFromInviteLinkAccess = signalmeow.AccessControl_ADMINISTRATOR
	}
	var inviteLinkPassword types.SerializedInviteLinkPassword
	if addFromInviteLinkAccess != signalmeow.AccessControl_UNSATISFIABLE {
		inviteLinkPassword = signalmeow.GenerateInviteLinkPassword()
	}
	membersAccess := signalmeow.AccessControl_MEMBER
	if powerLevels.Invite() >= 50 {
		membersAccess = signalmeow.AccessControl_ADMINISTRATOR
	}
	attributesAccess := signalmeow.AccessControl_MEMBER
	if powerLevels.StateDefault() >= 50 {
		attributesAccess = signalmeow.AccessControl_ADMINISTRATOR
	}
	announcementsOnly := false
	if powerLevels.EventsDefault >= 50 {
		announcementsOnly = true
	}
	ce.ZLog.Info().
		Str("room_name", roomName).
		Any("participants", participants).
		Msg("Creating Signal group for Matrix room")
	group, err := ce.User.Client.CreateGroupOnServer(ce.Ctx, &signalmeow.Group{
		Title:       roomName,
		Description: roomTopic,
		Members:     participants,
		AccessControl: &signalmeow.GroupAccessControl{
			Members:           membersAccess,
			Attributes:        attributesAccess,
			AddFromInviteLink: addFromInviteLinkAccess,
		},
		InviteLinkPassword: &inviteLinkPassword,
		BannedMembers:      bannedMembers,
		AnnouncementsOnly:  announcementsOnly,
	}, avatarBytes)
	if err != nil {
		ce.Reply("Failed to create group: %v", err)
		return
	}
	gid := group.GroupIdentifier
	ce.ZLog.UpdateContext(func(c zerolog.Context) zerolog.Context {
		return c.Stringer("group_id", gid)
	})
	portal := ce.User.GetPortalByChatID(gid.String())
	portal.roomCreateLock.Lock()
	defer portal.roomCreateLock.Unlock()
	if len(portal.MXID) != 0 {
		ce.ZLog.Warn().Msg("Detected race condition in room creation")
		// TODO race condition, clean up the old room
	}
	portal.MXID = ce.RoomID
	portal.Name = roomName
	portal.Encrypted = encryptionEvent.Algorithm == id.AlgorithmMegolmV1
	if !portal.Encrypted && ce.Bridge.Config.Bridge.Encryption.Default {
		_, err = portal.MainIntent().SendStateEvent(ce.Ctx, portal.MXID, event.StateEncryption, "", portal.GetEncryptionEventContent())
		if err != nil {
			ce.ZLog.Err(err).Msg("Failed to enable encryption in room")
			if errors.Is(err, mautrix.MForbidden) {
				ce.Reply("I don't seem to have permission to enable encryption in this room.")
			} else {
				ce.Reply("Failed to enable encryption in room: %v", err)
			}
		}
		portal.Encrypted = true
	}
	revision, err := ce.User.Client.UpdateGroup(ce.Ctx, &signalmeow.GroupChange{}, gid)
	if err != nil {
		ce.Reply("Failed to update Group")
		return
	}
	portal.Revision = revision
	portal.AvatarHash = avatarHash
	portal.AvatarURL = avatarURL
	portal.AvatarPath = group.AvatarPath
	portal.AvatarSet = true
	err = portal.Update(ce.Ctx)
	if err != nil {
		ce.ZLog.Err(err).Msg("Failed to save portal after creating group")
	}
	portal.UpdateBridgeInfo(ce.Ctx)
	ce.Reply("Successfully created Signal group %s", gid.String())
}
