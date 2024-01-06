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
	"fmt"
	"strings"

	"github.com/google/uuid"
	"github.com/skip2/go-qrcode"
	"maunium.net/go/mautrix"
	"maunium.net/go/mautrix/bridge/commands"
	"maunium.net/go/mautrix/event"
	"maunium.net/go/mautrix/id"

	"go.mau.fi/mautrix-signal/pkg/signalmeow"
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
		cmdSyncSpace,
		cmdDeleteSession,
		cmdSetRelay,
		cmdUnsetRelay,
		cmdDeletePortal,
		cmdDeleteAllPortals,
		cmdCleanupLostPortals,
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
	err := ce.User.Client.UpdateDeviceName(name)
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

func fnPM(ce *WrappedCommandEvent) {
	if len(ce.Args) == 0 {
		ce.Reply("**Usage:** `pm <international phone number>`")
		return
	}

	user := ce.User
	number := strings.Join(ce.Args, "")
	contact, err := user.Client.ContactByE164(ce.Ctx, number)
	if err != nil {
		ce.Reply("Error looking up number in local contact list: %v", err)
		return
	}
	if contact == nil {
		ce.Reply("The bridge does not have the Signal ID for the number %s", number)
		return
	}

	portal := user.GetPortalByChatID(contact.UUID.String())
	if portal == nil {
		ce.Reply("Error creating portal to %s", number)
		ce.Log.Errorln("Error creating portal to", number)
		return
	}
	if portal.MXID != "" {
		ce.Reply("You already have a portal to %s at %s", number, portal.MXID)
		return
	}
	if err := portal.CreateMatrixRoom(ce.Ctx, user, 0); err != nil {
		ce.Reply("Error creating Matrix room for portal to %s", number)
		ce.Log.Errorln("Error creating Matrix room for portal to %s: %s", number, err)
		return
	}
	ce.Reply("Created portal room with and invited you to it.")
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
		if ce.Bridge.StateStore.IsInRoom(portal.MXID, ce.User.MXID) && portal.addToPersonalSpace(ctx, ce.User) {
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
	//if ce.User.Session != nil {
	//	if ce.User.IsConnected() {
	//		ce.Reply("You're already logged in")
	//	} else {
	//		ce.Reply("You're already logged in. Perhaps you wanted to `reconnect`?")
	//	}
	//	return
	//}

	var qrEventID, msgEventID id.EventID
	var signalID uuid.UUID
	var signalPhone string

	// First get the provisioning URL
	provChan, err := ce.User.Login()
	if err != nil {
		ce.Log.Errorln("Failure logging in:", err)
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
		ce.Reply("Successfully logged in!")
		ce.Reply("ACI: %v, Phone Number: %v", resp.ProvisioningData.ACI, resp.ProvisioningData.Number)
	} else {
		ce.Reply("Unexpected state: %v", resp.State)
		return
	}

	// Finally, get the results of generating and registering prekeys
	resp = <-provChan
	if resp.Err != nil || resp.State == signalmeow.StateProvisioningError {
		ce.Reply("Error with prekeys: %v", resp.Err)
		return
	}
	if resp.State == signalmeow.StateProvisioningPreKeysRegistered {
		ce.Reply("Successfully generated, registered and stored prekeys! 🎉")
	} else {
		ce.Reply("Unexpected state: %v", resp.State)
		return
	}

	// Update user with SignalID
	if signalID != uuid.Nil {
		ce.User.SignalID = signalID
		ce.User.SignalUsername = signalPhone
	} else {
		ce.Reply("Problem logging in - No SignalID received")
		return
	}
	err = ce.User.Update(ce.Ctx)
	if err != nil {
		ce.ZLog.Err(err).Msg("Failed to save user to database")
	}

	// Connect to Signal
	ce.User.Connect()
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
		ce.Log.Errorln("Failed to send QR code to user:", err)
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
		ce.Log.Errorln("Failed to send raw code to user:", err)
	} else if len(prevMsg) == 0 {
		prevMsg = resp.EventID
	}
	return prevQR, prevMsg
}

func (user *User) uploadQR(ce *WrappedCommandEvent, code string) (event.MessageEventContent, bool) {
	const size = 512
	qrCode, err := qrcode.Encode(code, qrcode.Low, size)
	if err != nil {
		ce.Log.Errorln("Failed to encode QR code:", err)
		ce.Reply("Failed to encode QR code: %v", err)
		return event.MessageEventContent{}, false
	}

	bot := user.bridge.AS.BotClient()

	resp, err := bot.UploadBytes(ce.Ctx, qrCode, "image/png")
	if err != nil {
		ce.Log.Errorln("Failed to upload QR code:", err)
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
			Str("user_id", userID.String()).
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
