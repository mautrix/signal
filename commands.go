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
	"strings"

	"github.com/skip2/go-qrcode"
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
		cmdDeleteSession,
		cmdSetRelay,
		cmdUnsetRelay,
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
		ce.Portal.Update()
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
		ce.Portal.Update()
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
	if !ce.User.SignalDevice.IsDeviceLoggedIn() {
		ce.Reply("You're not logged in")
		return
	}
	ce.User.SignalDevice.ClearKeysAndDisconnect()
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
	if ce.User.SignalID == "" {
		ce.Reply("You're not logged in")
	} else if !ce.User.SignalDevice.IsDeviceLoggedIn() {
		ce.Reply("You were logged in at some point, but are not anymore")
	} else if !ce.User.SignalDevice.Connection.IsConnected() {
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
	err := ce.User.SignalDevice.UpdateDeviceName(name)
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
	contact, err := user.SignalDevice.ContactByE164(number)
	if err != nil {
		ce.Reply("Error looking up number in local contact list: %v", err)
		return
	}
	if contact == nil {
		ce.Reply("The bridge does not have the Signal ID for the number %s", number)
		return
	}

	portal := user.GetPortalByChatID(contact.UUID)
	if portal == nil {
		ce.Reply("Error creating portal to %s", number)
		ce.Log.Errorln("Error creating portal to", number)
		return
	}
	if portal.MXID != "" {
		ce.Reply("You already have a portal to %s at %s", number, portal.MXID)
		return
	}
	if err := portal.CreateMatrixRoom(user, nil); err != nil {
		ce.Reply("Error creating Matrix room for portal to %s", number)
		ce.Log.Errorln("Error creating Matrix room for portal to %s: %s", number, err)
		return
	}
	ce.Reply("Created portal room with and invited you to it.")
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

	var qrEventID id.EventID
	var signalID string
	var signalUsername string

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
		qrEventID = ce.User.sendQR(ce, resp.ProvisioningUrl, qrEventID)
	} else {
		ce.Reply("Unexpected state: %v", resp.State)
		return
	}

	// Next, get the results of finishing registration
	resp = <-provChan
	_, _ = ce.Bot.RedactEvent(ce.RoomID, qrEventID)
	if resp.Err != nil || resp.State == signalmeow.StateProvisioningError {
		if resp.Err != nil && strings.HasSuffix(resp.Err.Error(), " EOF") {
			ce.Reply("Logging in timed out, please try again.")
		} else {
			ce.Reply("Error finishing registration: %v", resp.Err)
		}
		return
	}
	if resp.State == signalmeow.StateProvisioningDataReceived {
		signalID = resp.ProvisioningData.AciUuid
		signalUsername = resp.ProvisioningData.Number
		ce.Reply("Successfully logged in!")
		ce.Reply("ACI: %v, Phone Number: %v", resp.ProvisioningData.AciUuid, resp.ProvisioningData.Number)
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
	if signalID != "" {
		ce.User.SignalID = signalID
		ce.User.SignalUsername = signalUsername
	} else {
		ce.Reply("Problem logging in - No SignalID received")
		return
	}
	ce.User.Update()

	// Connect to Signal
	ce.User.Connect()
}

func (user *User) sendQR(ce *WrappedCommandEvent, code string, prevEvent id.EventID) id.EventID {
	url, ok := user.uploadQR(ce, code)
	if !ok {
		return prevEvent
	}
	content := event.MessageEventContent{
		MsgType: event.MsgImage,
		Body:    code,
		URL:     url.CUString(),
	}
	if len(prevEvent) != 0 {
		content.SetEdit(prevEvent)
	}
	resp, err := ce.Bot.SendMessageEvent(ce.RoomID, event.EventMessage, &content)
	if err != nil {
		ce.Log.Errorln("Failed to send QR code to user:", err)
	} else if len(prevEvent) == 0 {
		prevEvent = resp.EventID
	}
	return prevEvent
}

func (user *User) uploadQR(ce *WrappedCommandEvent, code string) (id.ContentURI, bool) {
	qrCode, err := qrcode.Encode(code, qrcode.Low, 256)
	if err != nil {
		ce.Log.Errorln("Failed to encode QR code:", err)
		ce.Reply("Failed to encode QR code: %v", err)
		return id.ContentURI{}, false
	}

	bot := user.bridge.AS.BotClient()

	resp, err := bot.UploadBytes(qrCode, "image/png")
	if err != nil {
		ce.Log.Errorln("Failed to upload QR code:", err)
		ce.Reply("Failed to upload QR code: %v", err)
		return id.ContentURI{}, false
	}
	return resp.ContentURI, true
}
