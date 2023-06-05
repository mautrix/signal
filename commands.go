package main

import (
	"log"

	"github.com/skip2/go-qrcode"
	"go.mau.fi/mautrix-signal/pkg/signalmeow"
	"maunium.net/go/mautrix/bridge/commands"
	"maunium.net/go/mautrix/event"
	"maunium.net/go/mautrix/id"
)

type WrappedCommandEvent struct {
	*commands.Event
	Bridge *SignalBridge
	User   *User
	Portal *Portal
}

var HelpSectionPortalManagement = commands.HelpSection{Name: "Portal management", Order: 20}

func (br *SignalBridge) RegisterCommands() {
	proc := br.CommandProcessor.(*commands.Processor)
	proc.AddHandlers(
		cmdPing,
		cmdLogin,
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

var cmdPing = &commands.FullHandler{
	Func: wrapCommand(fnPing),
	Name: "ping",
	Help: commands.HelpMeta{
		Section:     commands.HelpSectionAuth,
		Description: "Check your connection to Signal",
	},
}

func fnPing(ce *WrappedCommandEvent) {
	ce.Reply("A fake ping! Well done! 💥")
}

var cmdLogin = &commands.FullHandler{
	Func: wrapCommand(fnLogin),
	Name: "login",
	Help: commands.HelpMeta{
		Section:     commands.HelpSectionAuth,
		Description: "Link the bridge to your WhatsApp account as a web client.",
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

	// First get the provisioning URL
	provChan, err := ce.User.Login()
	if err != nil {
		ce.Log.Errorln("Failure logging in:", err)
		ce.Reply("Failure logging in: %v", err)
		return
	}

	resp := <-provChan
	if resp.Err != nil || resp.State == signalmeow.StateProvisioningError {
		log.Printf("Error getting provisioning URL: %v", resp.Err)
		ce.Reply("Error getting provisioning URL: %v", resp.Err)
		return
	}
	if resp.State == signalmeow.StateProvisioningURLReceived {
		qrEventID = ce.User.sendQR(ce, resp.ProvisioningUrl, qrEventID)
	} else {
		log.Printf("Unexpected state: %v", resp.State)
		ce.Reply("Unexpected state: %v", resp.State)
		return
	}

	// Next, get the results of finishing registration
	resp = <-provChan
	if resp.Err != nil || resp.State == signalmeow.StateProvisioningError {
		log.Printf("Error finishing registration: %v", resp.Err)
		ce.Reply("Error finishing registration: %v", resp.Err)
		return
	}
	if resp.State == signalmeow.StateProvisioningDataReceived {
		log.Printf("provisioningData: %v", resp.ProvisioningData)
		signalID = resp.ProvisioningData.AciUuid
		ce.Reply("Successfully logged in!")
		ce.Reply("ACI: %v, Phone Number: %v", resp.ProvisioningData.AciUuid, resp.ProvisioningData.Number)
		_, _ = ce.Bot.RedactEvent(ce.RoomID, qrEventID)
	} else {
		log.Printf("Unexpected state: %v", resp.State)
		ce.Reply("Unexpected state: %v", resp.State)
		return
	}

	// Finally, get the results of generating and registering prekeys
	resp = <-provChan
	if resp.Err != nil || resp.State == signalmeow.StateProvisioningError {
		log.Printf("Error with prekeys: %v", resp.Err)
		ce.Reply("Error with prekeys: %v", resp.Err)
		return
	}
	if resp.State == signalmeow.StateProvisioningPreKeysRegistered {
		ce.Reply("Successfully generated, registered and stored prekeys! 🎉")
	} else {
		log.Printf("Unexpected state: %v", resp.State)
		ce.Reply("Unexpected state: %v", resp.State)
		return
	}

	// Update user with SignalID
	if signalID != "" {
		ce.User.SignalID = signalID
	} else {
		log.Printf("No SignalID received")
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
