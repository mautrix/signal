// mautrix-signal - A Matrix-Signal puppeting bridge.
// Copyright (C) 2024 Tulir Asokan
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
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/skip2/go-qrcode"
	"go.mau.fi/util/dbutil"
	"go.mau.fi/util/exerrors"
	"go.mau.fi/util/exzerolog"
	"gopkg.in/yaml.v3"

	"go.mau.fi/mautrix-signal/pkg/signalmeow"
	"maunium.net/go/mautrix/bridgev2"
	"maunium.net/go/mautrix/bridgev2/bridgeconfig"
	"maunium.net/go/mautrix/bridgev2/database"
	"maunium.net/go/mautrix/bridgev2/matrix"
	"maunium.net/go/mautrix/bridgev2/networkid"
	"maunium.net/go/mautrix/event"
	"maunium.net/go/mautrix/id"

	"go.mau.fi/mautrix-signal/connector"
)

func main() {
	var cfg bridgeconfig.Config
	config := exerrors.Must(os.ReadFile("config.yaml"))
	exerrors.PanicIfNotNil(yaml.Unmarshal(config, &cfg))
	log := exerrors.Must(cfg.Logging.Compile())
	exzerolog.SetupDefaults(log)
	db := exerrors.Must(dbutil.NewFromConfig("mautrix-signal", cfg.Database, dbutil.ZeroLogger(log.With().Str("db_section", "main").Logger())))
	signalConnector := connector.NewConnector()
	exerrors.PanicIfNotNil(cfg.Network.Decode(signalConnector.Config))
	bridge := bridgev2.NewBridge("", db, *log, matrix.NewConnector(&cfg), signalConnector)
	bridge.CommandPrefix = "!signal"
	bridge.Commands.AddHandlers(&bridgev2.FullHandler{
		Func: fnLogin,
		Name: "login",
		Help: bridgev2.HelpMeta{
			Section:     bridgev2.HelpSectionAuth,
			Description: "Log into Signal",
		},
	})
	bridge.Start()
}

func sendQR(ce *bridgev2.CommandEvent, code string, prevQR, prevMsg id.EventID) (qr, msg id.EventID) {
	content, ok := uploadQR(ce, code)
	if !ok {
		return prevQR, prevMsg
	}
	if len(prevQR) != 0 {
		content.SetEdit(prevQR)
	}
	resp, err := ce.Bot.SendMessage(ce.Ctx, ce.RoomID, event.EventMessage, &event.Content{Parsed: &content}, time.Now())
	if err != nil {
		ce.Log.Err(err).Msg("Failed to send QR code to user")
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
	resp, err = ce.Bot.SendMessage(ce.Ctx, ce.RoomID, event.EventMessage, &event.Content{Parsed: &content}, time.Now())
	if err != nil {
		ce.Log.Err(err).Msg("Failed to send raw code to user")
	} else if len(prevMsg) == 0 {
		prevMsg = resp.EventID
	}
	return prevQR, prevMsg
}

func uploadQR(ce *bridgev2.CommandEvent, code string) (event.MessageEventContent, bool) {
	const size = 512
	qrCode, err := qrcode.Encode(code, qrcode.Low, size)
	if err != nil {
		ce.Log.Err(err).Msg("Failed to encode QR code")
		ce.Reply("Failed to encode QR code: %v", err)
		return event.MessageEventContent{}, false
	}

	uri, file, err := ce.Bot.UploadMedia(ce.Ctx, ce.RoomID, qrCode, "qr.png", "image/png")
	if err != nil {
		ce.Log.Err(err).Msg("Failed to upload QR code")
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
		URL:  uri,
		File: file,
	}, true
}
func fnLogin(ce *bridgev2.CommandEvent) {
	signal := ce.Bridge.Network.(*connector.SignalConnector)
	// TODO configurable device name
	provChan := signalmeow.PerformProvisioning(ce.Ctx, signal.Store, "Mautrix-Signal Megabridge")

	resp := <-provChan
	if resp.Err != nil || resp.State == signalmeow.StateProvisioningError {
		ce.Reply("Error getting provisioning URL: %v", resp.Err)
		return
	}
	var qrEventID, msgEventID id.EventID
	if resp.State == signalmeow.StateProvisioningURLReceived {
		qrEventID, msgEventID = sendQR(ce, resp.ProvisioningURL, qrEventID, msgEventID)
	} else {
		ce.Reply("Unexpected state: %v", resp.State)
		return
	}

	// Next, get the results of finishing registration
	resp = <-provChan
	_, _ = ce.Bot.SendMessage(ce.Ctx, ce.RoomID, event.EventRedaction, &event.Content{
		Parsed: &event.RedactionEventContent{
			Redacts: qrEventID,
		},
	}, time.Now())
	_, _ = ce.Bot.SendMessage(ce.Ctx, ce.RoomID, event.EventRedaction, &event.Content{
		Parsed: &event.RedactionEventContent{
			Redacts: msgEventID,
		},
	}, time.Now())
	if resp.Err != nil || resp.State == signalmeow.StateProvisioningError {
		if resp.Err != nil && strings.HasSuffix(resp.Err.Error(), " EOF") {
			ce.Reply("Logging in timed out, please try again.")
		} else {
			ce.Reply("Error finishing registration: %v", resp.Err)
		}
		return
	}
	var signalID uuid.UUID
	var signalPhone string
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
	ul, err := ce.User.NewLogin(ce.Ctx, &database.UserLogin{
		ID: networkid.UserLoginID(signalID.String()),
		Metadata: map[string]any{
			"phone": signalPhone,
		},
	}, nil)
	if err != nil {
		ce.Reply("Failed to save new login: %v", err)
		return
	}
	err = ce.Bridge.Network.PrepareLogin(ce.Ctx, ul)
	if err != nil {
		ce.Reply("Failed to prepare connection after login: %v", err)
		return
	}
	err = ul.Client.Connect(ce.Ctx)
	if err != nil {
		ce.Reply("Failed to connect after login: %v", err)
		return
	}
	ce.Reply("Successfully logged in as %s (UUID: %s)", signalPhone, signalID)
}
