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

package signalmeow

import (
	"context"
	"errors"
	"fmt"
	"net/url"
	"sync"

	"github.com/rs/zerolog"
	"go.mau.fi/mautrix-signal/pkg/libsignalgo"
	"go.mau.fi/mautrix-signal/pkg/signalmeow/events"
	"go.mau.fi/mautrix-signal/pkg/signalmeow/web"
)

// Note: right now, the parent `Device` struct is in store.go
type DeviceData struct {
	AciIdentityKeyPair *libsignalgo.IdentityKeyPair
	PniIdentityKeyPair *libsignalgo.IdentityKeyPair
	RegistrationId     int
	PniRegistrationId  int
	AciUuid            string
	PniUuid            string
	DeviceId           int
	Number             string
	Password           string
}

func (d *DeviceData) BasicAuthCreds() (string, string) {
	username := fmt.Sprintf("%s.%d", d.AciUuid, d.DeviceId)
	password := d.Password
	return username, password
}

// DeviceConnection exists on a Device, and holds websockets, cached credentials,
// and other data that is used to communicate with the Signal servers and other clients.
type DeviceConnection struct {
	// cached data (not persisted)
	SenderCertificate      *libsignalgo.SenderCertificate
	GroupCredentials       *GroupCredentials
	GroupCache             *GroupCache
	ProfileCache           *ProfileCache
	GroupCallCache         *map[string]bool
	LastContactRequestTime *int64

	// mutexes
	EncryptionMutex sync.Mutex

	// Network interfaces
	AuthedWS   *web.SignalWebsocket
	UnauthedWS *web.SignalWebsocket
	WSCancel   context.CancelFunc

	EventHandler func(events.SignalEvent)
}

func (d *DeviceConnection) handleEvent(evt events.SignalEvent) {
	if d.EventHandler != nil {
		d.EventHandler(evt)
	}
}

func (d *DeviceConnection) IsConnected() bool {
	if d == nil {
		return false
	}
	return d.AuthedWS.IsConnected() && d.UnauthedWS.IsConnected()
}

func (d *DeviceConnection) ConnectAuthedWS(ctx context.Context, data DeviceData, requestHandler web.RequestHandlerFunc) (chan web.SignalWebsocketConnectionStatus, error) {
	if d.AuthedWS != nil {
		return nil, errors.New("authed websocket already connected")
	}

	username, password := data.BasicAuthCreds()
	log := zerolog.Ctx(ctx).With().
		Str("websocket_type", "authed").
		Str("username", username).
		Logger()
	ctx = log.WithContext(ctx)
	username = url.QueryEscape(username)
	password = url.QueryEscape(password)
	path := web.WebsocketPath +
		"?login=" + username +
		"&password=" + password
	authedWS := web.NewSignalWebsocket(path, &username, &password)
	statusChan := authedWS.Connect(ctx, &requestHandler)
	d.AuthedWS = authedWS
	return statusChan, nil
}

func (d *DeviceConnection) ConnectUnauthedWS(ctx context.Context, data DeviceData) (chan web.SignalWebsocketConnectionStatus, error) {
	if d.UnauthedWS != nil {
		return nil, errors.New("unauthed websocket already connected")
	}

	log := zerolog.Ctx(ctx).With().
		Str("websocket_type", "unauthed").
		Logger()
	ctx = log.WithContext(ctx)
	unauthedWS := web.NewSignalWebsocket(web.WebsocketPath, nil, nil)
	statusChan := unauthedWS.Connect(ctx, nil)
	d.UnauthedWS = unauthedWS
	return statusChan, nil
}
