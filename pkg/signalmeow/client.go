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
	"net/url"
	"sync"
	"time"

	"github.com/rs/zerolog"

	"go.mau.fi/mautrix-signal/pkg/libsignalgo"
	"go.mau.fi/mautrix-signal/pkg/signalmeow/events"
	"go.mau.fi/mautrix-signal/pkg/signalmeow/store"
	"go.mau.fi/mautrix-signal/pkg/signalmeow/web"
)

type Client struct {
	Store *store.Device
	Log   zerolog.Logger

	SenderCertificateWithE164 *libsignalgo.SenderCertificate
	SenderCertificateNoE164   *libsignalgo.SenderCertificate
	GroupCredentials          *GroupCredentials
	GroupCache                *GroupCache
	ProfileCache              *ProfileCache
	GroupCallCache            *map[string]bool
	LastContactRequestTime    time.Time
	SyncContactsOnConnect     bool

	encryptionLock sync.Mutex

	AuthedWS             *web.SignalWebsocket
	UnauthedWS           *web.SignalWebsocket
	lastConnectionStatus SignalConnectionStatus

	loopCancel context.CancelFunc
	loopWg     sync.WaitGroup

	EventHandler func(events.SignalEvent) bool

	storageAuthLock sync.Mutex
	storageAuth     *basicExpiringCredentials
	cdAuthLock      sync.Mutex
	cdAuth          *basicExpiringCredentials
	cdToken         []byte

	writeCallbackCounter chan time.Time
}

func (cli *Client) handleEvent(evt events.SignalEvent) bool {
	return cli.EventHandler(evt)
}

func (cli *Client) IsConnected() bool {
	if cli == nil {
		return false
	}
	return cli.AuthedWS.IsConnected() && cli.UnauthedWS.IsConnected()
}

func (cli *Client) connectAuthedWS(ctx context.Context, requestHandler web.RequestHandlerFunc) (chan web.SignalWebsocketConnectionStatus, error) {
	if cli.AuthedWS != nil {
		return nil, errors.New("authed websocket already connected")
	}

	username, password := cli.Store.BasicAuthCreds()
	log := zerolog.Ctx(ctx).With().
		Str("websocket_type", "authed").
		Str("username", username).
		Logger()
	ctx = log.WithContext(ctx)
	authedWS := web.NewSignalWebsocket(url.UserPassword(username, password))
	statusChan := authedWS.Connect(ctx, requestHandler)
	cli.AuthedWS = authedWS
	return statusChan, nil
}

func (cli *Client) connectUnauthedWS(ctx context.Context) (chan web.SignalWebsocketConnectionStatus, error) {
	if cli.UnauthedWS != nil {
		return nil, errors.New("unauthed websocket already connected")
	}

	log := zerolog.Ctx(ctx).With().
		Str("websocket_type", "unauthed").
		Logger()
	ctx = log.WithContext(ctx)
	unauthedWS := web.NewSignalWebsocket(nil)
	statusChan := unauthedWS.Connect(ctx, nil)
	cli.UnauthedWS = unauthedWS
	return statusChan, nil
}

func (cli *Client) IsLoggedIn() bool {
	return cli.Store != nil && cli.Store.IsDeviceLoggedIn()
}
