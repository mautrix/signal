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
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"

	"github.com/rs/zerolog"
	"go.mau.fi/util/exsync"

	"go.mau.fi/mautrix-signal/pkg/libsignalgo"
	"go.mau.fi/mautrix-signal/pkg/signalmeow/events"
	signalpb "go.mau.fi/mautrix-signal/pkg/signalmeow/protobuf"
	"go.mau.fi/mautrix-signal/pkg/signalmeow/store"
	"go.mau.fi/mautrix-signal/pkg/signalmeow/types"
	"go.mau.fi/mautrix-signal/pkg/signalmeow/web"
)

type Client struct {
	Store *store.Device
	Log   zerolog.Logger

	senderCertificateWithE164 *libsignalgo.SenderCertificate
	senderCertificateNoE164   *libsignalgo.SenderCertificate
	senderCertificateCache    sync.Mutex

	sendCache *exsync.RingBuffer[sendCacheKey, *signalpb.Content]

	GroupCache             *GroupCache
	ProfileCache           *ProfileCache
	LastContactRequestTime time.Time
	SyncContactsOnConnect  bool

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

// InMemorySendCacheSize specifies how large the cache for sent messages is, which is used to respond to retry receipts.
// The cache is large because every group member will be listed separately.
// 2k entries should hold at least 2 messages in max size groups.
var InMemorySendCacheSize = 2048

func NewClient(device *store.Device, log zerolog.Logger, evtHandler func(events.SignalEvent) bool) *Client {
	return &Client{
		Store:        device,
		Log:          log,
		EventHandler: evtHandler,
		GroupCache:   NewGroupCache(device.ACIServiceID()),
		ProfileCache: &ProfileCache{
			profiles:    make(map[string]*types.Profile),
			errors:      make(map[string]*error),
			lastFetched: make(map[string]time.Time),
		},
		sendCache: exsync.NewRingBuffer[sendCacheKey, *signalpb.Content](InMemorySendCacheSize),
	}
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

func (cli *Client) GetRemoteConfig(ctx context.Context) (json.RawMessage, error) {
	resp, err := cli.AuthedWS.SendRequest(ctx, http.MethodGet, "/v2/config", nil, nil)
	if err != nil {
		return nil, err
	}
	return resp.Body, web.DecodeWSResponseBody(ctx, nil, resp)
}

func (cli *Client) EnsureSelfSession(ctx context.Context) error {
	dev := cli.Store
	if dev == nil {
		return nil
	}

	serviceID := dev.ACIServiceID()
	sessionStore := dev.SessionStore(serviceID)

	// Check if we have any linked devices
	sessions, err := sessionStore.AllSessionsForServiceID(ctx, serviceID)
	if err == nil && len(sessions) > 0 {
		// Self-sessions already exist
		cli.Log.Debug().
			Int("session_count", len(sessions)).
			Msg("Self-sessions already exist")
		return nil
	}

	cli.Log.Info().
		Int("device_id", dev.DeviceID).
		Msg("Bootstrapping self-session for linked device")

	// Fetch pre-keys for all devices on our account
	// This will include Device 1 (primary) and other linked devices
	err = cli.FetchAndProcessPreKey(ctx, serviceID, -1)
	if err != nil {
		// Check if error is about processing our own device's pre-key
		// This is expected and safe to ignore
		ownDeviceStr := fmt.Sprintf("device %d", dev.DeviceID)
		if !strings.Contains(err.Error(), ownDeviceStr) {
			return fmt.Errorf("failed to establish self-sessions: %w", err)
		}
		cli.Log.Debug().
			Err(err).
			Msg("Ignoring expected error for own device pre-key processing")
	}

	// Verify sessions were created
	sessions, err = sessionStore.AllSessionsForServiceID(ctx, serviceID)
	if err != nil {
		return fmt.Errorf("failed to verify self-sessions: %w", err)
	}

	if len(sessions) == 0 {
		return fmt.Errorf("no self-sessions created - linked device may not have Device 1 registered")
	}

	cli.Log.Info().
		Int("session_count", len(sessions)).
		Msg("Self-sessions successfully established")

	return nil
}
