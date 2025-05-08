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

package connector

import (
	"context"
	"fmt"
	"strconv"
	"text/template"
	"time"

	"github.com/google/uuid"
	"go.mau.fi/util/dbutil"
	"go.mau.fi/util/exsync"
	"maunium.net/go/mautrix/bridgev2"
	"maunium.net/go/mautrix/bridgev2/networkid"
	"maunium.net/go/mautrix/event"
	"maunium.net/go/mautrix/id"

	"go.mau.fi/mautrix-signal/pkg/msgconv"
	"go.mau.fi/mautrix-signal/pkg/signalmeow"
	"go.mau.fi/mautrix-signal/pkg/signalmeow/store"
)

type SignalConnector struct {
	MsgConv *msgconv.MessageConverter
	Store   *store.Container
	Bridge  *bridgev2.Bridge
	Config  SignalConfig
}

var _ bridgev2.NetworkConnector = (*SignalConnector)(nil)
var _ bridgev2.MaxFileSizeingNetwork = (*SignalConnector)(nil)
var _ bridgev2.TransactionIDGeneratingNetwork = (*SignalConnector)(nil)

func (s *SignalConnector) GetName() bridgev2.BridgeName {
	return bridgev2.BridgeName{
		DisplayName:      "Signal",
		NetworkURL:       "https://signal.org",
		NetworkIcon:      "mxc://maunium.net/wPJgTQbZOtpBFmDNkiNEMDUp",
		NetworkID:        "signal",
		BeeperBridgeType: "signal",
		DefaultPort:      29328,
	}
}

func (s *SignalConnector) Init(bridge *bridgev2.Bridge) {
	var err error
	s.Config.displaynameTemplate, err = template.New("displayname").Parse(s.Config.DisplaynameTemplate)
	if err != nil {
		// TODO return error or do this later?
		panic(err)
	}
	s.Store = store.NewStore(bridge.DB.Database, dbutil.ZeroLogger(bridge.Log.With().Str("db_section", "signalmeow").Logger()))
	s.Bridge = bridge
	s.MsgConv = msgconv.NewMessageConverter(bridge)
	s.MsgConv.LocationFormat = s.Config.LocationFormat
	s.MsgConv.DisappearViewOnce = s.Config.DisappearViewOnce
}

func (s *SignalConnector) SetMaxFileSize(maxSize int64) {
	s.MsgConv.MaxFileSize = maxSize
}

func (s *SignalConnector) Start(ctx context.Context) error {
	err := s.Store.Upgrade(ctx)
	if err != nil {
		return bridgev2.DBUpgradeError{Err: err, Section: "signalmeow"}
	}
	return nil
}

func (s *SignalConnector) LoadUserLogin(ctx context.Context, login *bridgev2.UserLogin) error {
	aci, err := uuid.Parse(string(login.ID))
	if err != nil {
		return fmt.Errorf("failed to parse user login ID: %w", err)
	}
	device, err := s.Store.DeviceByACI(ctx, aci)
	if err != nil {
		return fmt.Errorf("failed to get device from store: %w", err)
	}
	sc := &SignalClient{
		Main:      s,
		UserLogin: login,

		queueEmptyWaiter: exsync.NewEvent(),
	}
	if device != nil {
		sc.Client = &signalmeow.Client{
			Store:        device,
			Log:          sc.UserLogin.Log.With().Str("component", "signalmeow").Logger(),
			EventHandler: sc.handleSignalEvent,

			SyncContactsOnConnect: s.Config.SyncContactsOnStartup,
		}
	}
	login.Client = sc
	return nil
}

func (s *SignalConnector) GenerateTransactionID(userID id.UserID, roomID id.RoomID, eventType event.Type) networkid.RawTransactionID {
	return networkid.RawTransactionID(strconv.FormatInt(time.Now().UnixMilli(), 10))
}
