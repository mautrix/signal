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
	"text/template"
	"time"

	"github.com/google/uuid"
	"github.com/rs/zerolog"
	"go.mau.fi/util/dbutil"
	"maunium.net/go/mautrix/bridgev2"
	"maunium.net/go/mautrix/bridgev2/database"
	"maunium.net/go/mautrix/bridgev2/networkid"
	"maunium.net/go/mautrix/id"

	"go.mau.fi/mautrix-signal/msgconv"
	"go.mau.fi/mautrix-signal/msgconv/matrixfmt"
	"go.mau.fi/mautrix-signal/msgconv/signalfmt"
	"go.mau.fi/mautrix-signal/pkg/signalmeow"
	"go.mau.fi/mautrix-signal/pkg/signalmeow/store"
)

type SignalConnector struct {
	MsgConv *msgconv.MessageConverter
	Store   *store.Container
	Bridge  *bridgev2.Bridge
	Config  *SignalConfig
}

var _ bridgev2.NetworkConnector = (*SignalConnector)(nil)
var _ bridgev2.MaxFileSizeingNetwork = (*SignalConnector)(nil)

func NewConnector() *SignalConnector {
	return &SignalConnector{
		Config: &SignalConfig{},
	}
}

var signalGeneralCaps = &bridgev2.NetworkGeneralCapabilities{
	DisappearingMessages: true,
	AggressiveUpdateInfo: true,
}

func (s *SignalConnector) GetCapabilities() *bridgev2.NetworkGeneralCapabilities {
	return signalGeneralCaps
}

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
	s.MsgConv = &msgconv.MessageConverter{
		PortalMethods: &msgconvPortalMethods{},
		SignalFmtParams: &signalfmt.FormatParams{
			GetUserInfo: func(ctx context.Context, uuid uuid.UUID) signalfmt.UserInfo {
				ghost, err := s.Bridge.GetGhostByID(ctx, makeUserID(uuid))
				if err != nil {
					// TODO log?
					return signalfmt.UserInfo{}
				}
				userInfo := signalfmt.UserInfo{
					MXID: ghost.Intent.GetMXID(),
					Name: ghost.Name,
				}
				userLogin := s.Bridge.GetCachedUserLoginByID(networkid.UserLoginID(uuid.String()))
				if userLogin != nil {
					userInfo.MXID = userLogin.UserMXID
					// TODO find matrix user displayname?
				}
				return userInfo
			},
		},
		MatrixFmtParams: &matrixfmt.HTMLParser{
			GetUUIDFromMXID: func(ctx context.Context, userID id.UserID) uuid.UUID {
				parsed, ok := s.Bridge.Matrix.ParseGhostMXID(userID)
				if ok {
					u, _ := uuid.Parse(string(parsed))
					return u
				}
				user, _ := s.Bridge.GetExistingUserByMXID(ctx, userID)
				// TODO log errors?
				if user != nil {
					preferredLogin, _, _ := ctx.Value(msgconvContextKey).(*msgconvContext).Portal.FindPreferredLogin(ctx, user, true)
					if preferredLogin != nil {
						u, _ := uuid.Parse(string(preferredLogin.ID))
						return u
					}
				}
				return uuid.Nil
			},
		},
		ConvertVoiceMessages: true,
		ConvertGIFToAPNG:     true,
		MaxFileSize:          50 * 1024 * 1024,
		AsyncFiles:           true,
		LocationFormat:       s.Config.LocationFormat,
		UpdateDisappearing: func(ctx context.Context, newTimer time.Duration) {
			portal := ctx.Value(msgconvContextKey).(*msgconvContext).Portal
			portal.Disappear.Timer = newTimer
			if newTimer == 0 {
				portal.Disappear.Type = ""
			} else {
				portal.Disappear.Type = database.DisappearingTypeAfterRead
			}
			err := portal.Save(ctx)
			if err != nil {
				zerolog.Ctx(ctx).Err(err).Msg("Failed to update portal disappearing timer in database")
			}
		},
	}
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
	}
	if device != nil {
		sc.Client = &signalmeow.Client{
			Store:        device,
			EventHandler: sc.handleSignalEvent,
		}
	}
	login.Client = sc
	return nil
}
