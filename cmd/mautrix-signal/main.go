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
	"maunium.net/go/mautrix/bridgev2/bridgeconfig"
	"maunium.net/go/mautrix/bridgev2/matrix/mxmain"

	"go.mau.fi/mautrix-signal/pkg/connector"
	"go.mau.fi/mautrix-signal/pkg/signalmeow"
)

// Information to find out exactly which commit the bridge was built from.
// These are filled at build time with the -X linker flag.
var (
	Tag       = "unknown"
	Commit    = "unknown"
	BuildTime = "unknown"
)

var m = mxmain.BridgeMain{
	Name:        "mautrix-signal",
	URL:         "https://github.com/mautrix/signal",
	Description: "A Matrix-Signal puppeting bridge.",
	Version:     "0.8.5",

	Connector: &connector.SignalConnector{},
}

func main() {
	bridgeconfig.HackyMigrateLegacyNetworkConfig = migrateLegacyConfig
	m.PostInit = func() {
		signalmeow.SetLogger(m.Log.With().Str("component", "signalmeow").Logger())
		m.CheckLegacyDB(
			20,
			"v0.5.1",
			"v0.7.0",
			m.LegacyMigrateSimple(legacyMigrateRenameTables, legacyMigrateCopyData, 21),
			true,
		)
	}
	m.PostStart = func() {
		if m.Matrix.Provisioning != nil {
			m.Matrix.Provisioning.Router.HandleFunc("POST /v2/link/new", legacyProvLinkNew)
			m.Matrix.Provisioning.Router.HandleFunc("POST /v2/link/wait/scan", legacyProvLinkWaitScan)
			m.Matrix.Provisioning.Router.HandleFunc("POST /v2/link/wait/account", legacyProvLinkWaitAccount)
			m.Matrix.Provisioning.Router.HandleFunc("POST /v2/logout", legacyProvLogout)
			m.Matrix.Provisioning.Router.HandleFunc("GET /v2/resolve_identifier/{phonenum}", legacyProvResolveIdentifier)
			m.Matrix.Provisioning.Router.HandleFunc("POST /v2/pm/{phonenum}", legacyProvPM)
		}
	}
	m.InitVersion(Tag, Commit, BuildTime)
	m.Run()
}
