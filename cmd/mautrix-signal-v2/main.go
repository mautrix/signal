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
	"os"

	"go.mau.fi/util/dbutil"
	"go.mau.fi/util/exerrors"
	"go.mau.fi/util/exzerolog"
	"gopkg.in/yaml.v3"
	"maunium.net/go/mautrix/bridgev2"
	"maunium.net/go/mautrix/bridgev2/bridgeconfig"
	"maunium.net/go/mautrix/bridgev2/matrix"

	"go.mau.fi/mautrix-signal/pkg/connector"
	"go.mau.fi/mautrix-signal/pkg/signalmeow"
)

func main() {
	var cfg bridgeconfig.Config
	config := exerrors.Must(os.ReadFile("config.yaml"))
	exerrors.PanicIfNotNil(yaml.Unmarshal(config, &cfg))
	log := exerrors.Must(cfg.Logging.Compile())
	exzerolog.SetupDefaults(log)
	signalmeow.SetLogger(log.With().Str("component", "signalmeow").Logger())
	db := exerrors.Must(dbutil.NewFromConfig("mautrix-signal", cfg.Database, dbutil.ZeroLogger(log.With().Str("db_section", "main").Logger())))
	signalConnector := connector.NewConnector()
	exerrors.PanicIfNotNil(cfg.Network.Decode(signalConnector.Config))
	bridge := bridgev2.NewBridge("", db, *log, matrix.NewConnector(&cfg), signalConnector)
	bridge.CommandPrefix = "!signal"
	bridge.Start()
}
