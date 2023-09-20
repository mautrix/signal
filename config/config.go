// mautrix-discord - A Matrix-Discord puppeting bridge.
// Copyright (C) 2022 Tulir Asokan
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

package config

import (
	"maunium.net/go/mautrix/bridge/bridgeconfig"
	"maunium.net/go/mautrix/id"
)

type Config struct {
	*bridgeconfig.BaseConfig `yaml:",inline"`

	Bridge BridgeConfig `yaml:"bridge"`
}

func (config *Config) CanAutoDoublePuppet(userID id.UserID) bool {
	_, homeserver, _ := userID.Parse()
	_, hasSecret := config.Bridge.DoublePuppetConfig.SharedSecretMap[homeserver]

	return hasSecret
}
