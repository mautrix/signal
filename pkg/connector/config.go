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
	_ "embed"
	"strings"
	"text/template"

	up "go.mau.fi/util/configupgrade"
	"maunium.net/go/mautrix/id"

	"go.mau.fi/mautrix-signal/pkg/signalmeow/types"
)

//go:embed example-config.yaml
var ExampleConfig string

type SignalConfig struct {
	DisplaynameTemplate string              `yaml:"displayname_template"`
	UseContactAvatars   bool                `yaml:"use_contact_avatars"`
	UseOutdatedProfiles bool                `yaml:"use_outdated_profiles"`
	NumberInTopic       bool                `yaml:"number_in_topic"`
	DeviceName          string              `yaml:"device_name"`
	NoteToSelfAvatar    id.ContentURIString `yaml:"note_to_self_avatar"`
	LocationFormat      string              `yaml:"location_format"`

	displaynameTemplate *template.Template `yaml:"-"`
}

type DisplaynameParams struct {
	ProfileName string
	ContactName string
	Username    string
	PhoneNumber string
	UUID        string
	ACI         string
	PNI         string
	AboutEmoji  string
}

func (c *SignalConfig) FormatDisplayname(contact *types.Recipient) string {
	var nameBuf strings.Builder
	err := c.displaynameTemplate.Execute(&nameBuf, &DisplaynameParams{
		ProfileName: contact.Profile.Name,
		ContactName: contact.ContactName,
		Username:    "",
		PhoneNumber: contact.E164,
		UUID:        contact.ACI.String(),
		ACI:         contact.ACI.String(),
		PNI:         contact.PNI.String(),
		AboutEmoji:  contact.Profile.AboutEmoji,
	})
	if err != nil {
		panic(err)
	}
	return nameBuf.String()
}

func upgradeConfig(helper up.Helper) {
	helper.Copy(up.Str, "displayname_template")
	helper.Copy(up.Bool, "use_contact_avatars")
	helper.Copy(up.Bool, "use_outdated_profiles")
	helper.Copy(up.Bool, "number_in_topic")
	helper.Copy(up.Str, "device_name")
	helper.Copy(up.Str, "note_to_self_avatar")
	helper.Copy(up.Str, "location_format")
}

func (s *SignalConnector) GetConfig() (string, any, up.Upgrader) {
	return ExampleConfig, s.Config, up.SimpleUpgrader(upgradeConfig)
}
