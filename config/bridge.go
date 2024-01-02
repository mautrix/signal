// mautrix-signal - A Matrix-signal puppeting bridge.
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
	"errors"
	"fmt"
	"strings"
	"text/template"
	"time"

	"maunium.net/go/mautrix/bridge/bridgeconfig"
	"maunium.net/go/mautrix/event"
	"maunium.net/go/mautrix/id"

	"go.mau.fi/mautrix-signal/pkg/signalmeow/types"
)

type BridgeConfig struct {
	UsernameTemplate      string `yaml:"username_template"`
	DisplaynameTemplate   string `yaml:"displayname_template"`
	PrivateChatPortalMeta string `yaml:"private_chat_portal_meta"`
	UseContactAvatars     bool   `yaml:"use_contact_avatars"`

	PortalMessageBuffer int `yaml:"portal_message_buffer"`

	DoublePuppetConfig bridgeconfig.DoublePuppetConfig `yaml:",inline"`

	BridgeNotices       bool `yaml:"bridge_notices"`
	DeliveryReceipts    bool `yaml:"delivery_receipts"`
	MessageStatusEvents bool `yaml:"message_status_events"`
	MessageErrorNotices bool `yaml:"message_error_notices"`
	SyncDirectChatList  bool `yaml:"sync_direct_chat_list"`
	ResendBridgeInfo    bool `yaml:"resend_bridge_info"`
	CaptionInMessage    bool `yaml:"caption_in_message"`
	FederateRooms       bool `yaml:"federate_rooms"`

	MessageHandlingTimeout struct {
		ErrorAfterStr string `yaml:"error_after"`
		DeadlineStr   string `yaml:"deadline"`

		ErrorAfter time.Duration `yaml:"-"`
		Deadline   time.Duration `yaml:"-"`
	} `yaml:"message_handling_timeout"`

	CommandPrefix      string                           `yaml:"command_prefix"`
	ManagementRoomText bridgeconfig.ManagementRoomTexts `yaml:"management_room_text"`

	Encryption bridgeconfig.EncryptionConfig `yaml:"encryption"`

	Provisioning struct {
		Prefix         string `yaml:"prefix"`
		SharedSecret   string `yaml:"shared_secret"`
		DebugEndpoints bool   `yaml:"debug_endpoints"`
	} `yaml:"provisioning"`

	Permissions bridgeconfig.PermissionConfig `yaml:"permissions"`

	Relay RelaybotConfig `yaml:"relay"`

	usernameTemplate    *template.Template `yaml:"-"`
	displaynameTemplate *template.Template `yaml:"-"`
}

func (bc *BridgeConfig) GetResendBridgeInfo() bool {
	return bc.ResendBridgeInfo
}

func (bc *BridgeConfig) EnableMessageStatusEvents() bool {
	return bc.MessageStatusEvents
}

func (bc *BridgeConfig) EnableMessageErrorNotices() bool {
	return bc.MessageErrorNotices
}

func boolToInt(val bool) int {
	if val {
		return 1
	}
	return 0
}

func (bc *BridgeConfig) Validate() error {
	_, hasWildcard := bc.Permissions["*"]
	_, hasExampleDomain := bc.Permissions["example.com"]
	_, hasExampleUser := bc.Permissions["@admin:example.com"]
	exampleLen := boolToInt(hasWildcard) + boolToInt(hasExampleUser) + boolToInt(hasExampleDomain)
	if len(bc.Permissions) <= exampleLen {
		return errors.New("bridge.permissions not configured")
	}
	return nil
}

type umBridgeConfig BridgeConfig

func (bc *BridgeConfig) UnmarshalYAML(unmarshal func(interface{}) error) error {
	err := unmarshal((*umBridgeConfig)(bc))
	if err != nil {
		return err
	}

	bc.usernameTemplate, err = template.New("username").Parse(bc.UsernameTemplate)
	if err != nil {
		return err
	} else if !strings.Contains(bc.FormatUsername("1234567890"), "1234567890") {
		return fmt.Errorf("username template is missing user ID placeholder")
	}
	bc.displaynameTemplate, err = template.New("displayname").Parse(bc.DisplaynameTemplate)
	if err != nil {
		return err
	}

	return nil
}

var _ bridgeconfig.BridgeConfig = (*BridgeConfig)(nil)

func (bc BridgeConfig) GetDoublePuppetConfig() bridgeconfig.DoublePuppetConfig {
	return bc.DoublePuppetConfig
}

func (bc BridgeConfig) GetEncryptionConfig() bridgeconfig.EncryptionConfig {
	return bc.Encryption
}

func (bc BridgeConfig) GetCommandPrefix() string {
	return bc.CommandPrefix
}

func (bc BridgeConfig) GetManagementRoomTexts() bridgeconfig.ManagementRoomTexts {
	return bc.ManagementRoomText
}

func (bc BridgeConfig) FormatUsername(userID string) string {
	var buffer strings.Builder
	_ = bc.usernameTemplate.Execute(&buffer, userID)
	return buffer.String()
}

type DisplaynameParams struct {
	ProfileName string
	ContactName string
	Username    string
	PhoneNumber string
	UUID        string
	AboutEmoji  string
}

func (bc BridgeConfig) FormatDisplayname(contact *types.Contact) string {
	var buffer strings.Builder
	_ = bc.displaynameTemplate.Execute(&buffer, DisplaynameParams{
		ProfileName: contact.ProfileName,
		ContactName: contact.ContactName,
		//Username:    contact.Username,
		PhoneNumber: contact.E164,
		UUID:        contact.UUID.String(),
		AboutEmoji:  contact.ProfileAboutEmoji,
	})
	return buffer.String()
}

type RelaybotConfig struct {
	Enabled          bool                         `yaml:"enabled"`
	AdminOnly        bool                         `yaml:"admin_only"`
	MessageFormats   map[event.MessageType]string `yaml:"message_formats"`
	messageTemplates *template.Template           `yaml:"-"`
}

type umRelaybotConfig RelaybotConfig

func (rc *RelaybotConfig) UnmarshalYAML(unmarshal func(interface{}) error) error {
	err := unmarshal((*umRelaybotConfig)(rc))
	if err != nil {
		return err
	}

	rc.messageTemplates = template.New("messageTemplates")
	for key, format := range rc.MessageFormats {
		_, err := rc.messageTemplates.New(string(key)).Parse(format)
		if err != nil {
			return err
		}
	}

	return nil
}

type Sender struct {
	UserID string
	event.MemberEventContent
}

type formatData struct {
	Sender  Sender
	Message string
	Content *event.MessageEventContent
}

func (rc *RelaybotConfig) FormatMessage(content *event.MessageEventContent, sender id.UserID, member event.MemberEventContent) (string, error) {
	if len(member.Displayname) == 0 {
		member.Displayname = sender.String()
	}
	member.Displayname = template.HTMLEscapeString(member.Displayname)
	var output strings.Builder
	err := rc.messageTemplates.ExecuteTemplate(&output, string(content.MsgType), formatData{
		Sender: Sender{
			UserID:             template.HTMLEscapeString(sender.String()),
			MemberEventContent: member,
		},
		Content: content,
		Message: content.FormattedBody,
	})
	return output.String(), err
}
