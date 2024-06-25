// mautrix-signal - A Matrix-Signal puppeting bridge.
// Copyright (C) 2024 Tulir Asokan
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU Affero General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.
//
// This program is istributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
// GNU Affero General Public License for more details.
//
// You should have received a copy of the GNU Affero General Public License
// along with this program.  If not, see <https://www.gnu.org/licenses/>.

package legacyprovision

import (
	"encoding/json"
	"net/http"

	"maunium.net/go/mautrix/id"
)

func JSONResponse(w http.ResponseWriter, status int, response any) {
	w.Header().Add("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(response)
}

type Error struct {
	Success bool   `json:"success"`
	Error   string `json:"error"`
	ErrCode string `json:"errcode"`
}

type Response struct {
	Success bool   `json:"success"`
	Status  string `json:"status"`

	// For response in LinkNew
	SessionID string `json:"session_id,omitempty"`
	URI       string `json:"uri,omitempty"`

	// For response in LinkWaitForAccount
	UUID   string `json:"uuid,omitempty"`
	Number string `json:"number,omitempty"`

	// For response in ResolveIdentifier
	*ResolveIdentifierResponse
}

type WhoAmIResponse struct {
	Permissions int                   `json:"permissions"`
	MXID        string                `json:"mxid"`
	Signal      *WhoAmIResponseSignal `json:"signal,omitempty"`
}

type WhoAmIResponseSignal struct {
	Number string `json:"number"`
	UUID   string `json:"uuid"`
	Name   string `json:"name"`
	Ok     bool   `json:"ok"`
}

type ResolveIdentifierResponse struct {
	RoomID      id.RoomID                           `json:"room_id"`
	ChatID      ResolveIdentifierResponseChatID     `json:"chat_id"`
	JustCreated bool                                `json:"just_created"`
	OtherUser   *ResolveIdentifierResponseOtherUser `json:"other_user,omitempty"`
}

type ResolveIdentifierResponseChatID struct {
	UUID   string `json:"uuid"`
	Number string `json:"number"`
}

type ResolveIdentifierResponseOtherUser struct {
	MXID        id.UserID     `json:"mxid"`
	DisplayName string        `json:"displayname"`
	AvatarURL   id.ContentURI `json:"avatar_url"`
}

type LinkWaitForScanRequest struct {
	SessionID string `json:"session_id"`
}

type LinkWaitForAccountRequest struct {
	SessionID  string `json:"session_id"`
	DeviceName string `json:"device_name"` // TODO this seems to not be used anywhere
}
