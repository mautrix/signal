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

package main

import (
	"fmt"
	"net/http"

	"github.com/gorilla/mux"
	"github.com/rs/zerolog"

	"go.mau.fi/mautrix-signal/legacyprovision"
	"maunium.net/go/mautrix"
	"maunium.net/go/mautrix/bridgev2"
)

func legacyProvLinkNew(w http.ResponseWriter, r *http.Request) {
	w.WriteHeader(http.StatusNotImplemented)
}

func legacyProvLinkWaitScan(w http.ResponseWriter, r *http.Request) {
	w.WriteHeader(http.StatusNotImplemented)
}

func legacyProvLinkWaitAccount(w http.ResponseWriter, r *http.Request) {
	w.WriteHeader(http.StatusNotImplemented)
}

func legacyProvLogout(w http.ResponseWriter, r *http.Request) {
	user := m.Matrix.Provisioning.GetUser(r)
	for {
		login := user.GetDefaultLogin()
		if login == nil {
			break
		}
		login.Logout(r.Context())
	}
	legacyprovision.JSONResponse(w, http.StatusOK, nil)
}

func legacyResolveIdentifierOrStartChat(w http.ResponseWriter, r *http.Request, create bool) {
	login := m.Matrix.Provisioning.GetLoginForRequest(w, r)
	if login == nil {
		return
	}
	api := login.Client.(bridgev2.IdentifierResolvingNetworkAPI)
	resp, err := api.ResolveIdentifier(r.Context(), mux.Vars(r)["phonenum"], create)
	if err != nil {
		zerolog.Ctx(r.Context()).Err(err).Msg("Failed to resolve identifier")
		legacyprovision.JSONResponse(w, http.StatusInternalServerError, &legacyprovision.Error{
			Error:   fmt.Sprintf("Failed to resolve identifier: %v", err),
			ErrCode: "M_UNKNOWN",
		})
		return
	} else if resp == nil {
		legacyprovision.JSONResponse(w, http.StatusNotFound, &legacyprovision.Error{
			ErrCode: mautrix.MNotFound.ErrCode,
			Error:   "User not found on Signal",
		})
		return
	}
	status := http.StatusOK
	apiResp := &legacyprovision.ResolveIdentifierResponse{
		ChatID: legacyprovision.ResolveIdentifierResponseChatID{
			UUID:   string(resp.UserID),
			Number: "",
		},
	}
	if resp.Ghost != nil {
		if resp.UserInfo != nil {
			resp.Ghost.UpdateInfo(r.Context(), resp.UserInfo)
		}
		apiResp.OtherUser = &legacyprovision.ResolveIdentifierResponseOtherUser{
			MXID:        resp.Ghost.Intent.GetMXID(),
			DisplayName: resp.Ghost.Name,
			AvatarURL:   resp.Ghost.AvatarMXC.ParseOrIgnore(),
		}
	}
	if resp.Chat != nil {
		if resp.Chat.Portal == nil {
			resp.Chat.Portal, err = m.Bridge.GetPortalByID(r.Context(), resp.Chat.PortalID)
			if err != nil {
				zerolog.Ctx(r.Context()).Err(err).Msg("Failed to get portal")
				legacyprovision.JSONResponse(w, http.StatusInternalServerError, &mautrix.RespError{
					Err:     "Failed to get portal",
					ErrCode: "M_UNKNOWN",
				})
				return
			}
		}
		if create && resp.Chat.Portal.MXID == "" {
			apiResp.JustCreated = true
			status = http.StatusCreated
			err = resp.Chat.Portal.CreateMatrixRoom(r.Context(), login, resp.Chat.PortalInfo)
			if err != nil {
				zerolog.Ctx(r.Context()).Err(err).Msg("Failed to create portal room")
				legacyprovision.JSONResponse(w, http.StatusInternalServerError, &mautrix.RespError{
					Err:     "Failed to create portal room",
					ErrCode: "M_UNKNOWN",
				})
				return
			}
		}
		apiResp.RoomID = resp.Chat.Portal.MXID
	}
	legacyprovision.JSONResponse(w, status, &legacyprovision.Response{
		Success:                   true,
		Status:                    "ok",
		ResolveIdentifierResponse: apiResp,
	})
}

func legacyProvResolveIdentifier(w http.ResponseWriter, r *http.Request) {
	legacyResolveIdentifierOrStartChat(w, r, false)
}

func legacyProvPM(w http.ResponseWriter, r *http.Request) {
	legacyResolveIdentifierOrStartChat(w, r, true)
}
