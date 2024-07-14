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
	"encoding/json"
	"fmt"
	"net/http"
	"strconv"
	"sync"
	"sync/atomic"

	"github.com/gorilla/mux"
	"github.com/rs/zerolog"
	"maunium.net/go/mautrix"
	"maunium.net/go/mautrix/bridgev2"

	"go.mau.fi/mautrix-signal/legacyprovision"
	"go.mau.fi/mautrix-signal/pkg/connector"
)

var legacyProvisionHandleID atomic.Uint32
var loginSessions = make(map[uint32]*legacyLoginProcess)
var loginSessionsLock sync.Mutex

type legacyLoginProcess struct {
	ID    uint32
	Login bridgev2.LoginProcess
	User  *bridgev2.User
}

func (llp *legacyLoginProcess) Delete() {
	loginSessionsLock.Lock()
	delete(loginSessions, llp.ID)
	loginSessionsLock.Unlock()
}

func legacyProvLinkNew(w http.ResponseWriter, r *http.Request) {
	handleID := legacyProvisionHandleID.Add(1)
	user := m.Matrix.Provisioning.GetUser(r)
	defLogin := user.GetDefaultLogin()
	if defLogin != nil && defLogin.Client != nil && defLogin.Client.IsLoggedIn() {
		legacyprovision.JSONResponse(w, http.StatusConflict, &legacyprovision.Error{
			Error:   "Already logged in",
			ErrCode: "FI.MAU.ALREADY_LOGGED_IN",
		})
		return
	}
	log := zerolog.Ctx(r.Context())
	login, err := m.Connector.CreateLogin(r.Context(), user, "qr")
	if err != nil {
		log.Err(err).Msg("Failed to create login")
		legacyprovision.JSONResponse(w, http.StatusInternalServerError, &legacyprovision.Error{
			Error:   "Internal error starting login",
			ErrCode: "M_UNKNOWN",
		})
		return
	}
	firstStep, err := login.Start(r.Context())
	if err != nil {
		log.Err(err).Msg("Failed to start login")
		legacyprovision.JSONResponse(w, http.StatusInternalServerError, &legacyprovision.Error{
			Error:   "Internal error starting login",
			ErrCode: "M_UNKNOWN",
		})
		return
	} else if firstStep.StepID != connector.LoginStepQR || firstStep.Type != bridgev2.LoginStepTypeDisplayAndWait || firstStep.DisplayAndWaitParams.Type != bridgev2.LoginDisplayTypeQR {
		log.Error().Any("first_step", firstStep).Msg("Unexpected first step")
		legacyprovision.JSONResponse(w, http.StatusInternalServerError, &legacyprovision.Error{
			Error:   "Unexpected first login step",
			ErrCode: "M_UNKNOWN",
		})
		return
	}
	loginSessionsLock.Lock()
	loginSessions[handleID] = &legacyLoginProcess{
		ID:    handleID,
		Login: login,
		User:  user,
	}
	loginSessionsLock.Unlock()
	legacyprovision.JSONResponse(w, http.StatusOK, legacyprovision.Response{
		Success:   true,
		Status:    "provisioning_url_received",
		SessionID: strconv.Itoa(int(handleID)),
		URI:       firstStep.DisplayAndWaitParams.Data,
	})
}

func getLoginProcess(w http.ResponseWriter, r *http.Request) *legacyLoginProcess {
	var body legacyprovision.LinkWaitForAccountRequest
	err := json.NewDecoder(r.Body).Decode(&body)
	if err != nil {
		legacyprovision.JSONResponse(w, http.StatusBadRequest, legacyprovision.Error{
			Success: false,
			Error:   "Error decoding JSON body",
			ErrCode: mautrix.MBadJSON.ErrCode,
		})
		return nil
	}
	sessionID, err := strconv.Atoi(body.SessionID)
	if err != nil {
		legacyprovision.JSONResponse(w, http.StatusBadRequest, legacyprovision.Error{
			Success: false,
			Error:   "Error decoding session ID in JSON body",
			ErrCode: mautrix.MBadJSON.ErrCode,
		})
		return nil
	}
	process, ok := loginSessions[uint32(sessionID)]
	user := m.Matrix.Provisioning.GetUser(r)
	if !ok || process.User != user {
		legacyprovision.JSONResponse(w, http.StatusNotFound, legacyprovision.Error{
			Success: false,
			Error:   "No session found",
			ErrCode: mautrix.MNotFound.ErrCode,
		})
		return nil
	}
	return process
}

func legacyProvLinkWaitScan(w http.ResponseWriter, r *http.Request) {
	login := getLoginProcess(w, r)
	if login == nil {
		return
	}
	res, err := login.Login.(bridgev2.LoginProcessDisplayAndWait).Wait(r.Context())
	if err != nil {
		zerolog.Ctx(r.Context()).Err(err).Msg("Failed to log in")
		legacyprovision.JSONResponse(w, http.StatusInternalServerError, legacyprovision.Error{
			Error:   "Failed to log in",
			ErrCode: "M_UNKNOWN",
		})
		login.Delete()
		return
	} else if res.StepID != connector.LoginStepProcess {
		zerolog.Ctx(r.Context()).Error().Any("first_step", res).Msg("Unexpected login step")
		legacyprovision.JSONResponse(w, http.StatusInternalServerError, legacyprovision.Error{
			Error:   "Unexpected login step",
			ErrCode: "M_UNKNOWN",
		})
		login.Delete()
		return
	}
	legacyprovision.JSONResponse(w, http.StatusOK, legacyprovision.Response{
		Success: true,
		Status:  "provisioning_data_received",
	})
}

func legacyProvLinkWaitAccount(w http.ResponseWriter, r *http.Request) {
	login := getLoginProcess(w, r)
	if login == nil {
		return
	}
	res, err := login.Login.(bridgev2.LoginProcessDisplayAndWait).Wait(r.Context())
	if err != nil {
		zerolog.Ctx(r.Context()).Err(err).Msg("Failed to log in")
		legacyprovision.JSONResponse(w, http.StatusInternalServerError, legacyprovision.Error{
			Error:   "Failed to log in",
			ErrCode: "M_UNKNOWN",
		})
	} else if res.StepID != connector.LoginStepComplete || res.Type != bridgev2.LoginStepTypeComplete {
		zerolog.Ctx(r.Context()).Error().Any("first_step", res).Msg("Unexpected login step")
		legacyprovision.JSONResponse(w, http.StatusInternalServerError, legacyprovision.Error{
			Error:   "Unexpected login step",
			ErrCode: "M_UNKNOWN",
		})
	} else {
		legacyprovision.JSONResponse(w, http.StatusOK, legacyprovision.Response{
			Success: true,
			Status:  "prekeys_registered",
			UUID:    string(res.CompleteParams.UserLogin.ID),
			Number:  res.CompleteParams.UserLogin.RemoteName,
		})
	}
	login.Delete()
}

func legacyProvLogout(w http.ResponseWriter, r *http.Request) {
	// No-op for backwards compatibility
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
			resp.Chat.Portal, err = m.Bridge.GetPortalByKey(r.Context(), resp.Chat.PortalKey)
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
