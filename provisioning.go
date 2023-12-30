// mautrix-signal - A Matrix-signal puppeting bridge.
// Copyright (C) 2023 Scott Weber
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
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	_ "net/http/pprof"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/beeper/libserv/pkg/requestlog"
	"github.com/google/uuid"
	"github.com/gorilla/mux"
	"github.com/rs/zerolog"
	"github.com/rs/zerolog/hlog"
	"maunium.net/go/mautrix"
	"maunium.net/go/mautrix/id"

	"go.mau.fi/mautrix-signal/pkg/signalmeow"
)

type provisioningContextKey int

const (
	provisioningUserKey provisioningContextKey = iota
)

type provisioningHandle struct {
	id      int
	context context.Context
	cancel  context.CancelFunc
	channel <-chan signalmeow.ProvisioningResponse
}

type ProvisioningAPI struct {
	bridge              *SignalBridge
	log                 zerolog.Logger
	provisioningHandles []*provisioningHandle
	provisioningUsers   map[string]int
	provisioningMutexes map[string]*sync.Mutex
}

func (prov *ProvisioningAPI) Init() {
	prov.log.Debug().Str("prefix", prov.bridge.Config.Bridge.Provisioning.Prefix).Msg("Enabling provisioning API")
	prov.provisioningUsers = make(map[string]int)
	prov.provisioningMutexes = make(map[string]*sync.Mutex)
	r := prov.bridge.AS.Router.PathPrefix(prov.bridge.Config.Bridge.Provisioning.Prefix).Subrouter()
	r.Use(hlog.NewHandler(prov.log))
	r.Use(requestlog.AccessLogger(true))
	r.Use(prov.AuthMiddleware)
	r.HandleFunc("/v2/link/new", prov.LinkNew).Methods(http.MethodPost)
	r.HandleFunc("/v2/link/wait/scan", prov.LinkWaitForScan).Methods(http.MethodPost)
	r.HandleFunc("/v2/link/wait/account", prov.LinkWaitForAccount).Methods(http.MethodPost)
	r.HandleFunc("/v2/logout", prov.Logout).Methods(http.MethodPost)
	r.HandleFunc("/v2/resolve_identifier/{phonenum}", prov.ResolveIdentifier).Methods(http.MethodGet)
	r.HandleFunc("/v2/pm/{phonenum}", prov.StartPM).Methods(http.MethodPost)

	if prov.bridge.Config.Bridge.Provisioning.DebugEndpoints {
		prov.log.Debug().Msg("Enabling debug API at /debug")
		r := prov.bridge.AS.Router.PathPrefix("/debug").Subrouter()
		r.Use(prov.AuthMiddleware)
		r.PathPrefix("/pprof").Handler(http.DefaultServeMux)
	}
}

func jsonResponse(w http.ResponseWriter, status int, response any) {
	w.Header().Add("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(response)
}

func (prov *ProvisioningAPI) AuthMiddleware(h http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		auth := strings.TrimPrefix(r.Header.Get("Authorization"), "Bearer ")
		if auth != prov.bridge.Config.Bridge.Provisioning.SharedSecret {
			zerolog.Ctx(r.Context()).Warn().Msg("Authentication token does not match shared secret")
			jsonResponse(w, http.StatusForbidden, &mautrix.RespError{
				Err:     "Authentication token does not match shared secret",
				ErrCode: mautrix.MForbidden.ErrCode,
			})
			return
		}
		userID := r.URL.Query().Get("user_id")
		user := prov.bridge.GetUserByMXID(id.UserID(userID))
		h.ServeHTTP(w, r.WithContext(context.WithValue(r.Context(), provisioningUserKey, user)))
	})
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

// ** Start New Chat ** //

type ResolveIdentifierResponse struct {
	RoomID      id.RoomID                          `json:"room_id"`
	ChatID      ResolveIdentifierResponseChatID    `json:"chat_id"`
	JustCreated bool                               `json:"just_created"`
	OtherUser   ResolveIdentifierResponseOtherUser `json:"other_user"`
}

type ResolveIdentifierResponseChatID struct {
	UUID   string `json:"uuid"`
	Number string `json:"number"`
}

type ResolveIdentifierResponseOtherUser struct {
	MXID        string `json:"mxid"`
	DisplayName string `json:"displayname"`
	AvatarURL   string `json:"avatar_url"`
}

func (prov *ProvisioningAPI) resolveIdentifier(user *User, phoneNum string) (int, *ResolveIdentifierResponse, error) {
	if !strings.HasPrefix(phoneNum, "+") {
		phoneNum = "+" + phoneNum
	}
	if user.SignalDevice == nil {
		prov.log.Debug().Msgf("ResolveIdentifier from %v, no device found", user.MXID)
		return http.StatusUnauthorized, nil, fmt.Errorf("Not currently connected to Signal")
	}
	contact, err := user.SignalDevice.ContactByE164(phoneNum)
	if err != nil {
		prov.log.Err(err).Msgf("ResolveIdentifier from %v, error looking up contact", user.MXID)
		return http.StatusInternalServerError, nil, fmt.Errorf("Error looking up number in local contact list: %w", err)
	}
	if contact == nil {
		prov.log.Debug().Msgf("ResolveIdentifier from %v, contact not found", user.MXID)
		return http.StatusNotFound, nil, fmt.Errorf("The bridge does not have the Signal ID for the number %s", phoneNum)
	}

	portal := user.GetPortalByChatID(contact.UUID.String())
	puppet := prov.bridge.GetPuppetBySignalID(contact.UUID)

	return http.StatusOK, &ResolveIdentifierResponse{
		RoomID: portal.MXID,
		ChatID: ResolveIdentifierResponseChatID{
			UUID:   contact.UUID.String(),
			Number: phoneNum,
		},
		OtherUser: ResolveIdentifierResponseOtherUser{
			MXID:        puppet.MXID.String(),
			DisplayName: puppet.Name,
			AvatarURL:   puppet.AvatarURL.String(),
		},
	}, nil
}

func (prov *ProvisioningAPI) ResolveIdentifier(w http.ResponseWriter, r *http.Request) {
	user := r.Context().Value(provisioningUserKey).(*User)
	phoneNum, _ := mux.Vars(r)["phonenum"]
	prov.log.Debug().Msgf("ResolveIdentifier from %v, phone number: %v", user.MXID, phoneNum)

	status, resp, err := prov.resolveIdentifier(user, phoneNum)
	if err != nil {
		errCode := "M_INTERNAL"
		if status == http.StatusNotFound {
			prov.log.Debug().Msgf("ResolveIdentifier from %v, contact not found", user.MXID)
			errCode = "M_NOT_FOUND"
		} else {
			prov.log.Err(err).Msgf("ResolveIdentifier from %v, error looking up contact", user.MXID)
		}
		jsonResponse(w, status, Error{
			Success: false,
			Error:   err.Error(),
			ErrCode: errCode,
		})
		return
	}
	jsonResponse(w, status, Response{
		Success:                   true,
		Status:                    "ok",
		ResolveIdentifierResponse: resp,
	})
}

func (prov *ProvisioningAPI) StartPM(w http.ResponseWriter, r *http.Request) {
	user := r.Context().Value(provisioningUserKey).(*User)
	phoneNum, _ := mux.Vars(r)["phonenum"]
	prov.log.Debug().Msgf("StartPM from %v, phone number: %v", user.MXID, phoneNum)

	status, resp, err := prov.resolveIdentifier(user, phoneNum)
	if err != nil {
		errCode := "M_INTERNAL"
		if status == http.StatusNotFound {
			prov.log.Debug().Msgf("StartPM from %v, contact not found", user.MXID)
			errCode = "M_NOT_FOUND"
		} else {
			prov.log.Err(err).Msgf("StartPM from %v, error looking up contact", user.MXID)
		}
		jsonResponse(w, status, Error{
			Success: false,
			Error:   err.Error(),
			ErrCode: errCode,
		})
		return
	}

	portal := user.GetPortalByChatID(resp.ChatID.UUID)
	if portal.MXID == "" {
		if err := portal.CreateMatrixRoom(user, nil); err != nil {
			prov.log.Err(err).Msgf("StartPM from %v, error creating Matrix room", user.MXID)
			jsonResponse(w, http.StatusInternalServerError, Error{
				Success: false,
				Error:   "Error creating Matrix room",
				ErrCode: "M_INTERNAL",
			})
			return
		}
		resp.JustCreated = true
		resp.RoomID = portal.MXID
	}
	if resp.JustCreated {
		status = http.StatusCreated
	}

	jsonResponse(w, status, Response{
		Success:                   true,
		Status:                    "ok",
		ResolveIdentifierResponse: resp,
	})
}

// ** Provisioning session creation and management ** //

func (prov *ProvisioningAPI) mutexForUser(user *User) *sync.Mutex {
	if _, ok := prov.provisioningMutexes[user.MXID.String()]; !ok {
		prov.provisioningMutexes[user.MXID.String()] = &sync.Mutex{}
	}
	return prov.provisioningMutexes[user.MXID.String()]
}

func (prov *ProvisioningAPI) newOrExistingSession(user *User) (newSessionLoggedIn bool, handle *provisioningHandle, err error) {
	prov.mutexForUser(user).Lock()
	defer prov.mutexForUser(user).Unlock()

	if existingSessionID, ok := prov.provisioningUsers[user.MXID.String()]; ok {
		provisioningHandle := prov.provisioningHandles[existingSessionID]
		return false, provisioningHandle, nil
	}

	provChan, err := user.Login()
	if err != nil {
		return false, nil, fmt.Errorf("Error logging in: %w", err)
	}
	provisioningCtx, cancel := context.WithCancel(context.Background())
	handle = &provisioningHandle{
		context: provisioningCtx,
		cancel:  cancel,
		channel: provChan,
	}
	prov.provisioningHandles = append(prov.provisioningHandles, handle)
	handle.id = len(prov.provisioningHandles) - 1
	prov.provisioningUsers[user.MXID.String()] = handle.id
	return true, handle, nil
}

func (prov *ProvisioningAPI) existingSession(user *User) (handle *provisioningHandle) {
	prov.mutexForUser(user).Lock()
	defer prov.mutexForUser(user).Unlock()

	if existingSessionID, ok := prov.provisioningUsers[user.MXID.String()]; ok {
		provisioningHandle := prov.provisioningHandles[existingSessionID]
		return provisioningHandle
	}
	return nil
}

func (prov *ProvisioningAPI) clearSession(user *User) {
	prov.mutexForUser(user).Lock()
	defer prov.mutexForUser(user).Unlock()

	if existingSessionID, ok := prov.provisioningUsers[user.MXID.String()]; ok {
		prov.log.Debug().Msgf("clearSession called for %v, clearing session %v", user.MXID, existingSessionID)
		if existingSessionID >= len(prov.provisioningHandles) {
			prov.log.Warn().Msgf("clearSession called for %v, session %v does not exist", user.MXID, existingSessionID)
			return
		}
		if prov.provisioningHandles[existingSessionID].cancel != nil {
			prov.provisioningHandles[existingSessionID].cancel()
		}
		prov.provisioningHandles[existingSessionID] = nil
		delete(prov.provisioningUsers, user.MXID.String())
	} else {
		prov.log.Debug().Msgf("clearSession called for %v, no session found", user.MXID)
	}
}

// ** Provisioning API Helpers ** //

func (prov *ProvisioningAPI) loginOrSendError(w http.ResponseWriter, user *User) *provisioningHandle {
	newSessionLoggedIn, handle, err := prov.newOrExistingSession(user)
	if err != nil {
		prov.log.Err(err).Msg("Error logging in")
		jsonResponse(w, http.StatusInternalServerError, Error{
			Success: false,
			Error:   "Error logging in",
			ErrCode: "M_INTERNAL",
		})
		return nil
	}
	if !newSessionLoggedIn {
		prov.log.Debug().Msgf("LinkNew from %v, user already has a pending provisioning request (%d), cancelling", user.MXID, handle.id)
		prov.clearSession(user)
		newSessionLoggedIn, handle, err = prov.newOrExistingSession(user)
		if err != nil {
			prov.log.Err(err).Msg("Error logging in after cancelling existing session")
			jsonResponse(w, http.StatusInternalServerError, Error{
				Success: false,
				Error:   "Error logging in",
				ErrCode: "M_INTERNAL",
			})
			return nil
		}
	}
	return handle
}

func (prov *ProvisioningAPI) checkSessionAndReturnHandle(w http.ResponseWriter, r *http.Request, currentSession int) *provisioningHandle {
	user := r.Context().Value(provisioningUserKey).(*User)
	handle := prov.existingSession(user)
	if handle == nil {
		prov.log.Warn().Msgf("checkSessionAndReturnHandle: from %v, no session found", user.MXID)
		jsonResponse(w, http.StatusNotFound, Error{
			Success: false,
			Error:   "No session found",
			ErrCode: "M_NOT_FOUND",
		})
		return nil
	}
	if handle.id != currentSession {
		prov.log.Warn().Msgf("checkSessionAndReturnHandle: from %v, session_id %v does not match user's current session_id %v", user.MXID, currentSession, handle.id)
		jsonResponse(w, http.StatusBadRequest, Error{
			Success: false,
			Error:   "session_id does not match user's session_id",
			ErrCode: "M_BAD_JSON",
		})
		return nil
	}
	return handle
}

// ** Provisioning API ** //

func (prov *ProvisioningAPI) LinkNew(w http.ResponseWriter, r *http.Request) {
	user := r.Context().Value(provisioningUserKey).(*User)

	prov.log.Debug().Msgf("LinkNew from %v, starting login", user.MXID)
	handle := prov.loginOrSendError(w, user)

	prov.log.Debug().Msgf("LinkNew from %v, waiting for provisioning response (session: %v)", user.MXID, handle.id)

	select {
	case resp := <-handle.channel:
		if resp.Err != nil || resp.State == signalmeow.StateProvisioningError {
			prov.log.Err(resp.Err).Msg("Error getting provisioning URL")
			jsonResponse(w, http.StatusInternalServerError, Error{
				Success: false,
				Error:   resp.Err.Error(),
				ErrCode: "M_INTERNAL",
			})
			return
		}
		if resp.State != signalmeow.StateProvisioningURLReceived {
			prov.log.Error().Msgf("LinkNew from %v, unexpected state: %v", user.MXID, resp.State)
			jsonResponse(w, http.StatusInternalServerError, Error{
				Success: false,
				Error:   "Unexpected state",
				ErrCode: "M_INTERNAL",
			})
			return
		}

		prov.log.Debug().Msgf("LinkNew from %v, provisioning URL received", user.MXID)
		jsonResponse(w, http.StatusOK, Response{
			Success:   true,
			Status:    "provisioning_url_received",
			SessionID: fmt.Sprintf("%v", handle.id),
			URI:       resp.ProvisioningUrl,
		})
		return
	case <-time.After(30 * time.Second):
		prov.log.Warn().Msg("Timeout waiting for provisioning response (new)")
		jsonResponse(w, http.StatusGatewayTimeout, Error{
			Success: false,
			Error:   "Timeout waiting for provisioning response (new)",
			ErrCode: "M_TIMEOUT",
		})
		return
	}
}

func (prov *ProvisioningAPI) LinkWaitForScan(w http.ResponseWriter, r *http.Request) {
	user := r.Context().Value(provisioningUserKey).(*User)
	body := struct {
		SessionID string `json:"session_id"`
	}{}
	err := json.NewDecoder(r.Body).Decode(&body)
	if err != nil {
		jsonResponse(w, http.StatusBadRequest, Error{
			Success: false,
			Error:   "Error decoding JSON body",
			ErrCode: "M_BAD_JSON",
		})
		return
	}
	sessionID, err := strconv.Atoi(body.SessionID)
	if err != nil {
		jsonResponse(w, http.StatusBadRequest, Error{
			Success: false,
			Error:   "Error decoding session ID in JSON body",
			ErrCode: "M_BAD_JSON",
		})
		return
	}

	prov.log.Debug().Msgf("LinkWaitForScan from %v, session_id: %v", user.MXID, sessionID)

	handle := prov.checkSessionAndReturnHandle(w, r, sessionID)
	if handle == nil {
		return
	}

	select {
	case resp := <-handle.channel:
		if resp.Err != nil || resp.State == signalmeow.StateProvisioningError {
			prov.log.Err(resp.Err).Msg("Error waiting for scan")
			// If context was cancelled be chill
			if errors.Is(resp.Err, context.Canceled) {
				prov.log.Debug().Msg("Context cancelled waiting for scan")
				return
			}
			// If we error waiting for the scan, treat it as a normal error not 5xx
			// so that the client will retry quietly. Also, it's really not an internal
			// error, sitting with a WS open waiting for a scan is inherently flaky.
			jsonResponse(w, http.StatusBadRequest, Error{
				Success: false,
				Error:   resp.Err.Error(),
				ErrCode: "M_INTERNAL",
			})
			return
		}
		if resp.State != signalmeow.StateProvisioningDataReceived {
			prov.log.Err(err).Msgf("LinkWaitForScan from %v, unexpected state: %v", user.MXID, resp.State)
			jsonResponse(w, http.StatusInternalServerError, Error{
				Success: false,
				Error:   "Unexpected state",
				ErrCode: "M_INTERNAL",
			})
			return
		}
		prov.log.Debug().Msgf("LinkWaitForScan from %v, provisioning data received", user.MXID)
		jsonResponse(w, http.StatusOK, Response{
			Success: true,
			Status:  "provisioning_data_received",
		})

		// Update user with SignalID
		if resp.ProvisioningData.AciUuid != "" {
			user.SignalID, err = uuid.Parse(resp.ProvisioningData.AciUuid)
			// TODO handle err
			user.SignalUsername = resp.ProvisioningData.Number
			err = user.Update(r.Context())
			if err != nil {
				prov.log.Err(err).Msg("Failed to save user after login")
			}
		}
		return
	case <-time.After(45 * time.Second):
		prov.log.Warn().Msg("Timeout waiting for provisioning response (scan)")
		// Using 400 here to match the old bridge
		jsonResponse(w, http.StatusBadRequest, Error{
			Success: false,
			Error:   "Timeout waiting for QR code scan",
			ErrCode: "M_BAD_REQUEST",
		})
		return
	}
}

func (prov *ProvisioningAPI) LinkWaitForAccount(w http.ResponseWriter, r *http.Request) {
	user := r.Context().Value(provisioningUserKey).(*User)
	body := struct {
		SessionID  string `json:"session_id"`
		DeviceName string `json:"device_name"`
	}{}
	err := json.NewDecoder(r.Body).Decode(&body)
	if err != nil {
		jsonResponse(w, http.StatusBadRequest, Error{
			Success: false,
			Error:   "Error decoding JSON body",
			ErrCode: "M_BAD_JSON",
		})
		return
	}
	sessionID, err := strconv.Atoi(body.SessionID)
	if err != nil {
		jsonResponse(w, http.StatusBadRequest, Error{
			Success: false,
			Error:   "Error decoding session ID in JSON body",
			ErrCode: "M_BAD_JSON",
		})
		return
	}
	deviceName := body.DeviceName

	prov.log.Debug().Msgf("LinkWaitForAccount from %v, session_id: %v, device_name: %v", user.MXID, sessionID, deviceName)

	handle := prov.checkSessionAndReturnHandle(w, r, sessionID)
	if handle == nil {
		return
	}

	select {
	case resp := <-handle.channel:
		if resp.Err != nil || resp.State == signalmeow.StateProvisioningError {
			prov.log.Err(resp.Err).Msg("Error waiting for account")
			jsonResponse(w, http.StatusInternalServerError, Error{
				Success: false,
				Error:   resp.Err.Error(),
				ErrCode: "M_INTERNAL",
			})
			return
		}
		if resp.State != signalmeow.StateProvisioningPreKeysRegistered {
			prov.log.Err(err).Msgf("LinkWaitForAccount from %v, unexpected state: %v", user.MXID, resp.State)
			jsonResponse(w, http.StatusInternalServerError, Error{
				Success: false,
				Error:   "Unexpected state",
				ErrCode: "M_INTERNAL",
			})
			return
		}

		prov.log.Debug().Msgf("LinkWaitForAccount from %v, prekeys registered", user.MXID)
		jsonResponse(w, http.StatusOK, Response{
			Success: true,
			Status:  "prekeys_registered",
			UUID:    user.SignalID.String(),
			Number:  user.SignalUsername,
		})

		// Connect to Signal!!
		user.Connect()
		return
	case <-time.After(30 * time.Second):
		prov.log.Warn().Msg("Timeout waiting for provisioning response (account)")
		jsonResponse(w, http.StatusGatewayTimeout, Error{
			Success: false,
			Error:   "Timeout waiting for provisioning response (account)",
			ErrCode: "M_TIMEOUT",
		})
		return
	}
}

func (prov *ProvisioningAPI) Logout(w http.ResponseWriter, r *http.Request) {
	user := r.Context().Value(provisioningUserKey).(*User)
	prov.log.Debug().Msgf("Logout called from %v (but not logging out)", user.MXID)
	prov.clearSession(user)

	// For now do nothing - we need this API to return 200 to be compatible with
	// the old Signal bridge, which needed a call to Logout before allowing LinkNew
	// to be called, but we don't actually want to logout, we want to allow a reconnect.
	jsonResponse(w, http.StatusOK, Response{
		Success: true,
		Status:  "logged_out",
	})
}
