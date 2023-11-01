package main

import (
	"bufio"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/rs/zerolog"
	"go.mau.fi/mautrix-signal/pkg/signalmeow"
	"maunium.net/go/mautrix/id"
)

type provisioningHandle struct {
	context context.Context
	cancel  context.CancelFunc
	channel <-chan signalmeow.ProvisioningResponse
}

type ProvisioningAPI struct {
	bridge              *SignalBridge
	log                 zerolog.Logger
	provisioningHandles []provisioningHandle
	provisioningUsers   map[string]int
}

func (prov *ProvisioningAPI) Init() {
	prov.log.Debug().Msgf("Enabling provisioning API at %v", prov.bridge.Config.Bridge.Provisioning.Prefix)
	prov.provisioningUsers = make(map[string]int)
	r := prov.bridge.AS.Router.PathPrefix(prov.bridge.Config.Bridge.Provisioning.Prefix).Subrouter()
	r.Use(prov.AuthMiddleware)
	r.HandleFunc("/v2/link/new", prov.LinkNew).Methods(http.MethodPost)
	r.HandleFunc("/v2/link/wait/scan", prov.LinkWaitForScan).Methods(http.MethodPost)
	r.HandleFunc("/v2/link/wait/account", prov.LinkWaitForAccount).Methods(http.MethodPost)
	r.HandleFunc("/v2/logout", prov.Logout).Methods(http.MethodPost)
}

type responseWrap struct {
	http.ResponseWriter
	statusCode int
}

func jsonResponse(w http.ResponseWriter, status int, response interface{}) {
	w.Header().Add("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(response)
}

var _ http.Hijacker = (*responseWrap)(nil)

func (rw *responseWrap) WriteHeader(statusCode int) {
	rw.ResponseWriter.WriteHeader(statusCode)
	rw.statusCode = statusCode
}

func (rw *responseWrap) Hijack() (net.Conn, *bufio.ReadWriter, error) {
	hijacker, ok := rw.ResponseWriter.(http.Hijacker)
	if !ok {
		return nil, nil, errors.New("response does not implement http.Hijacker")
	}
	return hijacker.Hijack()
}

func (prov *ProvisioningAPI) AuthMiddleware(h http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		auth := r.Header.Get("Authorization")
		if strings.HasPrefix(auth, "Bearer ") {
			auth = auth[len("Bearer "):]
		}
		if auth != prov.bridge.Config.Bridge.Provisioning.SharedSecret {
			prov.log.Info().Msg("Authentication token does not match shared secret")
			jsonResponse(w, http.StatusForbidden, map[string]interface{}{
				"error":   "Authentication token does not match shared secret",
				"errcode": "M_FORBIDDEN",
			})
			return
		}
		userID := r.URL.Query().Get("user_id")
		user := prov.bridge.GetUserByMXID(id.UserID(userID))
		start := time.Now()
		wWrap := &responseWrap{w, 200}
		h.ServeHTTP(wWrap, r.WithContext(context.WithValue(r.Context(), "user", user)))
		duration := time.Now().Sub(start).Seconds()
		prov.log.Info().Msgf("%s %s from %s took %.2f seconds and returned status %d", r.Method, r.URL.Path, user.MXID, duration, wWrap.statusCode)
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
}

func (prov *ProvisioningAPI) LinkNew(w http.ResponseWriter, r *http.Request) {
	user := r.Context().Value("user").(*User)
	prov.log.Debug().Msgf("LinkNew from %v", user.MXID)
	if existingSessionID, ok := prov.provisioningUsers[user.MXID.String()]; ok {
		prov.log.Warn().Msgf("LinkNew from %v, user already has a pending provisioning request (%d), cancelling", user.MXID, existingSessionID)
		prov.CancelLink(user)
	}

	provChan, err := user.Login()
	if err != nil {
		prov.log.Err(err).Msg("Error logging in")
		jsonResponse(w, http.StatusInternalServerError, Error{
			Success: false,
			Error:   "Error logging in",
			ErrCode: "M_INTERNAL",
		})
		return
	}
	provisioningCtx, cancel := context.WithCancel(context.Background())
	handle := provisioningHandle{
		context: provisioningCtx,
		cancel:  cancel,
		channel: provChan,
	}
	prov.provisioningHandles = append(prov.provisioningHandles, handle)
	sessionID := len(prov.provisioningHandles) - 1
	prov.provisioningUsers[user.MXID.String()] = sessionID
	prov.log.Debug().Msgf("LinkNew from %v, waiting for provisioning response", user.MXID)

	select {
	case resp := <-provChan:
		if resp.Err != nil || resp.State == signalmeow.StateProvisioningError {
			prov.log.Err(resp.Err).Msg("Error getting provisioning URL")
			jsonResponse(w, http.StatusInternalServerError, Error{
				Success: false,
				Error:   "Error getting provisioning URL",
				ErrCode: "M_INTERNAL",
			})
			return
		}
		if resp.State != signalmeow.StateProvisioningURLReceived {
			prov.log.Err(err).Msgf("LinkNew from %v, unexpected state: %v", user.MXID, resp.State)
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
			SessionID: fmt.Sprintf("%v", sessionID),
			URI:       resp.ProvisioningUrl,
		})
		return
	case <-time.After(30 * time.Second):
		prov.log.Err(err).Msg("Timeout waiting for provisioning response (new)")
		jsonResponse(w, http.StatusGatewayTimeout, Error{
			Success: false,
			Error:   "Timeout waiting for provisioning response (new)",
			ErrCode: "M_TIMEOUT",
		})
		return
	}
}

func (prov *ProvisioningAPI) LinkWaitForScan(w http.ResponseWriter, r *http.Request) {
	user := r.Context().Value("user").(*User)
	body := struct {
		SessionID string `json:"session_id"`
	}{}
	err := json.NewDecoder(r.Body).Decode(&body)
	if err != nil {
		prov.log.Err(err).Msg("Error decoding JSON body")
		jsonResponse(w, http.StatusBadRequest, Error{
			Success: false,
			Error:   "Error decoding JSON body",
			ErrCode: "M_BAD_JSON",
		})
		return
	}

	sessionID, err := strconv.Atoi(body.SessionID)
	if err != nil {
		prov.log.Err(err).Msg("Error decoding JSON body")
		jsonResponse(w, http.StatusBadRequest, Error{
			Success: false,
			Error:   "Error decoding JSON body",
			ErrCode: "M_BAD_JSON",
		})
		return
	}
	prov.log.Debug().Msgf("LinkWaitForScan from %v, session_id: %v", user.MXID, sessionID)
	if userSessionID, ok := prov.provisioningUsers[user.MXID.String()]; ok && userSessionID != sessionID {
		prov.log.Warn().Msgf("LinkWaitForAccount from %v, session_id %v does not match user's session_id %v", user.MXID, sessionID, userSessionID)
		jsonResponse(w, http.StatusBadRequest, Error{
			Success: false,
			Error:   "session_id does not match user's session_id",
			ErrCode: "M_BAD_JSON",
		})
		return
	}
	handle := prov.provisioningHandles[sessionID]

	select {
	case resp := <-handle.channel:
		if resp.Err != nil || resp.State == signalmeow.StateProvisioningError {
			prov.log.Err(resp.Err).Msg("Error getting provisioning URL")
			jsonResponse(w, http.StatusInternalServerError, Error{
				Success: false,
				Error:   "Error getting provisioning URL",
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
			user.SignalID = resp.ProvisioningData.AciUuid
			user.SignalUsername = resp.ProvisioningData.Number
			user.Update()
		}
		return
	case <-time.After(60 * time.Second):
		prov.log.Err(err).Msg("Timeout waiting for provisioning response (scan)")
		jsonResponse(w, http.StatusRequestTimeout, Error{
			Success: false,
			Error:   "Timeout waiting for QR code scan",
			ErrCode: "M_TIMEOUT",
		})
		return
	}
}

func (prov *ProvisioningAPI) LinkWaitForAccount(w http.ResponseWriter, r *http.Request) {
	user := r.Context().Value("user").(*User)
	body := struct {
		SessionID  string `json:"session_id"`
		DeviceName string `json:"device_name"`
	}{}
	err := json.NewDecoder(r.Body).Decode(&body)
	if err != nil {
		prov.log.Err(err).Msg("Error decoding JSON body")
		jsonResponse(w, http.StatusBadRequest, Error{
			Success: false,
			Error:   "Error decoding JSON body",
			ErrCode: "M_BAD_JSON",
		})
		return
	}
	sessionID, err := strconv.Atoi(body.SessionID)
	if err != nil {
		prov.log.Err(err).Msg("Error decoding JSON body")
		jsonResponse(w, http.StatusBadRequest, Error{
			Success: false,
			Error:   "Error decoding JSON body",
			ErrCode: "M_BAD_JSON",
		})
		return
	}
	deviceName := body.DeviceName
	prov.log.Debug().Msgf("LinkWaitForAccount from %v, session_id: %v, device_name: %v", user.MXID, sessionID, deviceName)
	if userSessionID, ok := prov.provisioningUsers[user.MXID.String()]; ok && userSessionID != sessionID {
		prov.log.Warn().Msgf("LinkWaitForAccount from %v, session_id %v does not match user's session_id %v", user.MXID, sessionID, userSessionID)
		jsonResponse(w, http.StatusBadRequest, Error{
			Success: false,
			Error:   "session_id does not match user's session_id",
			ErrCode: "M_BAD_JSON",
		})
		return
	}
	handle := prov.provisioningHandles[sessionID]

	select {
	case resp := <-handle.channel:
		if resp.Err != nil || resp.State == signalmeow.StateProvisioningError {
			prov.log.Err(resp.Err).Msg("Error getting provisioning URL")
			jsonResponse(w, http.StatusInternalServerError, Error{
				Success: false,
				Error:   "Error getting provisioning URL",
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
			UUID:    user.SignalID,
			Number:  user.SignalUsername,
		})

		// Connect to Signal!!
		user.Connect()
		return
	case <-time.After(30 * time.Second):
		prov.log.Err(err).Msg("Timeout waiting for provisioning response (account)")
		jsonResponse(w, http.StatusGatewayTimeout, Error{
			Success: false,
			Error:   "Timeout waiting for provisioning response (account)",
			ErrCode: "M_TIMEOUT",
		})
		return
	}
}

func (prov *ProvisioningAPI) CancelLink(user *User) {
	if sessionID, ok := prov.provisioningUsers[user.MXID.String()]; ok {
		prov.log.Debug().Msgf("CancelLink called for %v, clearing session %v", user.MXID, sessionID)
		if sessionID >= len(prov.provisioningHandles) {
			prov.log.Warn().Msgf("CancelLink called for %v, session %v does not exist", user.MXID, sessionID)
			return
		}
		if prov.provisioningHandles[sessionID].cancel != nil {
			prov.provisioningHandles[sessionID].cancel()
		}
		prov.provisioningHandles[sessionID] = provisioningHandle{}
		delete(prov.provisioningUsers, user.MXID.String())
	} else {
		prov.log.Debug().Msgf("CancelLink called for %v, no session found", user.MXID)
	}
}

func (prov *ProvisioningAPI) Logout(w http.ResponseWriter, r *http.Request) {
	user := r.Context().Value("user").(*User)
	prov.log.Debug().Msgf("Logout called from %v (but not logging out)", user.MXID)
	prov.CancelLink(user)

	// For now do nothing - we need this API to return 200 to be compatible with
	// the old Signal bridge, which needed a call to Logout before allowing LinkNew
	// to be called, but we don't actually want to logout, we want to allow a reconnect.
	jsonResponse(w, http.StatusOK, Response{
		Success: true,
		Status:  "logged_out",
	})
}
