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
	"context"
	"fmt"

	"github.com/google/uuid"
	"maunium.net/go/mautrix/bridgev2"
	"maunium.net/go/mautrix/bridgev2/database"

	"go.mau.fi/mautrix-signal/pkg/signalmeow"
)

func (s *SignalConnector) GetLoginFlows() []bridgev2.LoginFlow {
	return []bridgev2.LoginFlow{{
		Name:        "QR",
		Description: "Scan a QR code to pair the bridge to your Signal app",
		ID:          "qr",
	}}
}

func (s *SignalConnector) CreateLogin(ctx context.Context, user *bridgev2.User, flowID string) (bridgev2.LoginProcess, error) {
	if flowID != "qr" {
		return nil, fmt.Errorf("invalid login flow ID")
	}
	return &QRLogin{User: user, Main: s}, nil
}

type QRLogin struct {
	User       *bridgev2.User
	Existing   *bridgev2.UserLogin
	Main       *SignalConnector
	cancelChan context.CancelFunc
	ProvChan   chan signalmeow.ProvisioningResponse
}

var _ bridgev2.LoginProcessDisplayAndWait = (*QRLogin)(nil)

func (qr *QRLogin) Cancel() {
	qr.cancelChan()
	go func() {
		for range qr.ProvChan {
		}
	}()
}

func (qr *QRLogin) Start(ctx context.Context) (*bridgev2.LoginStep, error) {
	log := qr.Main.Bridge.Log.With().
		Str("action", "login").
		Stringer("user_id", qr.User.MXID).
		Logger()
	provCtx, cancel := context.WithCancel(log.WithContext(context.Background()))
	qr.cancelChan = cancel
	// Don't use the start context here: the channel will outlive the start request.
	qr.ProvChan = signalmeow.PerformProvisioning(provCtx, qr.Main.Store, qr.Main.Config.DeviceName)
	var resp signalmeow.ProvisioningResponse
	select {
	case resp = <-qr.ProvChan:
		if resp.Err != nil || resp.State == signalmeow.StateProvisioningError {
			return nil, resp.Err
		} else if resp.State != signalmeow.StateProvisioningURLReceived {
			return nil, fmt.Errorf("unexpected state %v", resp.State)
		}
	case <-ctx.Done():
		cancel()
		return nil, ctx.Err()
		// TODO separate timeout here?
	}
	return &bridgev2.LoginStep{
		Type:         bridgev2.LoginStepTypeDisplayAndWait,
		StepID:       "fi.mau.signal.login.qr",
		Instructions: "Scan the QR code on your Signal app to log in",
		DisplayAndWaitParams: &bridgev2.LoginDisplayAndWaitParams{
			Type: bridgev2.LoginDisplayTypeQR,
			Data: resp.ProvisioningURL,
		},
	}, nil
}

func (qr *QRLogin) Wait(ctx context.Context) (*bridgev2.LoginStep, error) {
	if qr.ProvChan == nil {
		return nil, fmt.Errorf("login not started")
	}
	defer qr.cancelChan()

	var signalID uuid.UUID
	var signalPhone string
	select {
	case resp := <-qr.ProvChan:
		if resp.Err != nil || resp.State == signalmeow.StateProvisioningError {
			return nil, resp.Err
		} else if resp.State != signalmeow.StateProvisioningDataReceived {
			return nil, fmt.Errorf("unexpected state %v", resp.State)
		} else if resp.ProvisioningData.ACI == uuid.Nil {
			return nil, fmt.Errorf("no signal account ID received")
		}
		signalID = resp.ProvisioningData.ACI
		signalPhone = resp.ProvisioningData.Number
	case <-ctx.Done():
		return nil, ctx.Err()
	}
	newLoginID := makeUserLoginID(signalID)
	if qr.Existing != nil && qr.Existing.ID != newLoginID {
		return nil, fmt.Errorf("user ID mismatch for re-auth")
	}

	select {
	case resp := <-qr.ProvChan:
		if resp.Err != nil || resp.State == signalmeow.StateProvisioningError {
			return nil, resp.Err
		} else if resp.State != signalmeow.StateProvisioningPreKeysRegistered {
			return nil, fmt.Errorf("unexpected state %v", resp.State)
		}
	case <-ctx.Done():
		return nil, ctx.Err()
	}

	var ul *bridgev2.UserLogin
	var err error
	if qr.Existing == nil {
		ul, err = qr.User.NewLogin(ctx, &database.UserLogin{
			ID: newLoginID,
			Metadata: database.UserLoginMetadata{
				StandardUserLoginMetadata: database.StandardUserLoginMetadata{
					RemoteName: signalPhone,
				},
				Extra: map[string]any{
					"phone": signalPhone,
				},
			},
		}, nil)
		if err != nil {
			return nil, fmt.Errorf("failed to save new login: %w", err)
		}
	} else {
		ul = qr.Existing
		ul.Metadata.Extra["phone"] = signalPhone
		ul.Metadata.RemoteName = signalPhone
		err = ul.Save(ctx)
		if err != nil {
			return nil, fmt.Errorf("failed to update existing login: %w", err)
		}
	}
	backgroundCtx := ul.Log.WithContext(context.Background())
	err = qr.Main.LoadUserLogin(backgroundCtx, ul)
	if err != nil {
		return nil, fmt.Errorf("failed to prepare connection after login: %w", err)
	}
	err = ul.Client.Connect(backgroundCtx)
	if err != nil {
		return nil, fmt.Errorf("failed to connect after login: %w", err)
	}
	return &bridgev2.LoginStep{
		Type:         bridgev2.LoginStepTypeComplete,
		StepID:       "fi.mau.signal.login.complete",
		Instructions: fmt.Sprintf("Successfully logged in as %s / %s", signalPhone, signalID),
		CompleteParams: &bridgev2.LoginCompleteParams{
			UserLoginID: ul.ID,
		},
	}, nil
}
