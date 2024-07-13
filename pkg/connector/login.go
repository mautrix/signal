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
	"go.mau.fi/mautrix-signal/pkg/signalmeow/store"
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
	Main       *SignalConnector
	cancelChan context.CancelFunc
	ProvChan   chan signalmeow.ProvisioningResponse

	ProvData *store.DeviceData
}

var _ bridgev2.LoginProcessDisplayAndWait = (*QRLogin)(nil)

func (qr *QRLogin) Cancel() {
	qr.cancelChan()
	go func() {
		for range qr.ProvChan {
		}
	}()
}

const (
	LoginStepQR       = "fi.mau.signal.login.qr"
	LoginStepProcess  = "fi.mau.signal.login.processing"
	LoginStepComplete = "fi.mau.signal.login.complete"
)

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
		StepID:       LoginStepQR,
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

	if qr.ProvData == nil {
		return qr.qrWait(ctx)
	} else {
		return qr.processingWait(ctx)
	}
}

func (qr *QRLogin) qrWait(ctx context.Context) (*bridgev2.LoginStep, error) {
	select {
	case resp := <-qr.ProvChan:
		if resp.Err != nil || resp.State == signalmeow.StateProvisioningError {
			qr.cancelChan()
			return nil, resp.Err
		} else if resp.State != signalmeow.StateProvisioningDataReceived {
			qr.cancelChan()
			return nil, fmt.Errorf("unexpected state %v", resp.State)
		} else if resp.ProvisioningData.ACI == uuid.Nil {
			qr.cancelChan()
			return nil, fmt.Errorf("no signal account ID received")
		}
		qr.ProvData = resp.ProvisioningData
		return &bridgev2.LoginStep{
			Type:         bridgev2.LoginStepTypeDisplayAndWait,
			StepID:       LoginStepProcess,
			Instructions: fmt.Sprintf("Processing login as %s...", resp.ProvisioningData.Number),
			DisplayAndWaitParams: &bridgev2.LoginDisplayAndWaitParams{
				Type: bridgev2.LoginDisplayTypeNothing,
			},
		}, nil
	case <-ctx.Done():
		qr.cancelChan()
		return nil, ctx.Err()
	}
}

func (qr *QRLogin) processingWait(ctx context.Context) (*bridgev2.LoginStep, error) {
	defer qr.cancelChan()
	newLoginID := makeUserLoginID(qr.ProvData.ACI)

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

	ul, err := qr.User.NewLogin(ctx, &database.UserLogin{
		ID:         newLoginID,
		RemoteName: qr.ProvData.Number,
		Metadata: &UserLoginMetadata{
			Phone: qr.ProvData.Number,
		},
	}, &bridgev2.NewLoginParams{
		DeleteOnConflict: true,
	})
	if err != nil {
		return nil, fmt.Errorf("failed to create user login: %w", err)
	}
	backgroundCtx := ul.Log.WithContext(context.Background())
	err = ul.Client.Connect(backgroundCtx)
	if err != nil {
		return nil, fmt.Errorf("failed to connect after login: %w", err)
	}
	return &bridgev2.LoginStep{
		Type:         bridgev2.LoginStepTypeComplete,
		StepID:       LoginStepComplete,
		Instructions: fmt.Sprintf("Successfully logged in as %s / %s", qr.ProvData.Number, qr.ProvData.ACI),
		CompleteParams: &bridgev2.LoginCompleteParams{
			UserLoginID: ul.ID,
			UserLogin:   ul,
		},
	}, nil
}
