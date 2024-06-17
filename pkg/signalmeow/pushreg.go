// mautrix-signal - A Matrix-signal puppeting bridge.
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

package signalmeow

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"

	"go.mau.fi/mautrix-signal/pkg/signalmeow/web"
)

type ReqRegisterFCM struct {
	GCMRegistrationID string `json:"gcmRegistrationId,omitempty"`
	WebSocketChannel  bool   `json:"webSocketChannel"`
}

type ReqRegisterAPNs struct {
	APNRegistrationID  string `json:"apnRegistrationId,omitempty"`
	VoIPRegistrationID string `json:"voipRegistrationId,omitempty"`
}

func (cli *Client) registerPush(ctx context.Context, pushType string, data any) error {
	username, password := cli.Store.BasicAuthCreds()
	req := &web.HTTPReqOpt{
		Username: &username,
		Password: &password,
	}
	var method string
	if data != nil {
		method = http.MethodPut
		req.ContentType = web.ContentTypeJSON
		var err error
		req.Body, err = json.Marshal(data)
		if err != nil {
			return err
		}
	} else {
		method = http.MethodDelete
	}
	resp, err := web.SendHTTPRequest(ctx, method, "/v1/accounts/"+pushType, req)
	if err != nil {
		return err
	} else if resp.StatusCode >= 300 || resp.StatusCode < 200 {
		return fmt.Errorf("unexpected status code %d", resp.StatusCode)
	}
	return nil
}

func (cli *Client) RegisterFCM(ctx context.Context, token string) error {
	if token == "" {
		return cli.registerPush(ctx, "gcm", nil)
	}
	return cli.registerPush(ctx, "gcm", &ReqRegisterFCM{
		GCMRegistrationID: token,
		WebSocketChannel:  true,
	})
}

func (cli *Client) RegisterAPNs(ctx context.Context, token string) error {
	if token == "" {
		return cli.registerPush(ctx, "apn", nil)
	}
	return cli.registerPush(ctx, "apn", &ReqRegisterAPNs{
		APNRegistrationID: token,
	})
}
