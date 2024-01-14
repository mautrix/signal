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
	"fmt"
	"net/http"
	"sync"
	"time"

	"go.mau.fi/mautrix-signal/pkg/signalmeow/web"
)

type basicExpiringCredentials struct {
	Username  string    `json:"username"`
	Password  string    `json:"password"`
	CreatedAt time.Time `json:"-"`
}

func (bec *basicExpiringCredentials) Expired() bool {
	return bec == nil || bec.CreatedAt.IsZero() || time.Since(bec.CreatedAt) > ContactDiscoveryAuthTTL
}

func (cli *Client) getContactDiscoveryCredentials(ctx context.Context) (*basicExpiringCredentials, error) {
	return cli.getCredentialsWithCache(ctx, &cli.cdAuth, &cli.cdAuthLock, "/v2/directory/auth")
}

func (cli *Client) getStorageCredentials(ctx context.Context) (*basicExpiringCredentials, error) {
	return cli.getCredentialsWithCache(ctx, &cli.storageAuth, &cli.storageAuthLock, "/v1/storage/auth")
}

func (cli *Client) getCredentialsWithCache(ctx context.Context, cache **basicExpiringCredentials, lock *sync.Mutex, path string) (*basicExpiringCredentials, error) {
	lock.Lock()
	defer lock.Unlock()
	if (*cache).Expired() {
		newCreds, err := cli.getCredentialsFromServer(ctx, path)
		if err != nil {
			return nil, err
		}
		*cache = newCreds
	}
	return *cache, nil
}

func (cli *Client) getCredentialsFromServer(ctx context.Context, path string) (*basicExpiringCredentials, error) {
	username, password := cli.Store.BasicAuthCreds()
	resp, err := web.SendHTTPRequest(ctx, http.MethodGet, path, &web.HTTPReqOpt{
		Username: &username,
		Password: &password,
	})
	if err != nil {
		return nil, err
	} else if resp.StatusCode >= 300 || resp.StatusCode < 200 {
		return nil, fmt.Errorf("unexpected status code %d", resp.StatusCode)
	}

	var auth basicExpiringCredentials
	auth.CreatedAt = time.Now()
	err = web.DecodeHTTPResponseBody(ctx, &auth, resp)
	if err != nil {
		return nil, fmt.Errorf("failed to decode response: %w", err)
	}
	return &auth, nil
}
