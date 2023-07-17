package signalmeow

import (
	"context"
	"fmt"
	"net/url"

	"go.mau.fi/mautrix-signal/pkg/libsignalgo"
	"go.mau.fi/mautrix-signal/pkg/signalmeow/web"
)

// Note: right now, the parent `Device` struct is in store/store.go, since
// it is so tied to storage and we don't want to have a circular dependency.

type DeviceData struct {
	AciIdentityKeyPair *libsignalgo.IdentityKeyPair
	PniIdentityKeyPair *libsignalgo.IdentityKeyPair
	RegistrationId     int
	PniRegistrationId  int
	AciUuid            string
	PniUuid            string
	DeviceId           int
	Number             string
	Password           string
}

func (d *DeviceData) BasicAuthCreds() (string, string) {
	username := fmt.Sprintf("%s.%d", d.AciUuid, d.DeviceId)
	password := d.Password
	return username, password
}

// DeviceConnection exists on a Device, and holds websockets, cached credentials,
// and other data that is used to communicate with the Signal servers and other clients.
type DeviceConnection struct {
	// cached data (not persisted)
	SenderCertificate *libsignalgo.SenderCertificate
	GroupCredentials  *GroupCredentials
	// Network interfaces
	AuthedWS   *web.SignalWebsocket
	UnauthedWS *web.SignalWebsocket

	IncomingSignalMessageHandler func(IncomingSignalMessage) error
}

func (d *DeviceConnection) ConnectAuthedWS(ctx context.Context, data DeviceData, requestHandler web.RequestHandlerFunc) error {
	if d.AuthedWS != nil {
		return nil
	}
	username, password := data.BasicAuthCreds()
	username = url.QueryEscape(username)
	password = url.QueryEscape(password)
	path := web.WebsocketPath +
		"?login=" + username +
		"&password=" + password
	authedWS := web.NewSignalWebsocket(ctx, path, &username, &password)
	authedWS.Connect(ctx, &requestHandler)
	d.AuthedWS = authedWS
	return nil
}
func (d *DeviceConnection) ConnectUnauthedWS(ctx context.Context, data DeviceData) error {
	if d.UnauthedWS != nil {
		return nil
	}
	unauthedWS := web.NewSignalWebsocket(ctx, web.WebsocketPath, nil, nil)
	unauthedWS.Connect(ctx, nil)
	d.UnauthedWS = unauthedWS
	return nil
}
