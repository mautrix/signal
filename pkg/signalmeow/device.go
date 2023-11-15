package signalmeow

import (
	"context"
	"errors"
	"fmt"
	"net/url"

	"go.mau.fi/mautrix-signal/pkg/libsignalgo"
	"go.mau.fi/mautrix-signal/pkg/signalmeow/web"
)

// Note: right now, the parent `Device` struct is in store.go
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
	SenderCertificate      *libsignalgo.SenderCertificate
	GroupCredentials       *GroupCredentials
	GroupCache             *GroupCache
	ProfileCache           *ProfileCache
	GroupCallCache         *map[string]bool
	LastContactRequestTime *int64
	// Network interfaces
	AuthedWS   *web.SignalWebsocket
	UnauthedWS *web.SignalWebsocket

	IncomingSignalMessageHandler func(IncomingSignalMessage) error
}

func (d *DeviceConnection) ConnectAuthedWS(ctx context.Context, data DeviceData, requestHandler web.RequestHandlerFunc) (chan web.SignalWebsocketConnectionStatus, error) {
	if d.AuthedWS != nil {
		return nil, errors.New("authed websocket already connected")
	}
	username, password := data.BasicAuthCreds()
	username = url.QueryEscape(username)
	password = url.QueryEscape(password)
	path := web.WebsocketPath +
		"?login=" + username +
		"&password=" + password
	authedWS := web.NewSignalWebsocket(ctx, "authed", path, &username, &password)
	statusChan := authedWS.Connect(ctx, &requestHandler)
	d.AuthedWS = authedWS
	return statusChan, nil
}

func (d *DeviceConnection) ConnectUnauthedWS(ctx context.Context, data DeviceData) (chan web.SignalWebsocketConnectionStatus, error) {
	if d.UnauthedWS != nil {
		return nil, errors.New("unauthed websocket already connected")
	}
	unauthedWS := web.NewSignalWebsocket(ctx, "unauthed", web.WebsocketPath, nil, nil)
	statusChan := unauthedWS.Connect(ctx, nil)
	d.UnauthedWS = unauthedWS

	return statusChan, nil
}
