package web

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"io/ioutil"
	"log"
	"net/http"
	"net/url"

	signalpb "go.mau.fi/mautrix-signal/pkg/signalmeow/protobuf"
	"nhooyr.io/websocket"
)

const proxyUrlStr = "http://localhost:8080"
const caCertPath = "/Users/sweber/.mitmproxy/mitmproxy-ca-cert.pem"

const urlHost = "chat.signal.org:443"

// Paths used to open websockets and make HTTP requests
const WebsocketProvisioningPath = "/v1/websocket/provisioning/"
const WebsocketPath = "/v1/websocket/"
const HTTPKeysPath = "/v2/keys"

// TODO: embed Signal's self-signed cert, and turn off InsecureSkipVerify
func proxiedHTTPClient() *http.Client {
	var proxyURL *url.URL
	if proxyUrlStr != "" {
		var err error
		proxyURL, err = url.Parse(proxyUrlStr)
		if err != nil {
			log.Fatal("Error parsing proxy URL:", err)
		}
	}

	tlsConfig := &tls.Config{}
	if caCertPath != "" {
		var caCert []byte
		var err error
		caCert, err = ioutil.ReadFile(caCertPath)
		if err != nil {
			log.Fatal("Error reading CA certificate:", err)
		}
		caCertPool := x509.NewCertPool()
		caCertPool.AppendCertsFromPEM(caCert)

		tlsConfig.InsecureSkipVerify = true
		tlsConfig.RootCAs = caCertPool
	}

	transport := &http.Transport{}
	if proxyURL != nil {
		transport.Proxy = http.ProxyURL(proxyURL)
	}
	transport.TLSClientConfig = tlsConfig

	client := &http.Client{
		Transport: transport,
	}
	return client
}

func OpenWebsocket(ctx context.Context, path string) (*websocket.Conn, *http.Response, error) {
	opt := &websocket.DialOptions{
		HTTPClient: proxiedHTTPClient(),
	}
	urlStr := "wss://" + urlHost + path
	ws, resp, err := websocket.Dial(ctx, urlStr, opt)

	if err != nil {
		log.Printf("failed on open %v", resp)
	}
	return ws, resp, err
}

func CreateWSResponse(id uint64, status uint32) *signalpb.WebSocketMessage {
	if status == 200 {
		msg_type := signalpb.WebSocketMessage_RESPONSE
		message := "OK"
		response := &signalpb.WebSocketMessage{
			Type: &msg_type,
			Response: &signalpb.WebSocketResponseMessage{
				Id:      &id,
				Message: &message,
				Status:  &status,
				Headers: []string{},
			},
		}
		return response
	}
	// TODO support non-200 responses
	log.Fatal("Error creating response (non 200 not supported yet)")
	return nil
}

var wsRequestId uint64 = 0

func CreateWSRequest(method string, path string, body []byte, username *string, password *string) *signalpb.WebSocketMessage {
	wsRequestId += 1
	msg_type := signalpb.WebSocketMessage_REQUEST
	request := &signalpb.WebSocketMessage{
		Type: &msg_type,
		Request: &signalpb.WebSocketRequestMessage{
			Id:   &wsRequestId,
			Verb: &method,
			Path: &path,
			Body: body,
		},
	}
	request.Request.Headers = append(request.Request.Headers, "Content-Type: application/json")
	if username != nil && password != nil {
		basicAuth := base64.StdEncoding.EncodeToString([]byte(*username + ":" + *password))
		request.Request.Headers = append(request.Request.Headers, "authorization:Basic "+basicAuth)
	}
	return request
}

func SendHTTPRequest(method string, path string, body []byte, username *string, password *string) (*http.Response, error) {
	urlStr := "https://" + urlHost + path
	req, err := http.NewRequest(method, urlStr, bytes.NewBuffer(body))
	if err != nil {
		log.Fatalf("Error creating request: %v", err)
	}
	req.Header.Set("Content-Type", "application/json")
	//req.Header.Set("User-Agent", "SignalBridge/0.1")
	//req.Header.Set("X-Signal-Agent", "SignalBridge/0.1")
	if username != nil && password != nil {
		req.SetBasicAuth(*username, *password)
	}

	client := proxiedHTTPClient()
	resp, err := client.Do(req)
	return resp, err
}
