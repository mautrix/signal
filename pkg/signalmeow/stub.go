package signalmeow

import (
	"context"
	crand "crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"log"
	"math/big"
	mrand "math/rand"
	"net/http"
	"net/url"
	"os"
	"time"

	"github.com/mdp/qrterminal/v3"
	signalpb "go.mau.fi/mautrix-signal/pkg/signalmeow/protobuf"
	"go.mau.fi/mautrix-signal/pkg/signalmeow/wspb"
	"google.golang.org/protobuf/proto"
	"nhooyr.io/websocket"
)

func Main() {
	provisioning_message := provision_secondary_device()

	username := provisioning_message.Number
	password, _ := generateRandomPassword(24)
	code := provisioning_message.ProvisioningCode
	registration_id := mrand.Intn(16383) + 1
	pni_registration_id := mrand.Intn(16383) + 1
	confirm_device(*username, password, *code, registration_id, pni_registration_id)

	generate_pre_keys()
	register_pre_keys()

	// Persist necessary data
}

func generateRandomPassword(length int) (string, error) {
	if length < 1 {
		return "", fmt.Errorf("password length must be at least 1")
	}

	const charset = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"
	var password []byte
	for i := 0; i < length; i++ {
		index, err := crand.Int(crand.Reader, big.NewInt(int64(len(charset))))
		if err != nil {
			return "", fmt.Errorf("error generating random index: %v", err)
		}
		password = append(password, charset[index.Int64()])
	}

	return string(password), nil
}

func open_websocket(ctx context.Context, urlStr string) (*websocket.Conn, *http.Response, error) {
	proxyURL, err := url.Parse("http://localhost:8080")
	if err != nil {
		log.Fatal("Error parsing proxy URL:", err)
	}

	caCertPath := "/Users/sweber/.mitmproxy/mitmproxy-ca-cert.pem"
	caCert, err := ioutil.ReadFile(caCertPath)
	if err != nil {
		log.Fatal("Error reading mitmproxy CA certificate:", err)
	}

	caCertPool := x509.NewCertPool()
	caCertPool.AppendCertsFromPEM(caCert)

	tlsConfig := &tls.Config{
		InsecureSkipVerify: true,
		RootCAs:            caCertPool,
	}

	opt := &websocket.DialOptions{
		HTTPClient: &http.Client{
			Transport: &http.Transport{
				TLSClientConfig: tlsConfig,
				Proxy:           http.ProxyURL(proxyURL),
			},
		},
	}
	ws, resp, err := websocket.Dial(ctx, urlStr, opt)

	if err != nil {
		log.Printf("failed on open %v", resp)
		log.Fatal(err)
	}
	return ws, resp, err
}

func provision_secondary_device() *signalpb.ProvisionMessage {
	ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
	defer cancel()
	ws, resp, err := open_websocket(ctx, "wss://chat.signal.org:443/v1/websocket/provisioning/")
	defer ws.Close(websocket.StatusInternalError, "Websocket StatusInternalError")

	provisioning_cipher := NewProvisioningCipher()
	pub_key := provisioning_cipher.GetPublicKey()

	// The things we want
	provisioning_url := ""
	envelope := &signalpb.ProvisionEnvelope{}

	msg := &signalpb.WebSocketMessage{}
	err = wspb.Read(ctx, ws, msg)
	if err != nil {
		log.Printf("failed on read %v", resp)
		log.Fatal(err)
	}
	log.Printf("*** Received: %s", msg)

	// Ensure the message is a request and has a valid verb and path
	if *msg.Type == signalpb.WebSocketMessage_REQUEST &&
		*msg.Request.Verb == "PUT" &&
		*msg.Request.Path == "/v1/address" {

		// Decode provisioning UUID
		provisioning_uuid := &signalpb.ProvisioningUuid{}
		err = proto.Unmarshal(msg.Request.Body, provisioning_uuid)

		// Create provisioning URL
		bytes_key, _ := pub_key.Serialize()
		base64_key := base64.StdEncoding.EncodeToString(bytes_key)
		uuid := url.QueryEscape(*provisioning_uuid.Uuid)
		pub_key := url.QueryEscape(base64_key)
		provisioning_url = "sgnl://linkdevice?uuid=" + uuid + "&pub_key=" + pub_key
		log.Printf("provisioning_url: %s", provisioning_url)

		// Create a 200 response
		msg_type := signalpb.WebSocketMessage_RESPONSE
		message := "OK"
		status := uint32(200)
		response := &signalpb.WebSocketMessage{
			Type: &msg_type,
			Response: &signalpb.WebSocketResponseMessage{
				Id:      msg.Request.Id,
				Message: &message,
				Status:  &status,
				Headers: []string{},
			},
		}

		// Send response
		err = wspb.Write(ctx, ws, response)
		if err != nil {
			log.Printf("failed on write %v", resp)
			log.Fatal(err)
		}

		log.Printf("*** Sent: %s", response)
	}

	// Print the provisioning URL to the console as a QR code
	qrterminal.Generate(provisioning_url, qrterminal.M, os.Stdout)

	msg2 := &signalpb.WebSocketMessage{}
	err = wspb.Read(ctx, ws, msg2)
	if err != nil {
		log.Printf("failed on 2nd read %v", resp)
		log.Fatal(err)
	}
	log.Printf("*** Received: %s", msg2)

	if *msg2.Type == signalpb.WebSocketMessage_REQUEST &&
		*msg2.Request.Verb == "PUT" &&
		*msg2.Request.Path == "/v1/message" {

		envelope = &signalpb.ProvisionEnvelope{}
		err = proto.Unmarshal(msg2.Request.Body, envelope)
		if err != nil {
			log.Printf("failed on unmarshal %v", resp)
			log.Fatal(err)
		}

		// Create a 200 response
		msg_type := signalpb.WebSocketMessage_RESPONSE
		message := "OK"
		status := uint32(200)
		response := &signalpb.WebSocketMessage{
			Type: &msg_type,
			Response: &signalpb.WebSocketResponseMessage{
				Id:      msg2.Request.Id,
				Message: &message,
				Status:  &status,
				Headers: []string{},
			},
		}

		// Send response
		err = wspb.Write(ctx, ws, response)
		if err != nil {
			log.Printf("failed on write %v", resp)
			log.Fatal(err)
		}
		log.Printf("*** Sent: %s", response)
	}

	ws.Close(websocket.StatusNormalClosure, "")

	log.Printf("provisioning_url: %v", provisioning_url)
	log.Printf("Envelope: %v", envelope)
	provisioning_message := provisioning_cipher.Decrypt(envelope)
	log.Printf("provisioning_message: %v", provisioning_message)

	return provisioning_message
}

func confirm_device(username string, password string, code string, registration_id int, pni_registration_id int) {
	ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
	defer cancel()
	ws, resp, err := open_websocket(ctx, "wss://chat.signal.org:443/v1/websocket/")
	defer ws.Close(websocket.StatusInternalError, "Websocket StatusInternalError")

	data := map[string]interface{}{
		"registrationId":    registration_id,
		"pniRegistrationId": pni_registration_id,
		"supportsSms":       true,
	}
	// TODO: Set deviceName with "Signal Bridge" or something properly encrypted

	json_bytes, err := json.Marshal(data)
	if err != nil {
		fmt.Println("Error:", err)
		return
	}

	msg_type := signalpb.WebSocketMessage_REQUEST
	response := &signalpb.WebSocketMessage{
		Type: &msg_type,
		Request: &signalpb.WebSocketRequestMessage{
			Id:   proto.Uint64(1),
			Verb: proto.String("PUT"),
			Path: proto.String("/v1/devices/" + code),
			Body: json_bytes,
		},
	}
	response.Request.Headers = append(response.Request.Headers, "Content-Type: application/json")
	basicAuth := base64.StdEncoding.EncodeToString([]byte(username + ":" + password))
	response.Request.Headers = append(response.Request.Headers, "authorization:Basic "+basicAuth)

	// Send response
	err = wspb.Write(ctx, ws, response)
	if err != nil {
		log.Printf("failed on write %v", resp)
		log.Fatal(err)
	}

	log.Printf("*** Sent: %s", response)

	received_msg := &signalpb.WebSocketMessage{}
	err = wspb.Read(ctx, ws, received_msg)
	if err != nil {
		log.Printf("failed to read after devices call: %v", resp)
		log.Fatal(err)
	}
	log.Printf("*** Received: %s", received_msg)
}

func generate_pre_keys() {
}

func register_pre_keys() {
}
