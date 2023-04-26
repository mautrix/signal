package signalmeow

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"io/ioutil"
	"log"
	"math/rand"
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
	//var username string
	//var password string

	//// Generate a random 24 byte password with upper and lower case letters and numbers
	//var rand_password = GeneratePassword(24)
	//// 52 bytes of random data (not just upper or lower case letters)
	var signalling_key = RandomBytes(52)

	//log.Print("signalling_key: ", signalling_key)
	provision_secondary_device(signalling_key)

}

func GeneratePassword(length int) string {
	var letters = []rune("abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789")
	b := make([]rune, length)
	for i := range b {
		b[i] = letters[rand.Intn(len(letters))]
	}
	return string(b)
}

func RandomBytes(length int) []byte {
	b := make([]byte, length)
	rand.Read(b)
	return b
}

func provision_secondary_device(signalling_key []byte) {
	ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
	defer cancel()

	urlStr := "wss://chat.signal.org:443/v1/websocket/provisioning/"

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
}
