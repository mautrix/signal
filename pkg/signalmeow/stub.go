package signalmeow

import (
	"context"
	"crypto/tls"
	"fmt"
	"log"
	"math/rand"
	"net/http"
	"time"

	"go.mau.fi/mautrix-signal/pkg/signalmeow/protobuf"
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

		url := "wss://chat.signal.org:443/v1/websocket/provisioning/"

		opt := &websocket.DialOptions{
			HTTPClient: &http.Client{Transport: &http.Transport{TLSClientConfig: &tls.Config{InsecureSkipVerify: true}}},
		}
		ws, resp, err := websocket.Dial(ctx, url, opt)

		if err != nil {
			log.Printf("failed on open %s", resp)
			log.Fatal(err)
		}
		defer ws.Close(websocket.StatusInternalError, "the sky is falling")

		msg := &signalpb.WebSocketMessage{}
		err = wspb.Read(ctx, ws, msg)
		if err != nil {
			log.Printf("failed on read %s", resp)
			log.Fatal(err)
		}
		fmt.Printf("Received: ***\n%s\n***", msg)

		// Ensure the message is a request and has a valid verb and path
		if *msg.Type == signalpb.WebSocketMessage_REQUEST {
			if *msg.Request.Verb == "PUT" && *msg.Request.Path == "/v1/address" {
				// Decode provisioning UUID
				provisioning_uuid := &signalpb.ProvisioningUuid{}
				err = proto.Unmarshal(msg.Request.Body, provisioning_uuid)

				// Create provisioning URL
				//provisioning_url := "sgnl://linkdevice/?uuid=" + *provisioning_uuid.Uuid + "&pub_key=" + string(signalling_key)

				// Create a 200 response
				msg_type := signalpb.WebSocketMessage_RESPONSE
				message := "OK"
				status := uint32(200)
				response := &signalpb.WebSocketMessage{
					Type: &msg_type,
					Response: &signalpb.WebSocketResponseMessage{
						Id: msg.Request.Id,
						Message: &message,
						Status: &status,
					},
				}

				// Send response
				err = wspb.Write(ctx, ws, response)
				if err != nil {
					log.Printf("failed on write %s", resp)
					log.Fatal(err)
				}
				fmt.Printf("Sent: ***\n%s\n***", response)
			}
		}

		ws.Close(websocket.StatusNormalClosure, "")
}
