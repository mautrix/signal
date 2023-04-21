package signalmeow

import (
	"context"
	"crypto/tls"
	"fmt"
	"log"
	"math/rand"
	"net/http"
	"time"

	"nhooyr.io/websocket"
	"go.mau.fi/mautrix-signal/pkg/signalmeow/protobuf"
	"go.mau.fi/mautrix-signal/pkg/signalmeow/wspb"
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

//func old_provision_secondary_device(signalling_key []byte) {
//		// open a websocket without authentication, to receive a tsurl://
//		url := "wss://chat.signal.org:443/v1/websocket/provisioning/"
//		origin := "http://localhost/"
//		config, _ := websocket.NewConfig(url, origin)
//		tlsConfig := &tls.Config{
//				// TODO: Don't do this
//				InsecureSkipVerify: true,
//		}
//		config.TlsConfig = tlsConfig
//		config.Protocol = []string{"wss"}
//		ws, err := websocket.DialConfig(config)
//		if err != nil {
//				log.Printf("failed on open %s", ws)
//				log.Fatal(err)
//		}
//		//if _, err := ws.Write([]byte("hello, world!\n")); err != nil {
//		//		log.Fatal(err)
//		//}
//		var msg = make([]byte, 512)
//		var n int
//		if n, err = ws.Read(msg); err != nil {
//				log.Fatal(err)
//		}
//		fmt.Printf("Received: %s.\n", msg[:n])
//}

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

		ws.Close(websocket.StatusNormalClosure, "")
}
