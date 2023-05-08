package signalmeow

import (
	"context"
	"fmt"
	"log"
	"os"

	_ "github.com/mattn/go-sqlite3"
	"github.com/mdp/qrterminal/v3"
	signalpb "go.mau.fi/mautrix-signal/pkg/signalmeow/protobuf"
	"go.mau.fi/mautrix-signal/pkg/signalmeow/store"
	"go.mau.fi/mautrix-signal/pkg/signalmeow/web"
	"go.mau.fi/mautrix-signal/pkg/signalmeow/wspb"
	"google.golang.org/protobuf/proto"
)

func Main() {
	sqlStore, err := store.New("sqlite3", "file:signalmeow.db?_foreign_keys=on")
	if err != nil {
		log.Printf("store.New error: %v", err)
		return
	}

	// See if we already have a device
	devices, err := sqlStore.GetAllDevices()
	if err != nil {
		log.Printf("GetAllDevices error: %v", err)
		return
	}
	if len(devices) > 1 {
		log.Printf("Too many devices, not sure which to test with: %v", len(devices))
		return
	}
	if len(devices) == 1 {
		log.Printf("Using existing device: %v", devices[0])
	} else {
		doProvisioning(sqlStore)
		devices, err = sqlStore.GetAllDevices()
		if err != nil {
			log.Printf("GetAllDevices error: %v", err)
			return
		}
		if len(devices) != 1 {
			log.Printf("Expected 1 device, got %v", len(devices))
			return
		}
	}
	device := devices[0]

	// Start message receiver
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	username := device.Data.AciUuid + "." + fmt.Sprintf("%d", device.Data.DeviceId)
	password := device.Data.Password
	agent := "OWD"
	path := web.WebsocketPath + "?" + "agent=" + agent + "login=" + username + "&password=" + password
	ws, resp, err := web.OpenWebsocket(ctx, path)
	if err != nil {
		log.Printf("OpenWebsocket error: %v", err)
		return
	}
	if resp.StatusCode != 101 {
		log.Printf("Unexpected status code: %v", resp.StatusCode)
		return
	}
	for {
		msg := &signalpb.WebSocketMessage{}
		err = wspb.Read(ctx, ws, msg)
		if err != nil {
			log.Printf("Read error: %v", err)
			return
		}
		if *msg.Type == signalpb.WebSocketMessage_REQUEST &&
			*msg.Request.Verb == "PUT" && *msg.Request.Path == "/api/v1/messages" {
			log.Printf("Received AN ACTUAL message: %v", msg)
			envelope := &signalpb.Envelope{}
			err := proto.Unmarshal(msg.Request.Body, envelope)
			if err != nil {
				log.Printf("Unmarshal error: %v", err)
				return
			}
			log.Printf("-----> envelope: %v", envelope)
		} else {
			log.Printf("Received NOT a message: %v", msg)
		}
	}
}

func doProvisioning(sqlStore *store.StoreContainer) {
	provChan := PerformProvisioning(sqlStore)

	// First get the provisioning URL
	resp := <-provChan
	if resp.Err != nil || resp.State == StateProvisioningError {
		log.Printf("PerformProvisioning error: %v", resp.Err)
		return
	}
	if resp.State == StateProvisioningURLReceived {
		qrterminal.Generate(resp.ProvisioningUrl, qrterminal.M, os.Stdout)
	} else {
		log.Printf("Unexpected state: %v", resp.State)
		return
	}

	// Next, get the results of finishing registration
	resp = <-provChan
	if resp.Err != nil || resp.State == StateProvisioningError {
		log.Printf("PerformProvisioning error: %v", resp.Err)
		return
	}
	if resp.State == StateProvisioningDataReceived {
		log.Printf("provisioningData: %v", resp.ProvisioningData)
	} else {
		log.Printf("Unexpected state: %v", resp.State)
		return
	}

	// Finally get the results of registering prekeys
	resp = <-provChan
	if resp.Err != nil || resp.State == StateProvisioningError {
		log.Printf("PerformProvisioning error: %v", resp.Err)
		return
	}
	if resp.State == StateProvisioningPreKeysRegistered {
		log.Printf("preKeysRegistered")
	} else {
		log.Printf("Unexpected state: %v", resp.State)
		return
	}
}
