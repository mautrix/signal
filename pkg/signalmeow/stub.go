package signalmeow

import (
	"log"
	"os"

	_ "github.com/mattn/go-sqlite3"
	"github.com/mdp/qrterminal/v3"
	"go.mau.fi/mautrix-signal/pkg/signalmeow/store"
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
	//device := devices[0]

	// Start message receiver
	// open websocket
	//ctx, cancel := context.WithCancel(context.Background())
	//ws, resp, err := openWebsocket(ctx, "/v1/websocket/?login=true")
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
