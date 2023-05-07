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
	provChan := PerformProvisioning(sqlStore, sqlStore)

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
