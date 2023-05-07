package signalmeow

import (
	"fmt"
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
	provChan := PerformProvisioning(sqlStore)

	// First get the provisioning URL
	resp := <-provChan
	if resp.Err != nil {
		log.Printf("PerformProvisioning error: %v", resp.Err)
		return
	}
	if resp.ProvisioningUrl != "" {
		qrterminal.Generate(resp.ProvisioningUrl, qrterminal.M, os.Stdout)
	}

	// Next, get the results of finishing registration
	resp = <-provChan
	if resp.Err != nil {
		log.Printf("PerformProvisioning error: %v", resp.Err)
		return
	}
	if resp.ProvisioningData != nil {
		// Persist necessary data
		log.Printf("provisioningData: %v", resp.ProvisioningData)
	}

	// Now, generate and register the prekeys
	aciPreKeys := GeneratePreKeys(0, 0, 100, resp.ProvisioningData.AciIdentityKeyPair, "aci")
	pniPreKeys := GeneratePreKeys(0, 0, 100, resp.ProvisioningData.PniIdentityKeyPair, "pni")

	username := resp.ProvisioningData.Number
	if resp.ProvisioningData.AciUuid != "" {
		username = resp.ProvisioningData.AciUuid
	}
	username = username + "." + fmt.Sprint(resp.ProvisioningData.DeviceId)
	regErr := RegisterPreKeys(aciPreKeys, "aci", username, resp.ProvisioningData.Password)
	if regErr != nil {
		log.Printf("RegisterPreKeys error: %v", regErr)
		return
	}
	regErr = RegisterPreKeys(pniPreKeys, "pni", username, resp.ProvisioningData.Password)
	if regErr != nil {
		log.Printf("RegisterPreKeys error: %v", regErr)
		return
	}

	// Persist prekeys
	log.Printf("aciPreKeys: %v", aciPreKeys)
	log.Printf("pniPreKeys: %v", pniPreKeys)
}
