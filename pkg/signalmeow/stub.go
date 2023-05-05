package signalmeow

import (
	"fmt"
	"log"
	"os"

	"github.com/mdp/qrterminal/v3"
	"go.mau.fi/mautrix-signal/pkg/libsignalgo"
)

func Main() {
	provChan := PerformProvisioning()

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
	err := RegisterPreKeys(aciPreKeys, "aci", username, resp.ProvisioningData.Password)
	if err != nil {
		log.Printf("RegisterPreKeys error: %v", err)
		return
	}
	err = RegisterPreKeys(pniPreKeys, "pni", username, resp.ProvisioningData.Password)
	if err != nil {
		log.Printf("RegisterPreKeys error: %v", err)
		return
	}

	// Persist prekeys
	log.Printf("aciPreKeys: %v", aciPreKeys)
	log.Printf("pniPreKeys: %v", pniPreKeys)
}

type AccountStore interface {
	SaveProvisioningData(aciUuid string, pd *ProvisioningData) error
	ProvisioningData(aciUuid string) (*ProvisioningData, error)
}

type PreKeyStore interface {
	SavePreKey(aciUuid string, uuidKind string, preKey *libsignalgo.PreKeyRecord) error
	PreKey(aciUuid string, uuidKind string, preKeyId int) (*libsignalgo.PreKeyRecord, error)
	RemovePreKey(aciUuid string, uuidKind string, preKeyId int) error
	SaveSignedPreKey(aciUuid string, uuidKind string, preKey *libsignalgo.PreKeyRecord) error
	PreSignedKey(aciUuid string, uuidKind string, preKeyId int) (*libsignalgo.PreKeyRecord, error)
	RemoveSignedPreKey(aciUuid string, uuidKind string, preKeyId int) error
}
