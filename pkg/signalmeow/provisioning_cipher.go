package signalmeow

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/hmac"
	"crypto/sha256"
	"io"
	"log"

	"go.mau.fi/mautrix-signal/pkg/libsignalgo"
	signalpb "go.mau.fi/mautrix-signal/pkg/signalmeow/protobuf"
	"golang.org/x/crypto/hkdf"
	"google.golang.org/protobuf/proto"
)

type ProvisioningCipher struct {
	keyPair *libsignalgo.IdentityKeyPair
}

func NewProvisioningCipher() *ProvisioningCipher {
	return &ProvisioningCipher{}
}

func (c *ProvisioningCipher) GetPublicKey() *libsignalgo.PublicKey {
	if c.keyPair == nil {
		keyPair, err := libsignalgo.GenerateIdentityKeyPair()
		if err != nil {
			log.Printf("Unable to generate key pair")
			log.Fatal(err)
		}
		c.keyPair = keyPair
	}
	return c.keyPair.GetPublicKey()
}

const SUPPORTED_VERSION uint8 = 1
const CIPHER_KEY_SIZE uint = 32
const MAC_SIZE uint = 32

const VERSION_OFFSET uint = 0
const VERSION_LENGTH uint = 1
const IV_OFFSET uint = VERSION_OFFSET + VERSION_LENGTH
const IV_LENGTH uint = 16
const CIPHERTEXT_OFFSET uint = IV_OFFSET + IV_LENGTH

func (c *ProvisioningCipher) Decrypt(env *signalpb.ProvisionEnvelope) *signalpb.ProvisionMessage {
	masterEphemeral, err := libsignalgo.DeserializePublicKey(env.GetPublicKey())
	if err != nil {
		log.Fatalf("Unable to deserialize public key: %v", err)
	}
	if masterEphemeral == nil {
		log.Fatalf("No public key: %v", env)
	}
	body := env.GetBody()
	if body == nil {
		log.Fatalf("No body: %v", env)
	}
	if body[0] != 1 {
		log.Fatalf("Invalid ProvisionMessage version: %v", body[0])
	}
	bodyLen := uint(len(body))
	log.Printf("bodyLen: %v", bodyLen)
	iv := body[IV_OFFSET : IV_OFFSET+IV_LENGTH]
	mac := body[bodyLen-MAC_SIZE : bodyLen]
	if uint(len(mac)) != MAC_SIZE {
		log.Fatalf("Invalid MAC size: %v", len(mac))
	}
	if uint(len(iv)) != IV_LENGTH {
		log.Fatalf("Invalid IV size: %v", len(iv))
	}
	cipherText := body[CIPHERTEXT_OFFSET : bodyLen-CIPHER_KEY_SIZE]
	ivAndCipherText := body[0 : bodyLen-CIPHER_KEY_SIZE]

	agreement, err := c.keyPair.GetPrivateKey().Agree(masterEphemeral)
	if err != nil {
		log.Fatalf("Unable to agree on key: %v", err)
	}

	sharedSecrets := make([]byte, 64)
	hkdfReader := hkdf.New(sha256.New, agreement, nil, []byte("TextSecure Provisioning Message"))

	if _, err := io.ReadFull(hkdfReader, sharedSecrets); err != nil {
		log.Fatalf("Unable to read from hkdfReader: %v", err)
	}

	parts1 := sharedSecrets[:32]
	parts2 := sharedSecrets[32:]

	verifier := hmac.New(sha256.New, parts2)
	verifier.Write(ivAndCipherText)
	ourMac := verifier.Sum(nil)
	if len(ourMac) != len(mac) {
		log.Fatalf("Invalid MAC length: ourmac:%v mac:%v", len(ourMac), len(mac))
	}
	if !hmac.Equal(ourMac[:32], mac) {
		log.Fatalf("Invalid MAC: %v", ourMac)
	}

	block, err := aes.NewCipher(parts1)
	if err != nil {
		log.Fatalf("Unable to create cipher: %v", err)
	}

	mode := cipher.NewCBCDecrypter(block, iv)
	paddedInput := make([]byte, len(cipherText))
	mode.CryptBlocks(paddedInput, cipherText)

	//input, err := pkcs7.Unpad(paddedInput)
	//if err != nil {
	//	return nil, errors.New("provisioning: CBC/Padding error: " + err.Error())
	//}
	input := paddedInput

	message := &signalpb.ProvisionMessage{}
	err = proto.Unmarshal(input, message)
	if err != nil {
		log.Fatalf("Unable to unmarshal ProvisionMessage: %v", err)
	}

	return message
}
