package signalmeow

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/hmac"
	"crypto/sha256"
	"fmt"
	"io"

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
			zlog.Err(err).Msg("")
			zlog.Fatal().Msg("Unable to generate key pair")
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

func (c *ProvisioningCipher) Decrypt(env *signalpb.ProvisionEnvelope) (*signalpb.ProvisionMessage, error) {
	masterEphemeral, err := libsignalgo.DeserializePublicKey(env.GetPublicKey())
	if err != nil {
		zlog.Err(err).Msg("Unable to deserialize public key")
		return nil, err
	}
	if masterEphemeral == nil {
		err = fmt.Errorf("No public key: %v", env)
		zlog.Err(err).Msg("")
		return nil, err
	}
	body := env.GetBody()
	if body == nil {
		err = fmt.Errorf("No body: %v", env)
		zlog.Err(err).Msg("")
		return nil, err
	}
	if body[0] != 1 {
		err = fmt.Errorf("Invalid ProvisionMessage version: %v", body[0])
		zlog.Err(err).Msg("")
		return nil, err
	}
	bodyLen := uint(len(body))
	iv := body[IV_OFFSET : IV_OFFSET+IV_LENGTH]
	mac := body[bodyLen-MAC_SIZE : bodyLen]
	if uint(len(mac)) != MAC_SIZE {
		err = fmt.Errorf("Invalid MAC size: %v", len(mac))
		zlog.Err(err).Msg("")
		return nil, err
	}
	if uint(len(iv)) != IV_LENGTH {
		err = fmt.Errorf("Invalid IV size: %v", len(iv))
		zlog.Err(err).Msg("")
		return nil, err
	}
	cipherText := body[CIPHERTEXT_OFFSET : bodyLen-CIPHER_KEY_SIZE]
	ivAndCipherText := body[0 : bodyLen-CIPHER_KEY_SIZE]

	agreement, err := c.keyPair.GetPrivateKey().Agree(masterEphemeral)
	if err != nil {
		zlog.Err(err).Msg("Unable to agree on key")
		return nil, err
	}

	sharedSecrets := make([]byte, 64)
	hkdfReader := hkdf.New(sha256.New, agreement, nil, []byte("TextSecure Provisioning Message"))

	if _, err := io.ReadFull(hkdfReader, sharedSecrets); err != nil {
		zlog.Err(err).Msg("Unable to read from hkdfReader")
	}

	parts1 := sharedSecrets[:32]
	parts2 := sharedSecrets[32:]

	verifier := hmac.New(sha256.New, parts2)
	verifier.Write(ivAndCipherText)
	ourMac := verifier.Sum(nil)
	if len(ourMac) != len(mac) {
		err = fmt.Errorf("Invalid MAC length: ourmac:%v mac:%v", len(ourMac), len(mac))
		zlog.Err(err).Msg("")
	}
	if !hmac.Equal(ourMac[:32], mac) {
		err = fmt.Errorf("Invalid MAC: %v", ourMac)
		zlog.Err(err).Msg("")
	}

	block, err := aes.NewCipher(parts1)
	if err != nil {
		zlog.Err(err).Msg("Unable to create cipher")
		return nil, err
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
		zlog.Err(err).Msg("Unable to unmarshal ProvisionMessage")
		return nil, err
	}

	return message, nil
}
