// mautrix-signal - A Matrix-signal puppeting bridge.
// Copyright (C) 2023 Scott Weber
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU Affero General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.
//
// This program is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
// GNU Affero General Public License for more details.
//
// You should have received a copy of the GNU Affero General Public License
// along with this program.  If not, see <https://www.gnu.org/licenses/>.

package signalmeow

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/hmac"
	"crypto/sha256"
	"errors"
	"fmt"
	"io"
	"math"
	"net/http"

	"github.com/rs/zerolog/log"
	"go.mau.fi/util/random"

	signalpb "go.mau.fi/mautrix-signal/pkg/signalmeow/protobuf"
	"go.mau.fi/mautrix-signal/pkg/signalmeow/web"
)

// *** Attachments! ***

// Attachment represents an attachment received from a peer
type Attachment struct {
	R        io.Reader
	MimeType string
	FileName string
}

func getAttachmentPath(id uint64, key string, cdnNumber uint32) (string, error) {
	const (
		attachmentKeyDownloadPath = "/attachments/%s"
		attachmentIDDownloadPath  = "/attachments/%d"
	)
	if id != 0 {
		return fmt.Sprintf(attachmentIDDownloadPath, id), nil
	}
	return fmt.Sprintf(attachmentKeyDownloadPath, key), nil
}

// ErrInvalidMACForAttachment signals that the downloaded attachment has an invalid MAC.
var ErrInvalidMACForAttachment = errors.New("invalid MAC for attachment")
var ErrInvalidDigestForAttachment = errors.New("invalid digest for attachment")

func DownloadAttachment(a *signalpb.AttachmentPointer) ([]byte, error) {
	path, err := getAttachmentPath(a.GetCdnId(), a.GetCdnKey(), a.GetCdnNumber())
	if err != nil {
		return nil, err
	}
	resp, err := web.GetAttachment(path, a.GetCdnNumber(), nil)
	if err != nil {
		return nil, err
	}
	bodyReader := resp.Body
	defer bodyReader.Close()

	body, err := io.ReadAll(bodyReader)
	if err != nil {
		return nil, err
	}

	return decryptAttachment(body, a.Key, a.Digest, *a.Size)
}

func decryptAttachment(body, key, digest []byte, size uint32) ([]byte, error) {
	hash := sha256.Sum256(body)
	if !hmac.Equal(hash[:], digest) {
		return nil, ErrInvalidDigestForAttachment
	}
	l := len(body) - 32
	if !verifyMAC(key[32:], body[:l], body[l:]) {
		return nil, ErrInvalidMACForAttachment
	}

	decrypted, err := aesDecrypt(key[:32], body[:l])
	if err != nil {
		return nil, err
	}
	if len(decrypted) < int(size) {
		return nil, fmt.Errorf("decrypted attachment length %v < expected %v", len(decrypted), size)
	}
	return decrypted[:size], nil
}

type attachmentV3UploadAttributes struct {
	Cdn                  uint32            `json:"cdn"`
	Key                  string            `json:"key"`
	Headers              map[string]string `json:"headers"`
	SignedUploadLocation string            `json:"signedUploadLocation"`
}

func UploadAttachment(device *Device, body []byte) (*signalpb.AttachmentPointer, error) {
	keys := random.Bytes(64) // combined AES and MAC keys
	plaintextLength := uint32(len(body))

	// Padded length uses exponential bracketing
	paddedLen := int(math.Max(541, math.Floor(math.Pow(1.05, math.Ceil(math.Log(float64(len(body)))/math.Log(1.05))))))
	if paddedLen < len(body) {
		log.Debug().Msgf("encryptAndUploadAttachment paddedLen %v < len %v. Continuing with a privacy risk.", paddedLen, len(body))
	} else {
		body = append(body, bytes.Repeat([]byte{0}, int(paddedLen)-len(body))...)
	}

	encrypted, err := aesEncrypt(keys[:32], body)
	if err != nil {
		return nil, err
	}
	encryptedWithMAC := appendMAC(keys[32:], encrypted)

	// Get upload attributes from Signal server
	attributesPath := "/v3/attachments/form/upload"
	username, password := device.Data.BasicAuthCreds()
	opts := &web.HTTPReqOpt{Username: &username, Password: &password}
	resp, err := web.SendHTTPRequest(http.MethodGet, attributesPath, opts)
	if err != nil {
		log.Err(err).Msg("Error sending request fetching upload attributes")
		return nil, err
	}
	var uploadAttributes attachmentV3UploadAttributes
	err = web.DecodeHTTPResponseBody(&uploadAttributes, resp)
	if err != nil {
		log.Err(err).Msg("Error decoding response body fetching upload attributes")
		return nil, err
	}

	// Allocate attachment on CDN
	resp, err = web.SendHTTPRequest(http.MethodPost, "", &web.HTTPReqOpt{
		OverrideURL: uploadAttributes.SignedUploadLocation,
		ContentType: web.ContentTypeOctetStream,
		Headers:     uploadAttributes.Headers,
		Username:    &username,
		Password:    &password,
	})
	if err != nil {
		log.Err(err).Msg("Error sending request allocating attachment")
		return nil, err
	}
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		err := fmt.Errorf("Error allocating attachment: %v", resp.Status)
		log.Err(err).Msg("Error allocating attachment")
		return nil, err
	}

	// Upload attachment to CDN
	resp, err = web.SendHTTPRequest(http.MethodPut, "", &web.HTTPReqOpt{
		OverrideURL: resp.Header.Get("Location"),
		Body:        encryptedWithMAC,
		ContentType: web.ContentTypeOctetStream,
		Username:    &username,
		Password:    &password,
	})
	if err != nil {
		log.Err(err).Msg("Error sending request uploading attachment")
		return nil, err
	}
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		err := fmt.Errorf("Error uploading attachment: %v", resp.Status)
		log.Err(err).Msg("Error uploading attachment")
		return nil, err
	}

	digest := sha256.Sum256(encryptedWithMAC)

	attachmentPointer := &signalpb.AttachmentPointer{
		AttachmentIdentifier: &signalpb.AttachmentPointer_CdnKey{
			CdnKey: uploadAttributes.Key,
		},
		Key:       keys,
		Digest:    digest[:],
		Size:      &plaintextLength,
		CdnNumber: &uploadAttributes.Cdn,
	}

	return attachmentPointer, nil
}

func verifyMAC(key, body, mac []byte) bool {
	m := hmac.New(sha256.New, key)
	m.Write(body)
	return hmac.Equal(m.Sum(nil), mac)
}

func aesDecrypt(key, ciphertext []byte) ([]byte, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}

	if len(ciphertext)%aes.BlockSize != 0 {
		length := len(ciphertext) % aes.BlockSize
		log.Debug().Msgf("aesDecrypt ciphertext not multiple of AES blocksize: %v", length)
		return nil, errors.New("ciphertext not multiple of AES blocksize")
	}

	iv := ciphertext[:aes.BlockSize]
	mode := cipher.NewCBCDecrypter(block, iv)
	mode.CryptBlocks(ciphertext, ciphertext)
	pad := ciphertext[len(ciphertext)-1]
	if pad > aes.BlockSize {
		return nil, fmt.Errorf("pad value (%d) larger than AES blocksize (%d)", pad, aes.BlockSize)
	}
	return ciphertext[aes.BlockSize : len(ciphertext)-int(pad)], nil
}

func appendMAC(key, body []byte) []byte {
	m := hmac.New(sha256.New, key)
	m.Write(body)
	return m.Sum(body)
}

func aesEncrypt(key, plaintext []byte) ([]byte, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}

	pad := aes.BlockSize - len(plaintext)%aes.BlockSize
	plaintext = append(plaintext, bytes.Repeat([]byte{byte(pad)}, pad)...)

	ciphertext := make([]byte, len(plaintext))
	iv := random.Bytes(16)

	mode := cipher.NewCBCEncrypter(block, iv)
	mode.CryptBlocks(ciphertext, plaintext)

	return append(iv, ciphertext...), nil
}
