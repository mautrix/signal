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
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/hmac"
	"crypto/sha256"
	"errors"
	"fmt"
	"io"
	"math"
	"mime/multipart"
	"net/http"

	"github.com/rs/zerolog"
	"go.mau.fi/util/random"
	"google.golang.org/protobuf/proto"

	"go.mau.fi/mautrix-signal/pkg/libsignalgo"
	signalpb "go.mau.fi/mautrix-signal/pkg/signalmeow/protobuf"
	"go.mau.fi/mautrix-signal/pkg/signalmeow/types"
	"go.mau.fi/mautrix-signal/pkg/signalmeow/web"
)

const (
	attachmentKeyDownloadPath = "/attachments/%s"
	attachmentIDDownloadPath  = "/attachments/%d"
)

func getAttachmentPath(id uint64, key string, cdnNumber uint32) (string, error) {
	if id != 0 {
		return fmt.Sprintf(attachmentIDDownloadPath, id), nil
	}
	return fmt.Sprintf(attachmentKeyDownloadPath, key), nil
}

// ErrInvalidMACForAttachment signals that the downloaded attachment has an invalid MAC.
var ErrInvalidMACForAttachment = errors.New("invalid MAC for attachment")
var ErrInvalidDigestForAttachment = errors.New("invalid digest for attachment")

func DownloadAttachment(ctx context.Context, a *signalpb.AttachmentPointer) ([]byte, error) {
	path, err := getAttachmentPath(a.GetCdnId(), a.GetCdnKey(), a.GetCdnNumber())
	if err != nil {
		return nil, err
	}
	resp, err := web.GetAttachment(ctx, path, a.GetCdnNumber(), nil)
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

func extend(data []byte, paddedLen int) []byte {
	origLen := len(data)
	if cap(data) >= paddedLen {
		data = data[:paddedLen]
		for i := origLen; i < paddedLen; i++ {
			data[i] = 0
		}
		return data
	} else {
		newData := make([]byte, paddedLen)
		copy(newData, data)
		return newData
	}
}

func (cli *Client) UploadAttachment(ctx context.Context, body []byte) (*signalpb.AttachmentPointer, error) {
	log := zerolog.Ctx(ctx).With().Str("func", "upload attachment").Logger()
	keys := random.Bytes(64) // combined AES and MAC keys
	plaintextLength := uint32(len(body))

	// Padded length uses exponential bracketing
	paddedLen := int(math.Max(541, math.Floor(math.Pow(1.05, math.Ceil(math.Log(float64(len(body)))/math.Log(1.05))))))
	if paddedLen < len(body) {
		log.Panic().
			Int("padded_len", paddedLen).
			Int("len", len(body)).
			Msg("Math error: padded length is less than body length")
	}
	body = extend(body, paddedLen)

	encrypted, err := aesEncrypt(keys[:32], body)
	if err != nil {
		return nil, err
	}
	encryptedWithMAC := appendMAC(keys[32:], encrypted)

	// Get upload attributes from Signal server
	attributesPath := "/v3/attachments/form/upload"
	username, password := cli.Store.BasicAuthCreds()
	opts := &web.HTTPReqOpt{Username: &username, Password: &password}
	resp, err := web.SendHTTPRequest(ctx, http.MethodGet, attributesPath, opts)
	if err != nil {
		log.Err(err).Msg("Error sending request fetching upload attributes")
		return nil, err
	}
	var uploadAttributes attachmentV3UploadAttributes
	err = web.DecodeHTTPResponseBody(ctx, &uploadAttributes, resp)
	if err != nil {
		log.Err(err).Msg("Error decoding response body fetching upload attributes")
		return nil, err
	}

	// Allocate attachment on CDN
	resp, err = web.SendHTTPRequest(ctx, http.MethodPost, "", &web.HTTPReqOpt{
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
		log.Error().Int("status_code", resp.StatusCode).Msg("Error allocating attachment")
		return nil, fmt.Errorf("error allocating attachment: %s", resp.Status)
	}

	// Upload attachment to CDN
	resp, err = web.SendHTTPRequest(ctx, http.MethodPut, "", &web.HTTPReqOpt{
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
		log.Error().Int("status_code", resp.StatusCode).Msg("Error uploading attachment")
		return nil, fmt.Errorf("error uploading attachment: %s", resp.Status)
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

func (cli *Client) UploadGroupAvatar(ctx context.Context, avatarBytes []byte, gid types.GroupIdentifier) (*string, error) {
	log := zerolog.Ctx(ctx)
	groupMasterKey, err := cli.Store.GroupStore.MasterKeyFromGroupIdentifier(ctx, gid)
	if err != nil {
		log.Err(err).Msg("Could not get master key from group id")
		return nil, err
	}
	groupAuth, err := cli.GetAuthorizationForToday(ctx, masterKeyToBytes(groupMasterKey))
	if err != nil {
		log.Err(err).Msg("Failed to get Authorization for today")
		return nil, err
	}
	groupSecretParams, err := libsignalgo.DeriveGroupSecretParamsFromMasterKey(masterKeyToBytes(groupMasterKey))
	if err != nil {
		log.Err(err).Msg("Could not get groupSecretParams from master key")
		return nil, err
	}
	attributeBlob := signalpb.GroupAttributeBlob{Content: &signalpb.GroupAttributeBlob_Avatar{Avatar: avatarBytes}}
	encryptedAvatar, err := encryptBlobIntoGroupProperty(groupSecretParams, &attributeBlob)
	if err != nil {
		log.Err(err).Msg("Could not encrypt avatar into Group Property")
		return nil, err
	}

	// Get upload form from Signal server
	formPath := "/v1/groups/avatar/form"
	opts := &web.HTTPReqOpt{Username: &groupAuth.Username, Password: &groupAuth.Password, ContentType: web.ContentTypeProtobuf, Host: web.StorageHostname}
	resp, err := web.SendHTTPRequest(ctx, http.MethodGet, formPath, opts)
	if err != nil {
		log.Err(err).Msg("Error sending request fetching avatar upload form")
		return nil, err
	}
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		log.Err(err).Msg("Error decoding response body fetching upload attributes")
		return nil, err
	}
	uploadForm := signalpb.AvatarUploadAttributes{}
	err = proto.Unmarshal(body, &uploadForm)
	if err != nil {
		log.Err(err).Msg("failed to unmarshal group avatar upload form")
		return nil, err
	}
	requestBody := &bytes.Buffer{}
	w := multipart.NewWriter(requestBody)
	w.WriteField("key", uploadForm.Key)
	w.WriteField("x-amz-credential", uploadForm.Credential)
	w.WriteField("acl", uploadForm.Acl)
	w.WriteField("x-amz-algorithm", uploadForm.Algorithm)
	w.WriteField("x-amz-date", uploadForm.Date)
	w.WriteField("policy", uploadForm.Policy)
	w.WriteField("x-amz-signature", uploadForm.Signature)
	w.WriteField("Content-Type", "application/octet-stream")
	filewriter, _ := w.CreateFormFile("file", "file")
	filewriter.Write(*encryptedAvatar)
	w.Close()

	// Upload avatar to CDN
	resp, err = web.SendHTTPRequest(ctx, http.MethodPost, "", &web.HTTPReqOpt{
		Body:        requestBody.Bytes(),
		ContentType: web.ContentType(w.FormDataContentType()),
		Host:        web.CDN1Hostname,
	})
	if err != nil {
		log.Err(err).Msg("Error sending request uploading attachment")
		return nil, err
	}
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		log.Error().Int("status_code", resp.StatusCode).Msg("Error uploading attachment")
		return nil, fmt.Errorf("error uploading attachment: %s", resp.Status)
	}

	return &uploadForm.Key, nil
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
		return nil, fmt.Errorf("ciphertext not multiple of AES blocksize (%d extra bytes)", len(ciphertext)%aes.BlockSize)
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
