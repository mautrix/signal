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

package libsignalgo

/*
#cgo LDFLAGS: -lsignal_ffi -ldl -lm
#include "./libsignal-ffi.h"
*/
import "C"
import (
	"context"
	"runtime"
	"time"

	"github.com/google/uuid"
)

type SealedSenderAddress struct {
	E164     string
	UUID     uuid.UUID
	DeviceID uint32
}

func NewSealedSenderAddress(e164 string, uuid uuid.UUID, deviceID uint32) *SealedSenderAddress {
	return &SealedSenderAddress{
		E164:     e164,
		UUID:     uuid,
		DeviceID: deviceID,
	}
}

func SealedSenderEncryptPlaintext(ctx context.Context, message []byte, forAddress *Address, fromSenderCert *SenderCertificate, sessionStore SessionStore, identityStore IdentityKeyStore) ([]byte, error) {
	ciphertextMessage, err := Encrypt(ctx, message, forAddress, sessionStore, identityStore)
	if err != nil {
		return nil, err
	}

	usmc, err := NewUnidentifiedSenderMessageContent(
		ciphertextMessage,
		fromSenderCert,
		UnidentifiedSenderMessageContentHintDefault,
		nil,
	)
	if err != nil {
		return nil, err
	}
	return SealedSenderEncrypt(ctx, usmc, forAddress, identityStore)
}

func SealedSenderEncrypt(ctx context.Context, usmc *UnidentifiedSenderMessageContent, forRecipient *Address, identityStore IdentityKeyStore) ([]byte, error) {
	var encrypted C.SignalOwnedBuffer = C.SignalOwnedBuffer{}
	callbackCtx := NewCallbackContext(ctx)
	defer callbackCtx.Unref()
	signalFfiError := C.signal_sealed_session_cipher_encrypt(
		&encrypted,
		forRecipient.ptr,
		usmc.ptr,
		callbackCtx.wrapIdentityKeyStore(identityStore),
	)
	runtime.KeepAlive(usmc)
	runtime.KeepAlive(forRecipient)
	if signalFfiError != nil {
		return nil, callbackCtx.wrapError(signalFfiError)
	}
	return CopySignalOwnedBufferToBytes(encrypted), nil
}

func SealedSenderMultiRecipientEncrypt(messageContent *UnidentifiedSenderMessageContent, forRecipients []*Address, identityStore IdentityKeyStore, sessionStore SessionStore, ctx *CallbackContext) ([]byte, error) {
	panic("not implemented")
}

type SealedSenderResult struct {
	Message []byte
	Sender  SealedSenderAddress
}

func SealedSenderDecryptToUSMC(
	ctx context.Context,
	ciphertext []byte,
	identityStore IdentityKeyStore,
) (*UnidentifiedSenderMessageContent, error) {
	callbackCtx := NewCallbackContext(ctx)
	defer callbackCtx.Unref()
	var usmc *C.SignalUnidentifiedSenderMessageContent = nil
	signalFfiError := C.signal_sealed_session_cipher_decrypt_to_usmc(
		&usmc,
		BytesToBuffer(ciphertext),
		callbackCtx.wrapIdentityKeyStore(identityStore),
	)
	runtime.KeepAlive(ciphertext)
	if signalFfiError != nil {
		return nil, callbackCtx.wrapError(signalFfiError)
	}
	return wrapUnidentifiedSenderMessageContent(usmc), nil
}

func SealedSenderDecrypt(
	ctx context.Context,
	ciphertext []byte,
	localAddress *SealedSenderAddress,
	trustRoot *PublicKey,
	timestamp time.Time,
	sessionStore SessionStore,
	identityStore IdentityKeyStore,
	preKeyStore PreKeyStore,
	signedPreKeyStore SignedPreKeyStore,
) (result SealedSenderResult, err error) {
	callbackCtx := NewCallbackContext(ctx)
	defer callbackCtx.Unref()

	var decrypted C.SignalOwnedBuffer = C.SignalOwnedBuffer{}
	var senderE164 *C.char
	var senderUUID *C.char
	var senderDeviceID C.uint32_t

	signalFfiError := C.signal_sealed_session_cipher_decrypt(
		&decrypted,
		&senderE164,
		&senderUUID,
		&senderDeviceID,
		BytesToBuffer(ciphertext),
		trustRoot.ptr,
		C.uint64_t(timestamp.UnixMilli()),
		C.CString(localAddress.E164),
		C.CString(localAddress.UUID.String()),
		C.uint32_t(localAddress.DeviceID),
		callbackCtx.wrapSessionStore(sessionStore),
		callbackCtx.wrapIdentityKeyStore(identityStore),
		callbackCtx.wrapPreKeyStore(preKeyStore),
		callbackCtx.wrapSignedPreKeyStore(signedPreKeyStore),
	)
	runtime.KeepAlive(localAddress)
	runtime.KeepAlive(trustRoot)
	if signalFfiError != nil {
		err = callbackCtx.wrapError(signalFfiError)
		return
	}

	defer C.signal_free_string(senderE164)
	defer C.signal_free_string(senderUUID)

	return SealedSenderResult{
		Message: CopySignalOwnedBufferToBytes(decrypted),
		Sender: SealedSenderAddress{
			E164:     C.GoString(senderE164),
			UUID:     uuid.MustParse(C.GoString(senderUUID)),
			DeviceID: uint32(senderDeviceID),
		},
	}, nil
}

type UnidentifiedSenderMessageContentHint uint32

const (
	UnidentifiedSenderMessageContentHintDefault    UnidentifiedSenderMessageContentHint = 0
	UnidentifiedSenderMessageContentHintResendable UnidentifiedSenderMessageContentHint = 1
	UnidentifiedSenderMessageContentHintImplicit   UnidentifiedSenderMessageContentHint = 2
)

type UnidentifiedSenderMessageContent struct {
	nc  noCopy
	ptr *C.SignalUnidentifiedSenderMessageContent
}

func wrapUnidentifiedSenderMessageContent(ptr *C.SignalUnidentifiedSenderMessageContent) *UnidentifiedSenderMessageContent {
	messageContent := &UnidentifiedSenderMessageContent{ptr: ptr}
	runtime.SetFinalizer(messageContent, (*UnidentifiedSenderMessageContent).Destroy)
	return messageContent
}

func NewUnidentifiedSenderMessageContent(message *CiphertextMessage, senderCertificate *SenderCertificate, contentHint UnidentifiedSenderMessageContentHint, groupID []byte) (*UnidentifiedSenderMessageContent, error) {
	var usmc *C.SignalUnidentifiedSenderMessageContent
	signalFfiError := C.signal_unidentified_sender_message_content_new(&usmc, message.ptr, senderCertificate.ptr, C.uint32_t(contentHint), BytesToBuffer(groupID))
	runtime.KeepAlive(message)
	runtime.KeepAlive(senderCertificate)
	runtime.KeepAlive(groupID)
	if signalFfiError != nil {
		return nil, wrapError(signalFfiError)
	}
	return wrapUnidentifiedSenderMessageContent(usmc), nil
}

//func NewUnidentifiedSenderMessageContentFromMessage(sealedSenderMessage []byte, identityStore IdentityKeyStore, ctx *CallbackContext) (*UnidentifiedSenderMessageContent, error) {
//	contextPtr := gopointer.Save(ctx)
//	defer gopointer.Unref(contextPtr)
//
//	var usmc *C.SignalUnidentifiedSenderMessageContent
//
//	signalFfiError := C.signal_sealed_session_cipher_decrypt_to_usmc(
//		&usmc,
//		BytesToBuffer(sealedSenderMessage),
//		wrapIdentityKeyStore(identityStore),
//		contextPtr,
//	)
//	if signalFfiError != nil {
//		return nil, wrapError(signalFfiError)
//	}
//	return wrapUnidentifiedSenderMessageContent(usmc), nil
//}

func DeserializeUnidentifiedSenderMessageContent(serialized []byte) (*UnidentifiedSenderMessageContent, error) {
	var usmc *C.SignalUnidentifiedSenderMessageContent
	signalFfiError := C.signal_unidentified_sender_message_content_deserialize(&usmc, BytesToBuffer(serialized))
	runtime.KeepAlive(serialized)
	if signalFfiError != nil {
		return nil, wrapError(signalFfiError)
	}
	return wrapUnidentifiedSenderMessageContent(usmc), nil
}

func (usmc *UnidentifiedSenderMessageContent) Destroy() error {
	usmc.CancelFinalizer()
	return wrapError(C.signal_unidentified_sender_message_content_destroy(usmc.ptr))
}

func (usmc *UnidentifiedSenderMessageContent) CancelFinalizer() {
	runtime.SetFinalizer(usmc, nil)
}

func (usmc *UnidentifiedSenderMessageContent) Serialize() ([]byte, error) {
	var serialized C.SignalOwnedBuffer = C.SignalOwnedBuffer{}
	signalFfiError := C.signal_unidentified_sender_message_content_serialize(&serialized, usmc.ptr)
	runtime.KeepAlive(usmc)
	if signalFfiError != nil {
		return nil, wrapError(signalFfiError)
	}
	return CopySignalOwnedBufferToBytes(serialized), nil
}

func (usmc *UnidentifiedSenderMessageContent) GetContents() ([]byte, error) {
	var contents C.SignalOwnedBuffer = C.SignalOwnedBuffer{}
	signalFfiError := C.signal_unidentified_sender_message_content_get_contents(&contents, usmc.ptr)
	runtime.KeepAlive(usmc)
	if signalFfiError != nil {
		return nil, wrapError(signalFfiError)
	}
	return CopySignalOwnedBufferToBytes(contents), nil
}

//func (usmc *UnidentifiedSenderMessageContent) GetGroupID() ([]byte, error) {
//	var groupID *C.uchar
//	var length C.ulong
//	signalFfiError := C.signal_unidentified_sender_message_content_get_group_id(&groupID, &length, usmc.ptr)
//	if signalFfiError != nil {
//		return nil, wrapError(signalFfiError)
//	}
//	if groupID == nil {
//		return nil, nil
//	}
//	return CopyBufferToBytes(groupID, length), nil
//}

func (usmc *UnidentifiedSenderMessageContent) GetSenderCertificate() (*SenderCertificate, error) {
	var senderCertificate *C.SignalSenderCertificate
	signalFfiError := C.signal_unidentified_sender_message_content_get_sender_cert(&senderCertificate, usmc.ptr)
	runtime.KeepAlive(usmc)
	if signalFfiError != nil {
		return nil, wrapError(signalFfiError)
	}
	return wrapSenderCertificate(senderCertificate), nil
}

func (usmc *UnidentifiedSenderMessageContent) GetMessageType() (CiphertextMessageType, error) {
	var messageType C.uint8_t
	signalFfiError := C.signal_unidentified_sender_message_content_get_msg_type(&messageType, usmc.ptr)
	runtime.KeepAlive(usmc)
	if signalFfiError != nil {
		return 0, wrapError(signalFfiError)
	}
	return CiphertextMessageType(messageType), nil
}

func (usmc *UnidentifiedSenderMessageContent) GetContentHint() (UnidentifiedSenderMessageContentHint, error) {
	var contentHint C.uint32_t
	signalFfiError := C.signal_unidentified_sender_message_content_get_content_hint(&contentHint, usmc.ptr)
	runtime.KeepAlive(usmc)
	if signalFfiError != nil {
		return 0, wrapError(signalFfiError)
	}
	return UnidentifiedSenderMessageContentHint(contentHint), nil
}
