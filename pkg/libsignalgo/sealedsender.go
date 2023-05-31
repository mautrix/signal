package libsignalgo

/*
#cgo LDFLAGS: -lsignal_ffi -ldl
#include "./libsignal-ffi.h"
*/
import "C"
import (
	"runtime"
	"time"

	"github.com/google/uuid"
	gopointer "github.com/mattn/go-pointer"
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

func SealedSenderEncryptPlaintext(message []byte, forAddress *Address, fromSenderCert *SenderCertificate, sessionStore SessionStore, identityStore IdentityKeyStore, ctx *CallbackContext) ([]byte, error) {
	ciphertextMessage, err := Encrypt(message, forAddress, sessionStore, identityStore, ctx)
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
	return SealedSenderEncrypt(usmc, forAddress, identityStore, ctx)
}

func SealedSenderEncrypt(messageContent *UnidentifiedSenderMessageContent, forRecipient *Address, identityStore IdentityKeyStore, ctx *CallbackContext) ([]byte, error) {
	contextPointer := gopointer.Save(ctx)
	defer gopointer.Unref(contextPointer)

	var encrypted *C.uchar
	var length C.ulong
	signalFfiError := C.signal_sealed_session_cipher_encrypt(
		&encrypted,
		&length,
		forRecipient.ptr,
		messageContent.ptr,
		wrapIdentityKeyStore(identityStore),
		contextPointer,
	)
	if signalFfiError != nil {
		return nil, wrapCallbackError(signalFfiError, ctx)
	}
	return CopyBufferToBytes(encrypted, length), nil
}

func SealedSenderMultiRecipientEncrypt(messageContent *UnidentifiedSenderMessageContent, forRecipients []*Address, identityStore IdentityKeyStore, sessionStore SessionStore, ctx *CallbackContext) ([]byte, error) {
	contextPointer := gopointer.Save(ctx)
	defer gopointer.Unref(contextPointer)

	panic("not implemented")
}

type SealedSenderResult struct {
	Message []byte
	Sender  SealedSenderAddress
}

func SealedSenderDecrypt(
	ciphertext []byte,
	localAddress *SealedSenderAddress,
	trustRoot *PublicKey,
	timestamp time.Time,
	sessionStore SessionStore,
	identityStore IdentityKeyStore,
	preKeyStore PreKeyStore,
	signedPreKeyStore SignedPreKeyStore,
	ctx *CallbackContext,
) (result SealedSenderResult, err error) {
	contextPointer := gopointer.Save(ctx)
	defer gopointer.Unref(contextPointer)

	var decrypted *C.uchar
	var length C.ulong
	var senderE164 *C.char
	var senderUUID *C.char
	var senderDeviceID C.uint32_t

	signalFfiError := C.signal_sealed_session_cipher_decrypt(
		&decrypted,
		&length,
		&senderE164,
		&senderUUID,
		&senderDeviceID,
		BytesToBuffer(ciphertext),
		trustRoot.ptr,
		C.uint64_t(timestamp.UnixMilli()),
		C.CString(localAddress.E164),
		C.CString(localAddress.UUID.String()),
		C.uint32_t(localAddress.DeviceID),
		wrapSessionStore(sessionStore),
		wrapIdentityKeyStore(identityStore),
		wrapPreKeyStore(preKeyStore),
		wrapSignedPreKeyStore(signedPreKeyStore),
		contextPointer,
	)
	if signalFfiError != nil {
		err = wrapCallbackError(signalFfiError, ctx)
		return
	}

	defer C.signal_free_string(senderE164)
	defer C.signal_free_string(senderUUID)

	return SealedSenderResult{
		Message: CopyBufferToBytes(decrypted, length),
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
	if signalFfiError != nil {
		return nil, wrapError(signalFfiError)
	}
	return wrapUnidentifiedSenderMessageContent(usmc), nil
}

func (usmc *UnidentifiedSenderMessageContent) Destroy() error {
	runtime.SetFinalizer(usmc, nil)
	return wrapError(C.signal_unidentified_sender_message_content_destroy(usmc.ptr))
}

func (usmc *UnidentifiedSenderMessageContent) Serialize() ([]byte, error) {
	var serialized *C.uchar
	var length C.ulong
	signalFfiError := C.signal_unidentified_sender_message_content_serialize(&serialized, &length, usmc.ptr)
	if signalFfiError != nil {
		return nil, wrapError(signalFfiError)
	}
	return CopyBufferToBytes(serialized, length), nil
}

func (usmc *UnidentifiedSenderMessageContent) GetContents() ([]byte, error) {
	var contents *C.uchar
	var length C.ulong
	signalFfiError := C.signal_unidentified_sender_message_content_get_contents(&contents, &length, usmc.ptr)
	if signalFfiError != nil {
		return nil, wrapError(signalFfiError)
	}
	return CopyBufferToBytes(contents, length), nil
}

func (usmc *UnidentifiedSenderMessageContent) GetGroupID() ([]byte, error) {
	var groupID *C.uchar
	var length C.ulong
	signalFfiError := C.signal_unidentified_sender_message_content_get_group_id(&groupID, &length, usmc.ptr)
	if signalFfiError != nil {
		return nil, wrapError(signalFfiError)
	}
	if groupID == nil {
		return nil, nil
	}
	return CopyBufferToBytes(groupID, length), nil
}

func (usmc *UnidentifiedSenderMessageContent) GetSenderCertificate() (*SenderCertificate, error) {
	var senderCertificate *C.SignalSenderCertificate
	signalFfiError := C.signal_unidentified_sender_message_content_get_sender_cert(&senderCertificate, usmc.ptr)
	if signalFfiError != nil {
		return nil, wrapError(signalFfiError)
	}
	return wrapSenderCertificate(senderCertificate), nil
}

func (usmc *UnidentifiedSenderMessageContent) GetMessageType() (CiphertextMessageType, error) {
	var messageType C.uint8_t
	signalFfiError := C.signal_unidentified_sender_message_content_get_msg_type(&messageType, usmc.ptr)
	if signalFfiError != nil {
		return 0, wrapError(signalFfiError)
	}
	return CiphertextMessageType(messageType), nil
}

func (usmc *UnidentifiedSenderMessageContent) GetContentHint() (UnidentifiedSenderMessageContentHint, error) {
	var contentHint C.uint32_t
	signalFfiError := C.signal_unidentified_sender_message_content_get_content_hint(&contentHint, usmc.ptr)
	if signalFfiError != nil {
		return 0, wrapError(signalFfiError)
	}
	return UnidentifiedSenderMessageContentHint(contentHint), nil
}

/*
func SealedSenderDecrypt(
	ciphertext []byte,
	trustRoot *PublicKey,
	timestamp uint64,
	localE164 *string,
	localUuid string,
	localDeviceId uint32,
	sessionStore SessionStore,
	identityStore IdentityKeyStore,
	preKeyStore PreKeyStore,
	signedPreKeyStore SignedPreKeyStore,
	ctx *CallbackContext,
) (*SealedSenderAddress, []byte, error) {
	contextPtr := gopointer.Save(ctx)
	defer gopointer.Unref(contextPtr)

	var plaintext *C.uchar
	var plaintextLength C.ulong
	var senderE164 *C.char
	var senderUuid *C.char
	var senderDeviceId C.uint32_t
	signalFfiError := C.signal_sealed_session_cipher_decrypt(
		&plaintext,
		&plaintextLength,
		&senderE164,
		&senderUuid,
		&senderDeviceId,
		BytesToBuffer(ciphertext),
		trustRoot.ptr,
		C.uint64_t(timestamp),
		nil, //C.CString(*localE164), // TODO: make optional localE164
		C.CString(localUuid),
		C.uint32_t(localDeviceId),
		wrapSessionStore(sessionStore),
		wrapIdentityKeyStore(identityStore),
		wrapPreKeyStore(preKeyStore),
		wrapSignedPreKeyStore(signedPreKeyStore),
		contextPtr,
	)
	if signalFfiError != nil {
		return nil, nil, wrapError(signalFfiError)
	}

	senderUuidString := CopyCStringToString(senderUuid)
	uuid, err := uuid.Parse(senderUuidString)
	if err != nil {
		log.Println("Error parsing UUID:", err)
		return nil, nil, err
	}

	address := &SealedSenderAddress{
		E164:     CopyCStringToString(senderE164),
		UUID:     uuid,
		DeviceID: uint32(senderDeviceId),
	}
	return address, CopyBufferToBytes(plaintext, plaintextLength), nil
}
*/
