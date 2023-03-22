package libsignalgo

/*
#cgo LDFLAGS: ./libsignal/target/release/libsignal_ffi.a -ldl
#include "./libsignal/libsignal-ffi.h"
*/
import "C"
import (
	"fmt"
)

type ErrorCode int

const (
	ErrorCodeUnknownError               ErrorCode = 1
	ErrorCodeInvalidState               ErrorCode = 2
	ErrorCodeInternalError              ErrorCode = 3
	ErrorCodeNullParameter              ErrorCode = 4
	ErrorCodeInvalidArgument            ErrorCode = 5
	ErrorCodeInvalidType                ErrorCode = 6
	ErrorCodeInvalidUtf8String          ErrorCode = 7
	ErrorCodeProtobufError              ErrorCode = 10
	ErrorCodeLegacyCiphertextVersion    ErrorCode = 21
	ErrorCodeUnknownCiphertextVersion   ErrorCode = 22
	ErrorCodeUnrecognizedMessageVersion ErrorCode = 23
	ErrorCodeInvalidMessage             ErrorCode = 30
	ErrorCodeSealedSenderSelfSend       ErrorCode = 31
	ErrorCodeInvalidKey                 ErrorCode = 40
	ErrorCodeInvalidSignature           ErrorCode = 41
	ErrorCodeInvalidAttestationData     ErrorCode = 42
	ErrorCodeFingerprintVersionMismatch ErrorCode = 51
	ErrorCodeFingerprintParsingError    ErrorCode = 52
	ErrorCodeUntrustedIdentity          ErrorCode = 60
	ErrorCodeInvalidKeyIdentifier       ErrorCode = 70
	ErrorCodeSessionNotFound            ErrorCode = 80
	ErrorCodeInvalidRegistrationId      ErrorCode = 81
	ErrorCodeInvalidSession             ErrorCode = 82
	ErrorCodeInvalidSenderKeySession    ErrorCode = 83
	ErrorCodeDuplicatedMessage          ErrorCode = 90
	ErrorCodeCallbackError              ErrorCode = 100
	ErrorCodeVerificationFailure        ErrorCode = 110
)

type SignalError struct {
	Code    ErrorCode
	Message string
}

func (e *SignalError) Error() string {
	return fmt.Sprintf("%d: %s", e.Code, e.Message)
}

func wrapCallbackError(signalError *C.SignalFfiError, ctx *CallbackContext) error {
	if signalError == nil {
		return nil
	}

	defer C.signal_error_free(signalError)

	errorType := C.signal_error_get_type(signalError)
	if ErrorCode(errorType) == ErrorCodeCallbackError {
		return ctx.Error
	} else {
		return wrapSignalError(signalError, errorType)
	}
}

func wrapError(signalError *C.SignalFfiError) error {
	if signalError == nil {
		return nil
	}

	defer C.signal_error_free(signalError)

	return wrapSignalError(signalError, C.signal_error_get_type(signalError))
}

func wrapSignalError(signalError *C.SignalFfiError, errorType C.uint32_t) error {
	var messageBytes *C.char
	getMessageError := C.signal_error_get_message(signalError, &messageBytes)
	if getMessageError != nil {
		// Ignore any errors from this, it will just end up being an empty
		// string.
		C.signal_error_free(getMessageError)
	}
	return &SignalError{Code: ErrorCode(errorType), Message: CopyCStringToString(messageBytes)}
}
