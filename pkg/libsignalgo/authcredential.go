package libsignalgo

/*
#cgo LDFLAGS: -lsignal_ffi -ldl
#include "./libsignal-ffi.h"
#include <stdlib.h>
*/
import "C"
import (
	"unsafe"
)

// type AuthCredential [C.SignalAUTH_CREDENTIAL_LEN]byte
// type AuthCredentialResponse [C.SignalAUTH_CREDENTIAL_RESPONSE_LEN]byte
type AuthCredentialWithPni [C.SignalAUTH_CREDENTIAL_WITH_PNI_LEN]byte
type AuthCredentialWithPniResponse [C.SignalAUTH_CREDENTIAL_WITH_PNI_RESPONSE_LEN]byte
type AuthCredentialPresentation [C.SignalAUTH_CREDENTIAL_PRESENTATION_V2_LEN]byte

func (ac *AuthCredentialWithPni) Slice() []byte {
	return (*ac)[:]
}

// wrap C.signal_server_public_params_receive_auth_credential_with_pni
func ReceiveAuthCredentialWithPni(
	serverPublicParams ServerPublicParams,
	aci UUID,
	pni UUID,
	redemptionTime uint64,
	authCredResponse AuthCredentialWithPniResponse,
) (*AuthCredentialWithPni, error) {
	c_result := [C.SignalAUTH_CREDENTIAL_WITH_PNI_LEN]C.uchar{}
	c_serverPublicParams := (*[C.SignalSERVER_PUBLIC_PARAMS_LEN]C.uchar)(unsafe.Pointer(&serverPublicParams[0]))
	c_aci := (*[C.SignalUUID_LEN]C.uchar)(unsafe.Pointer(&aci[0]))
	c_pni := (*[C.SignalUUID_LEN]C.uchar)(unsafe.Pointer(&pni[0]))
	c_authCredResponse := (*[C.SignalAUTH_CREDENTIAL_WITH_PNI_RESPONSE_LEN]C.uchar)(unsafe.Pointer(&authCredResponse[0]))

	signalFfiError := C.signal_server_public_params_receive_auth_credential_with_pni(
		&c_result,
		c_serverPublicParams,
		c_aci,
		c_pni,
		C.uint64_t(redemptionTime),
		c_authCredResponse,
	)
	if signalFfiError != nil {
		return nil, wrapError(signalFfiError)
	}
	result := AuthCredentialWithPni(C.GoBytes(unsafe.Pointer(&c_result), C.int(C.SignalAUTH_CREDENTIAL_WITH_PNI_LEN)))
	return &result, nil
}

func NewAuthCredentialWithPniResponse(b []byte) (*AuthCredentialWithPniResponse, error) {
	borrowedBuffer := BytesToBuffer(b)
	signalFfiError := C.signal_auth_credential_with_pni_response_check_valid_contents(borrowedBuffer)
	if signalFfiError != nil {
		return nil, wrapError(signalFfiError)
	}
	authCred := AuthCredentialWithPniResponse(b)
	return &authCred, nil
}

// wrap C.signal_server_public_params_create_auth_credential_with_pni_presentation_deterministic
func CreateAuthCredentialWithPniPresentation(
	serverPublicParams ServerPublicParams,
	randomness Randomness,
	groupSecretParams GroupSecretParams,
	authCredWithPni AuthCredentialWithPni,
) (*AuthCredentialPresentation, error) {
	var c_result C.SignalOwnedBuffer = C.SignalOwnedBuffer{}
	c_serverPublicParams := (*[C.SignalSERVER_PUBLIC_PARAMS_LEN]C.uchar)(unsafe.Pointer(&serverPublicParams[0]))
	c_randomness := (*[C.SignalRANDOMNESS_LEN]C.uchar)(unsafe.Pointer(&randomness[0]))
	c_groupSecretParams := (*[C.SignalGROUP_SECRET_PARAMS_LEN]C.uchar)(unsafe.Pointer(&groupSecretParams[0]))
	c_authCredWithPni := (*[C.SignalAUTH_CREDENTIAL_WITH_PNI_LEN]C.uchar)(unsafe.Pointer(&authCredWithPni[0]))

	signalFfiError := C.signal_server_public_params_create_auth_credential_with_pni_presentation_deterministic(
		&c_result,
		c_serverPublicParams,
		c_randomness,
		c_groupSecretParams,
		c_authCredWithPni,
	)
	if signalFfiError != nil {
		return nil, wrapError(signalFfiError)
	}
	result := CopySignalOwnedBufferToBytes(c_result)
	pres := AuthCredentialPresentation(result)
	return &pres, nil
}
