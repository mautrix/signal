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
#include <stdlib.h>
*/
import "C"
import (
	"unsafe"

	"github.com/google/uuid"
)

// type AuthCredential [C.SignalAUTH_CREDENTIAL_LEN]byte
// type AuthCredentialResponse [C.SignalAUTH_CREDENTIAL_RESPONSE_LEN]byte
type AuthCredentialWithPni [C.SignalAUTH_CREDENTIAL_WITH_PNI_LEN]byte
type AuthCredentialWithPniResponse [C.SignalAUTH_CREDENTIAL_WITH_PNI_RESPONSE_LEN]byte
type AuthCredentialPresentation []byte

func (ac *AuthCredentialWithPni) Slice() []byte {
	return (*ac)[:]
}

func ReceiveAuthCredentialWithPni(
	serverPublicParams ServerPublicParams,
	aci uuid.UUID,
	pni uuid.UUID,
	redemptionTime uint64,
	authCredResponse AuthCredentialWithPniResponse,
) (*AuthCredentialWithPni, error) {
	c_result := [C.SignalAUTH_CREDENTIAL_WITH_PNI_LEN]C.uchar{}
	c_serverPublicParams := (*[C.SignalSERVER_PUBLIC_PARAMS_LEN]C.uchar)(unsafe.Pointer(&serverPublicParams[0]))
	c_aci, err := SignalServiceIDFromUUID(aci)
	if err != nil {
		return nil, err
	}
	c_pni, err := SignalPNIServiceIDFromUUID(pni)
	if err != nil {
		return nil, err
	}
	c_authCredResponse := (*[C.SignalAUTH_CREDENTIAL_WITH_PNI_RESPONSE_LEN]C.uchar)(unsafe.Pointer(&authCredResponse[0]))

	signalFfiError := C.signal_server_public_params_receive_auth_credential_with_pni_as_service_id(
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
	result := AuthCredentialPresentation(CopySignalOwnedBufferToBytes(c_result))
	return &result, nil
}
