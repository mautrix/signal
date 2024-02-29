// mautrix-signal - A Matrix-signal puppeting bridge.
// Copyright (C) 2024 Malte Eggers
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
	"runtime"
	"unsafe"

	"github.com/google/uuid"
)

type ServerSecretParams [C.SignalSERVER_SECRET_PARAMS_LEN]byte

func GenerateServerSecretParams() (ServerSecretParams, error) {
	return GenerateServerSecretParamsWithRandomness(GenerateRandomness())
}

func GenerateServerSecretParamsWithRandomness(randomness Randomness) (ServerSecretParams, error) {
	var params [C.SignalSERVER_SECRET_PARAMS_LEN]C.uchar
	signalFfiError := C.signal_server_secret_params_generate_deterministic(&params, (*[C.SignalRANDOMNESS_LEN]C.uint8_t)(unsafe.Pointer(&randomness)))
	runtime.KeepAlive(randomness)
	if signalFfiError != nil {
		return ServerSecretParams{}, wrapError(signalFfiError)
	}
	var serverSecretParams ServerSecretParams
	copy(serverSecretParams[:], C.GoBytes(unsafe.Pointer(&params), C.int(C.SignalSERVER_SECRET_PARAMS_LEN)))
	return serverSecretParams, nil
}

func (ssp *ServerSecretParams) IssueExpiringProfileKeyCredential(request ProfileKeyCredentialRequest, uuid uuid.UUID, commitment ProfileKeyCommitment, expiration uint64) (*ExpiringProfileKeyCredentialResponse, error) {
	var response [C.SignalEXPIRING_PROFILE_KEY_CREDENTIAL_RESPONSE_LEN]C.uchar
	randomness := GenerateRandomness()
	serviceID, err := SignalServiceIDFromUUID(uuid)
	if err != nil {
		return nil, err
	}
	signalFfiError := C.signal_server_secret_params_issue_expiring_profile_key_credential_deterministic(
		&response,
		(*[C.SignalSERVER_SECRET_PARAMS_LEN]C.uint8_t)(unsafe.Pointer(ssp)),
		(*[C.SignalRANDOMNESS_LEN]C.uint8_t)(unsafe.Pointer(&randomness)),
		(*[C.SignalPROFILE_KEY_CREDENTIAL_REQUEST_LEN]C.uchar)(unsafe.Pointer(&request)),
		serviceID,
		(*[C.SignalPROFILE_KEY_COMMITMENT_LEN]C.uchar)(unsafe.Pointer(&commitment)),
		(C.uint64_t)(expiration),
	)
	runtime.KeepAlive(ssp)
	runtime.KeepAlive(randomness)
	runtime.KeepAlive(request)
	runtime.KeepAlive(serviceID)
	runtime.KeepAlive(commitment)
	runtime.KeepAlive(expiration)
	if signalFfiError != nil {
		return nil, wrapError(signalFfiError)
	}
	var result *ExpiringProfileKeyCredentialResponse
	copy(result[:], C.GoBytes(unsafe.Pointer(&response), C.int(C.SignalEXPIRING_PROFILE_KEY_CREDENTIAL_RESPONSE_LEN)))
	return result, nil
}
