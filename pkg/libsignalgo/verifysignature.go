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
	"runtime"
	"unsafe"
)

type NotarySignature [C.SignalSIGNATURE_LEN]byte

func ServerPublicParamsVerifySignature(
	serverPublicParams ServerPublicParams,
	messageBytes []byte,
	NotarySignature NotarySignature,
) error {
	c_notarySignature := (*[C.SignalSIGNATURE_LEN]C.uint8_t)(unsafe.Pointer(&NotarySignature[0]))
	c_serverPublicParams := (*[C.SignalSERVER_PUBLIC_PARAMS_LEN]C.uchar)(unsafe.Pointer(&serverPublicParams[0]))
	signalFfiError := C.signal_server_public_params_verify_signature(
		c_serverPublicParams,
		BytesToBuffer(messageBytes),
		c_notarySignature,
	)
	runtime.KeepAlive(messageBytes)
	return wrapError(signalFfiError)
}
