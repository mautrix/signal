// mautrix-signal - A Matrix-signal puppeting bridge.
// Copyright (C) 2023 Sumner Evans
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
)

func Encrypt(ctx context.Context, plaintext []byte, forAddress *Address, sessionStore SessionStore, identityKeyStore IdentityKeyStore) (*CiphertextMessage, error) {
	var ciphertextMessage *C.SignalCiphertextMessage
	var now C.uint64_t = C.uint64_t(time.Now().Unix())
	callbackCtx := NewCallbackContext(ctx)
	defer callbackCtx.Unref()
	signalFfiError := C.signal_encrypt_message(
		&ciphertextMessage,
		BytesToBuffer(plaintext),
		forAddress.ptr,
		callbackCtx.wrapSessionStore(sessionStore),
		callbackCtx.wrapIdentityKeyStore(identityKeyStore),
		now,
	)
	runtime.KeepAlive(plaintext)
	runtime.KeepAlive(forAddress)
	if signalFfiError != nil {
		return nil, callbackCtx.wrapError(signalFfiError)
	}
	return wrapCiphertextMessage(ciphertextMessage), nil
}
