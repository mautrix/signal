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
	"unsafe"

	gopointer "github.com/mattn/go-pointer"
)

type CallbackContext struct {
	Error error
	Ctx   context.Context
}

func NewEmptyCallbackContext() *CallbackContext {
	return NewCallbackContext(context.TODO())
}

func NewCallbackContext(ctx context.Context) *CallbackContext {
	return &CallbackContext{Ctx: ctx}
}

func wrapStoreCallback[T any](storeCtx, ctxPtr unsafe.Pointer, callback func(store T, ctx context.Context) error) C.int {
	store := gopointer.Restore(storeCtx).(T)
	ctx := NewEmptyCallbackContext()
	if ctxPtr != nil {
		if restored := gopointer.Restore(ctxPtr); restored != nil {
			ctx = restored.(*CallbackContext)
		}
	}
	if err := callback(store, ctx.Ctx); err != nil {
		ctx.Error = err
		return -1
	}
	return 0
}
