package libsignalgo

/*
#cgo LDFLAGS: ./libsignal/target/release/libsignal_ffi.a -ldl
#include "./libsignal/libsignal-ffi.h"
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
