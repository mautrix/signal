//go:build darwin

package libsignalgo

/*
#cgo LDFLAGS: -lsignal_ffi -ldl
#include "./libsignal-ffi.h"
#include <stdlib.h>
*/
import "C"

type cPNIType = *C.SignalServiceIdFixedWidthBinaryBytes
