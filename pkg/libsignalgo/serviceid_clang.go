//go:build darwin || android || ios

package libsignalgo

/*
#cgo LDFLAGS: -lsignal_ffi -ldl -lm
#include "./libsignal-ffi.h"
#include <stdlib.h>
*/
import "C"

type cPNIType = *C.SignalServiceIdFixedWidthBinaryBytes
