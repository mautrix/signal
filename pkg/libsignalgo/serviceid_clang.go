//go:build darwin || android || ios

package libsignalgo

/*
#include "./libsignal-ffi.h"
#include <stdlib.h>
*/
import "C"

type cPNIType = *C.SignalServiceIdFixedWidthBinaryBytes
