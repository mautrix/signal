package libsignalgo

/*
#cgo LDFLAGS: -lsignal_ffi -ldl
#include "./libsignal-ffi.h"

extern bool signal_log_enabled_callback(char *target, SignalLogLevel level);
extern void signal_log_callback(char *target, SignalLogLevel level, char *file, uint32_t line, char *message);
extern void signal_log_flush_callback();
*/
import "C"

// ffiLogger is the global logger object.
var ffiLogger Logger

//export signal_log_enabled_callback
func signal_log_enabled_callback(target *C.char, level C.SignalLogLevel) C.bool {
	return C.bool(ffiLogger.Enabled(C.GoString(target), LogLevel(int(level))))
}

//export signal_log_callback
func signal_log_callback(target *C.char, level C.SignalLogLevel, file *C.char, line C.uint32_t, message *C.char) {
	ffiLogger.Log(C.GoString(target), LogLevel(int(level)), C.GoString(file), uint(line), C.GoString(message))
}

//export signal_log_flush_callback
func signal_log_flush_callback() {
	ffiLogger.Flush()
}

type LogLevel int

const (
	LogLevelError LogLevel = iota + 1
	LogLevelWarn
	LogLevelInfo
	LogLevelDebug
	LogLevelTrace
)

type Logger interface {
	Enabled(target string, level LogLevel) bool
	Log(target string, level LogLevel, file string, line uint, message string)
	Flush()
}

func InitLogger(level LogLevel, logger Logger) {
	ffiLogger = logger
	C.signal_init_logger(C.SignalLogLevel(level), C.SignalFfiLogger{
		enabled: C.SignalLogEnabledCallback(C.signal_log_enabled_callback),
		log:     C.SignalLogCallback(C.signal_log_callback),
		flush:   C.SignalLogFlushCallback(C.signal_log_flush_callback),
	})
}
