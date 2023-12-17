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
#cgo LDFLAGS: -lsignal_ffi -ldl
#include <./libsignal-ffi.h>

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
