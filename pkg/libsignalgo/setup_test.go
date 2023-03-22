package libsignalgo_test

import (
	"os"

	"github.com/rs/zerolog"
	"github.com/rs/zerolog/log"

	"github.com/beeper/libsignalgo"
)

type FFILogger struct{}

func (FFILogger) Enabled(target string, level libsignalgo.LogLevel) bool { return true }

func (FFILogger) Log(target string, level libsignalgo.LogLevel, file string, line uint, message string) {
	var evt *zerolog.Event
	switch level {
	case libsignalgo.LogLevelError:
		evt = log.Error()
	case libsignalgo.LogLevelWarn:
		evt = log.Warn()
	case libsignalgo.LogLevelInfo:
		evt = log.Info()
	case libsignalgo.LogLevelDebug:
		evt = log.Debug()
	case libsignalgo.LogLevelTrace:
		evt = log.Trace()
	default:
		panic("invalid log level from libsignal")
	}

	evt.Str("component", "libsignal").
		Str("target", target).
		Str("file", file).
		Uint("line", line).
		Msg(message)
}

func (FFILogger) Flush() {}

var loggingSetup = false

func setupLogging() {
	if !loggingSetup {
		log.Logger = log.Output(zerolog.ConsoleWriter{Out: os.Stderr})
		libsignalgo.InitLogger(libsignalgo.LogLevelTrace, FFILogger{})
		loggingSetup = true
	}
}
