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

package signalmeow

import (
	_ "embed"

	"github.com/rs/zerolog"

	"go.mau.fi/mautrix-signal/pkg/libsignalgo"
	"go.mau.fi/mautrix-signal/pkg/signalmeow/web"
)

// Deprecated: global loggers are bad
var zlog zerolog.Logger = zerolog.New(zerolog.ConsoleWriter{}).With().Timestamp().Logger()

func SetLogger(l zerolog.Logger) {
	zlog = l
	setupFFILogging()
	web.SetLogger(l.With().Str("component", "signalmeow/web").Logger())
}

type FFILogger struct{}

func (FFILogger) Enabled(target string, level libsignalgo.LogLevel) bool { return true }

func (FFILogger) Log(target string, level libsignalgo.LogLevel, file string, line uint, message string) {
	var evt *zerolog.Event
	switch level {
	case libsignalgo.LogLevelError:
		evt = zlog.Error()
	case libsignalgo.LogLevelWarn:
		evt = zlog.Warn()
	case libsignalgo.LogLevelInfo:
		evt = zlog.Info()
	case libsignalgo.LogLevelDebug:
		evt = zlog.Debug()
	case libsignalgo.LogLevelTrace:
		evt = zlog.Trace()
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

// Ensure FFILogger implements the Logger interface
var _ libsignalgo.Logger = FFILogger{}

var loggingSetup = false

func setupFFILogging() {
	if !loggingSetup {
		libsignalgo.InitLogger(libsignalgo.LogLevelInfo, FFILogger{})
		loggingSetup = true
	}
}

//go:embed prod-server-public-params.dat
var prodServerPublicParamsSlice []byte
var prodServerPublicParams libsignalgo.ServerPublicParams

func init() {
	prodServerPublicParams = libsignalgo.ServerPublicParams(prodServerPublicParamsSlice)
}
