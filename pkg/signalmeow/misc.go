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
	"encoding/base64"

	"github.com/rs/zerolog"

	"go.mau.fi/mautrix-signal/pkg/libsignalgo"
	"go.mau.fi/mautrix-signal/pkg/signalmeow/web"
)

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

func serverPublicParams() libsignalgo.ServerPublicParams {
	serverPublicParamsBase64 := "AMhf5ywVwITZMsff/eCyudZx9JDmkkkbV6PInzG4p8x3VqVJSFiMvnvlEKWuRob/1eaIetR31IYeAbm0NdOuHH8Qi+Rexi1wLlpzIo1gstHWBfZzy1+qHRV5A4TqPp15YzBPm0WSggW6PbSn+F4lf57VCnHF7p8SvzAA2ZZJPYJURt8X7bbg+H3i+PEjH9DXItNEqs2sNcug37xZQDLm7X36nOoGPs54XsEGzPdEV+itQNGUFEjY6X9Uv+Acuks7NpyGvCoKxGwgKgE5XyJ+nNKlyHHOLb6N1NuHyBrZrgtY/JYJHRooo5CEqYKBqdFnmbTVGEkCvJKxLnjwKWf+fEPoWeQFj5ObDjcKMZf2Jm2Ae69x+ikU5gBXsRmoF94GXTLfN0/vLt98KDPnxwAQL9j5V1jGOY8jQl6MLxEs56cwXN0dqCnImzVH3TZT1cJ8SW1BRX6qIVxEzjsSGx3yxF3suAilPMqGRp4ffyopjMD1JXiKR2RwLKzizUe5e8XyGOy9fplzhw3jVzTRyUZTRSZKkMLWcQ/gv0E4aONNqs4P"
	serverPublicParamsBytes, err := base64.StdEncoding.DecodeString(serverPublicParamsBase64)
	if err != nil {
		panic(err)
	}
	var serverPublicParams libsignalgo.ServerPublicParams
	copy(serverPublicParams[:], serverPublicParamsBytes)
	return serverPublicParams
}
