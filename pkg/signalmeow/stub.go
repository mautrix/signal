package signalmeow

import (
	"context"
	"os"

	_ "github.com/mattn/go-sqlite3"
	"github.com/mdp/qrterminal/v3"
	"github.com/rs/zerolog"
	"github.com/rs/zerolog/log"
	"go.mau.fi/mautrix-signal/pkg/libsignalgo"
)

func Main() {
	setupLogging()

	sqlStore, err := NewStore("sqlite3", "file:signalmeow.db?_foreign_keys=on")
	if err != nil {
		log.Printf("store.New error: %v", err)
		return
	}

	// See if we already have a device
	devices, err := sqlStore.GetAllDevices()
	if err != nil {
		log.Printf("GetAllDevices error: %v", err)
		return
	}
	if len(devices) > 1 {
		log.Printf("Too many devices, not sure which to test with: %v", len(devices))
		return
	}
	if len(devices) == 1 {
		log.Printf("Using existing device: %v", devices[0])
	} else {
		doProvisioning(sqlStore)
		devices, err = sqlStore.GetAllDevices()
		if err != nil {
			log.Printf("GetAllDevices error: %v", err)
			return
		}
		if len(devices) != 1 {
			log.Printf("Expected 1 device, got %v", len(devices))
			return
		}
	}
	device := devices[0]

	// sender cert testing
	cert, err := senderCertificate(device)
	if err != nil {
		log.Printf("senderCertificate error: %v", err)
		return
	}
	log.Printf("senderCertificate: %v, %v", cert, err)

	ctx := context.Background()
	err = StartReceiveLoops(ctx, device)
	if err != nil {
		log.Printf("StartReceiveLoops error: %v", err)
		return
	}

	// Wait forever
	select {}
}

func doProvisioning(sqlStore *StoreContainer) {
	provChan := PerformProvisioning(sqlStore)

	// First get the provisioning URL
	resp := <-provChan
	if resp.Err != nil || resp.State == StateProvisioningError {
		log.Printf("PerformProvisioning error: %v", resp.Err)
		return
	}
	if resp.State == StateProvisioningURLReceived {
		qrterminal.Generate(resp.ProvisioningUrl, qrterminal.M, os.Stdout)
	} else {
		log.Printf("Unexpected state: %v", resp.State)
		return
	}

	// Next, get the results of finishing registration
	resp = <-provChan
	if resp.Err != nil || resp.State == StateProvisioningError {
		log.Printf("PerformProvisioning error: %v", resp.Err)
		return
	}
	if resp.State == StateProvisioningDataReceived {
		log.Printf("provisioningData: %v", resp.ProvisioningData)
	} else {
		log.Printf("Unexpected state: %v", resp.State)
		return
	}

	// Finally get the results of registering prekeys
	resp = <-provChan
	if resp.Err != nil || resp.State == StateProvisioningError {
		log.Printf("PerformProvisioning error: %v", resp.Err)
		return
	}
	if resp.State == StateProvisioningPreKeysRegistered {
		log.Printf("preKeysRegistered")
	} else {
		log.Printf("Unexpected state: %v", resp.State)
		return
	}
}

// Logging

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
