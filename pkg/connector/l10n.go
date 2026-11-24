package connector

import (
	"go.mau.fi/util/l10n"
)

var L = l10n.NewNamespace("mautrix-signal")

var (
	msgFlowQRName        = L.Define("login.flow.qr.name", "QR")
	msgFlowQRDescription = L.Define("login.flow.qr.description", "Scan a QR code to pair the bridge to your Signal app")

	msgStepQRInstructions       = L.Define("login.step.qr.instructions", "Scan the QR code on your Signal app to log in")
	msgStepCompleteInstructions = L.Define(
		"login.step.complete.instructions", "Successfully logged in as {phone} / {aci}",
		l10n.WithComment("phone is the phone number of the Signal account, aci is its account UUID"),
	)
)
