package main

import (
	"crypto/hmac"
	"crypto/sha512"
	"encoding/hex"
	"errors"
	"fmt"

	"maunium.net/go/mautrix"
	"maunium.net/go/mautrix/appservice"
	"maunium.net/go/mautrix/id"
)

var (
	ErrNoCustomMXID    = errors.New("no custom mxid set")
	ErrMismatchingMXID = errors.New("whoami result does not match custom mxid")
)

func (br *SignalBridge) newDoublePuppetClient(mxid id.UserID, accessToken string) (*mautrix.Client, error) {
	_, homeserver, err := mxid.Parse()
	if err != nil {
		return nil, err
	}

	homeserverURL, found := br.Config.Bridge.DoublePuppetServerMap[homeserver]
	if !found {
		if homeserver == br.AS.HomeserverDomain {
			homeserverURL = ""
		} else if br.Config.Bridge.DoublePuppetAllowDiscovery {
			resp, err := mautrix.DiscoverClientAPI(homeserver)
			if err != nil {
				return nil, fmt.Errorf("failed to find homeserver URL for %s: %v", homeserver, err)
			}

			homeserverURL = resp.Homeserver.BaseURL
			br.Log.Debugfln("Discovered URL %s for %s to enable double puppeting for %s", homeserverURL, homeserver, mxid)
		} else {
			return nil, fmt.Errorf("double puppeting from %s is not allowed", homeserver)
		}
	}

	return br.AS.NewExternalMautrixClient(mxid, accessToken, homeserverURL)
}

func (puppet *Puppet) clearCustomMXID() {
	puppet.CustomMXID = ""
	puppet.AccessToken = ""
	puppet.customIntent = nil
	puppet.customUser = nil
}

func (puppet *Puppet) newCustomIntent() (*appservice.IntentAPI, error) {
	if puppet.CustomMXID == "" {
		return nil, ErrNoCustomMXID
	}

	client, err := puppet.bridge.newDoublePuppetClient(puppet.CustomMXID, puppet.AccessToken)
	if err != nil {
		return nil, err
	}

	ia := puppet.bridge.AS.NewIntentAPI("custom")
	ia.Client = client
	ia.Localpart, _, _ = puppet.CustomMXID.Parse()
	ia.UserID = puppet.CustomMXID
	ia.IsCustomPuppet = true
	return ia, nil
}

func (puppet *Puppet) tryRelogin(cause error, action string) bool {
	if !puppet.bridge.Config.CanAutoDoublePuppet(puppet.CustomMXID) {
		return false
	}
	log := puppet.log.With().
		AnErr("cause_error", cause).
		Str("while_action", action).
		Logger()
	log.Debug().Msg("Trying to relogin")
	accessToken, err := puppet.LoginWithSharedSecret(puppet.CustomMXID)
	if err != nil {
		log.Error().Err(err).Msg("Failed to relogin")
		return false
	}
	log.Info().Msg("Successfully relogined")
	puppet.AccessToken = accessToken
	err = puppet.Update()
	if err != nil {
		log.Error().Err(err).Msg("Failed to update puppet")
	}
	return true
}

func (puppet *Puppet) StartCustomMXID(reloginOnFail bool) error {
	if puppet.CustomMXID == "" {
		puppet.clearCustomMXID()
		return nil
	}

	intent, err := puppet.newCustomIntent()
	if err != nil {
		puppet.clearCustomMXID()
		return err
	}

	resp, err := intent.Whoami()
	if err != nil {
		tokenIsUnknownOrMissing := errors.Is(err, mautrix.MUnknownToken) || errors.Is(err, mautrix.MMissingToken)
		if !reloginOnFail || (tokenIsUnknownOrMissing && !puppet.tryRelogin(err, "initializing double puppeting")) {
			puppet.clearCustomMXID()
			return err
		}

		intent.AccessToken = puppet.AccessToken
	} else if resp.UserID != puppet.CustomMXID {
		puppet.clearCustomMXID()
		return ErrMismatchingMXID
	}

	puppet.customIntent = intent
	puppet.customUser = puppet.bridge.GetUserByMXID(puppet.CustomMXID)
	return nil
}

func (puppet *Puppet) LoginWithSharedSecret(mxid id.UserID) (string, error) {
	_, homeserver, _ := mxid.Parse()
	puppet.log.Debug().Str("user_id", mxid.String()).Msg("Logging into double puppet target with shared secret")
	loginSecret := puppet.bridge.Config.Bridge.LoginSharedSecretMap[homeserver]
	client, err := puppet.bridge.newDoublePuppetClient(mxid, "")
	if err != nil {
		return "", fmt.Errorf("failed to create mautrix client to log in: %v", err)
	}
	req := mautrix.ReqLogin{
		Identifier:               mautrix.UserIdentifier{Type: mautrix.IdentifierTypeUser, User: string(mxid)},
		DeviceID:                 "Signal Bridge",
		InitialDeviceDisplayName: "Signal Bridge",
	}
	if loginSecret == "appservice" {
		client.AccessToken = puppet.bridge.AS.Registration.AppToken
		req.Type = mautrix.AuthTypeAppservice
	} else {
		mac := hmac.New(sha512.New, []byte(loginSecret))
		mac.Write([]byte(mxid))
		req.Password = hex.EncodeToString(mac.Sum(nil))
		req.Type = mautrix.AuthTypePassword
	}
	resp, err := client.Login(&req)
	if err != nil {
		return "", err
	}
	return resp.AccessToken, nil
}

func (puppet *Puppet) SwitchCustomMXID(accessToken string, mxid id.UserID) error {
	prevCustomMXID := puppet.CustomMXID
	puppet.CustomMXID = mxid
	puppet.AccessToken = accessToken

	err := puppet.StartCustomMXID(false)
	if err != nil {
		return err
	}

	if prevCustomMXID != "" {
		delete(puppet.bridge.puppetsByCustomMXID, prevCustomMXID)
	}
	if puppet.CustomMXID != "" {
		puppet.bridge.puppetsByCustomMXID[puppet.CustomMXID] = puppet
	}
	puppet.bridge.AS.StateStore.MarkRegistered(puppet.CustomMXID)
	puppet.Update()
	// TODO leave rooms with default puppet
	return nil
}
