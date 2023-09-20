package main

import (
	"maunium.net/go/mautrix/id"
)

func (puppet *Puppet) SwitchCustomMXID(accessToken string, mxid id.UserID) error {
	puppet.CustomMXID = mxid
	puppet.AccessToken = accessToken
	puppet.Update()
	err := puppet.StartCustomMXID(false)
	if err != nil {
		return err
	}
	// TODO leave rooms with default puppet
	return nil
}

func (puppet *Puppet) ClearCustomMXID() {
	save := puppet.CustomMXID != "" || puppet.AccessToken != ""
	puppet.bridge.puppetsLock.Lock()
	if puppet.CustomMXID != "" && puppet.bridge.puppetsByCustomMXID[puppet.CustomMXID] == puppet {
		delete(puppet.bridge.puppetsByCustomMXID, puppet.CustomMXID)
	}
	puppet.bridge.puppetsLock.Unlock()
	puppet.CustomMXID = ""
	puppet.AccessToken = ""
	puppet.customIntent = nil
	puppet.customUser = nil
	if save {
		puppet.Update()
	}
}

func (puppet *Puppet) StartCustomMXID(reloginOnFail bool) error {
	newIntent, newAccessToken, err := puppet.bridge.DoublePuppet.Setup(puppet.CustomMXID, puppet.AccessToken, reloginOnFail)
	if err != nil {
		puppet.ClearCustomMXID()
		return err
	}
	puppet.bridge.puppetsLock.Lock()
	puppet.bridge.puppetsByCustomMXID[puppet.CustomMXID] = puppet
	puppet.bridge.puppetsLock.Unlock()
	if puppet.AccessToken != newAccessToken {
		puppet.AccessToken = newAccessToken
		puppet.Update()
	}
	puppet.customIntent = newIntent
	puppet.customUser = puppet.bridge.GetUserByMXID(puppet.CustomMXID)
	return nil
}

func (user *User) tryAutomaticDoublePuppeting() {
	if !user.bridge.Config.CanAutoDoublePuppet(user.MXID) {
		return
	}
	user.log.Debug().Msg("Checking if double puppeting needs to be enabled")
	puppet := user.bridge.GetPuppetBySignalID(user.SignalID)
	if len(puppet.CustomMXID) > 0 {
		user.log.Debug().Msg("User already has double-puppeting enabled")
		// Custom puppet already enabled
		return
	}
	puppet.CustomMXID = user.MXID
	err := puppet.StartCustomMXID(true)
	if err != nil {
		user.log.Warn().Err(err).Msg("Failed to login with shared secret")
	} else {
		// TODO leave rooms with default puppet
		user.log.Debug().Msg("Successfully automatically enabled custom puppet")
	}
}
