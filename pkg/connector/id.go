// mautrix-signal - A Matrix-Signal puppeting bridge.
// Copyright (C) 2024 Tulir Asokan
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

package connector

import (
	"fmt"
	"strconv"
	"strings"

	"github.com/google/uuid"
	"maunium.net/go/mautrix/bridgev2"
	"maunium.net/go/mautrix/bridgev2/networkid"

	"go.mau.fi/mautrix-signal/pkg/libsignalgo"
	"go.mau.fi/mautrix-signal/pkg/signalmeow/types"
)

func parseUserID(userID networkid.UserID) (uuid.UUID, error) {
	serviceID, err := parseUserIDAsServiceID(userID)
	if err != nil {
		return uuid.Nil, err
	} else if serviceID.Type != libsignalgo.ServiceIDTypeACI {
		return uuid.Nil, fmt.Errorf("invalid user ID: expected ACI type")
	} else {
		return serviceID.UUID, nil
	}
}

func parseUserIDAsServiceID(userID networkid.UserID) (libsignalgo.ServiceID, error) {
	return libsignalgo.ServiceIDFromString(string(userID))
}

func parsePortalID(portalID networkid.PortalID) (userID libsignalgo.ServiceID, groupID types.GroupIdentifier, err error) {
	if len(portalID) == 44 {
		groupID = types.GroupIdentifier(portalID)
	} else {
		userID, err = libsignalgo.ServiceIDFromString(string(portalID))
	}
	return
}

func parseMessageID(messageID networkid.MessageID) (sender uuid.UUID, timestamp uint64, err error) {
	parts := strings.Split(string(messageID), "|")
	if len(parts) != 2 {
		err = fmt.Errorf("invalid message ID: expected two pipe-separated parts")
		return
	}
	sender, err = uuid.Parse(parts[0])
	if err != nil {
		return
	}
	timestamp, err = strconv.ParseUint(parts[1], 10, 64)
	return
}

func makeGroupPortalID(groupID types.GroupIdentifier) networkid.PortalID {
	return networkid.PortalID(groupID)
}

func makeGroupPortalKey(groupID types.GroupIdentifier) networkid.PortalKey {
	return networkid.PortalKey{
		ID:       makeGroupPortalID(groupID),
		Receiver: "",
	}
}

func makeDMPortalID(serviceID libsignalgo.ServiceID) networkid.PortalID {
	return networkid.PortalID(serviceID.String())
}

func (s *SignalClient) makePortalKey(chatID string) networkid.PortalKey {
	key := networkid.PortalKey{ID: networkid.PortalID(chatID)}
	// For non-group chats, add receiver
	if len(chatID) != 44 {
		key.Receiver = s.UserLogin.ID
	}
	return key
}

func (s *SignalClient) makeDMPortalKey(serviceID libsignalgo.ServiceID) networkid.PortalKey {
	return networkid.PortalKey{
		ID:       makeDMPortalID(serviceID),
		Receiver: s.UserLogin.ID,
	}
}

func makeMessageID(sender uuid.UUID, timestamp uint64) networkid.MessageID {
	return networkid.MessageID(fmt.Sprintf("%s|%d", sender, timestamp))
}

func makeUserID(user uuid.UUID) networkid.UserID {
	return networkid.UserID(user.String())
}

func makeUserIDFromServiceID(user libsignalgo.ServiceID) networkid.UserID {
	return networkid.UserID(user.String())
}

func makeUserLoginID(user uuid.UUID) networkid.UserLoginID {
	return networkid.UserLoginID(user.String())
}

func (s *SignalClient) makeEventSender(sender uuid.UUID) bridgev2.EventSender {
	return bridgev2.EventSender{
		IsFromMe:    sender == s.Client.Store.ACI,
		SenderLogin: makeUserLoginID(sender),
		Sender:      makeUserID(sender),
	}
}

func makeMessagePartID(index int) networkid.PartID {
	if index == 0 {
		return ""
	}
	return networkid.PartID(strconv.Itoa(index))
}
