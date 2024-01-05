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
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"net/http"
	"strings"

	"github.com/google/uuid"
	"google.golang.org/protobuf/proto"

	"go.mau.fi/mautrix-signal/pkg/libsignalgo"
	signalpb "go.mau.fi/mautrix-signal/pkg/signalmeow/protobuf"
	"go.mau.fi/mautrix-signal/pkg/signalmeow/types"
)

func (cli *Client) StoreContactDetailsAsContact(contactDetails *signalpb.ContactDetails, avatar *[]byte) (*types.Contact, error) {
	ctx := context.TODO()
	parsedUUID, err := uuid.Parse(contactDetails.GetAci())
	if err != nil {
		return nil, err
	}
	existingContact, err := cli.Store.ContactStore.LoadContact(ctx, parsedUUID)
	if err != nil {
		zlog.Err(err).Msg("StoreContactDetailsAsContact error loading contact")
		return nil, err
	}
	if existingContact == nil {
		zlog.Debug().Msgf("StoreContactDetailsAsContact: creating new contact for uuid: %v", parsedUUID)
		existingContact = &types.Contact{
			UUID: parsedUUID,
		}
	} else {
		zlog.Debug().Msgf("StoreContactDetailsAsContact: updating existing contact for uuid: %v", parsedUUID)
	}

	existingContact.E164 = contactDetails.GetNumber()
	existingContact.ContactName = contactDetails.GetName()
	if profileKeyString := contactDetails.GetProfileKey(); profileKeyString != nil {
		profileKey := libsignalgo.ProfileKey(profileKeyString)
		existingContact.ProfileKey = &profileKey
		err = cli.Store.ProfileKeyStore.StoreProfileKey(ctx, existingContact.UUID, profileKey)
		if err != nil {
			zlog.Err(err).Msg("StoreContactDetailsAsContact error storing profile key")
			//return *existingContact, nil, err
		}
	}

	if avatar != nil && *avatar != nil && len(*avatar) > 0 {
		rawHash := sha256.Sum256(*avatar)
		avatarHash := hex.EncodeToString(rawHash[:])
		var contentType string
		if avatarDetails := contactDetails.GetAvatar(); avatarDetails != nil && !strings.HasSuffix(avatarDetails.GetContentType(), "/*") {
			contentType = *avatarDetails.ContentType
		} else {
			contentType = http.DetectContentType(*avatar)
		}
		existingContact.ContactAvatar = types.ContactAvatar{
			Image:       *avatar,
			ContentType: contentType,
			Hash:        avatarHash,
		}
	}

	zlog.Debug().Msgf("StoreContactDetailsAsContact: storing contact for uuid: %v", contactDetails.GetAci())
	storeErr := cli.Store.ContactStore.StoreContact(ctx, *existingContact)
	if storeErr != nil {
		zlog.Err(storeErr).Msg("StoreContactDetailsAsContact: error storing contact")
		return existingContact, storeErr
	}
	return existingContact, nil
}

func (cli *Client) fetchContactThenTryAndUpdateWithProfile(profileUuid uuid.UUID) (*types.Contact, error) {
	ctx := context.TODO()
	contactChanged := false

	existingContact, err := cli.Store.ContactStore.LoadContact(ctx, profileUuid)
	if err != nil {
		zlog.Err(err).Msg("fetchContactThenTryAndUpdateWithProfile: error loading contact")
		return nil, err
	}
	if existingContact == nil {
		zlog.Debug().Msgf("fetchContactThenTryAndUpdateWithProfile: creating new contact for uuid: %v", profileUuid)
		existingContact = &types.Contact{
			UUID: profileUuid,
		}
		contactChanged = true
	} else {
		zlog.Debug().Msgf("fetchContactThenTryAndUpdateWithProfile: updating existing contact for uuid: %v", profileUuid)
	}
	profile, err := cli.RetrieveProfileByID(ctx, profileUuid)
	if err != nil {
		zlog.Err(err).Msgf("fetchContactThenTryAndUpdateWithProfile: error retrieving profile for uuid: %v", profileUuid)
		//return nil, nil, err
		// Don't return here, we still want to return what we have
	}

	if profile != nil {
		if existingContact.ProfileName != profile.Name {
			existingContact.ProfileName = profile.Name
			contactChanged = true
		}
		if existingContact.ProfileAbout != profile.About {
			existingContact.ProfileAbout = profile.About
			contactChanged = true
		}
		if existingContact.ProfileAboutEmoji != profile.AboutEmoji {
			existingContact.ProfileAboutEmoji = profile.AboutEmoji
			contactChanged = true
		}
		if existingContact.ProfileAvatarPath != profile.AvatarPath {
			existingContact.ProfileAvatarPath = profile.AvatarPath
			contactChanged = true
		}
		if existingContact.ProfileKey == nil || *existingContact.ProfileKey != profile.Key {
			existingContact.ProfileKey = &profile.Key
			contactChanged = true
		}
	}

	if contactChanged {
		storeErr := cli.Store.ContactStore.StoreContact(ctx, *existingContact)
		if storeErr != nil {
			zlog.Err(storeErr).Msg("fetchContactThenTryAndUpdateWithProfile: error storing contact")
		}
	}
	return existingContact, nil
}

func (cli *Client) UpdateContactE164(uuid uuid.UUID, e164 string) error {
	ctx := context.TODO()
	existingContact, err := cli.Store.ContactStore.LoadContact(ctx, uuid)
	if err != nil {
		zlog.Err(err).Msg("UpdateContactE164: error loading contact")
		return err
	}
	if existingContact == nil {
		zlog.Debug().Msgf("UpdateContactE164: creating new contact for uuid: %v", uuid)
		existingContact = &types.Contact{
			UUID: uuid,
		}
	} else {
		zlog.Debug().Msgf("UpdateContactE164: found existing contact for uuid: %v", uuid)
	}
	if existingContact.E164 != e164 {
		zlog.Debug().Msgf("UpdateContactE164: e164 changed for uuid: %v", uuid)
		existingContact.E164 = e164
		storeErr := cli.Store.ContactStore.StoreContact(ctx, *existingContact)
		if storeErr != nil {
			zlog.Err(storeErr).Msg("UpdateContactE164: error storing contact")
			return storeErr
		}
	}
	return nil
}

func (cli *Client) ContactByID(uuid uuid.UUID) (*types.Contact, error) {
	return cli.fetchContactThenTryAndUpdateWithProfile(uuid)
}

func (cli *Client) ContactByE164(e164 string) (*types.Contact, error) {
	ctx := context.TODO()
	contact, err := cli.Store.ContactStore.LoadContactByE164(ctx, e164)
	if err != nil {
		zlog.Err(err).Msg("ContactByE164 error loading contact")
		return nil, err
	}
	if contact == nil {
		return nil, nil
	}
	contact, err = cli.fetchContactThenTryAndUpdateWithProfile(contact.UUID)
	return contact, err
}

// UnmarshalContactDetailsMessages unmarshals a slice of ContactDetails messages from a byte buffer.
func unmarshalContactDetailsMessages(byteStream []byte) ([]*signalpb.ContactDetails, [][]byte, error) {
	var contactDetailsList []*signalpb.ContactDetails
	var avatarList [][]byte
	buf := bytes.NewBuffer(byteStream)

	for {
		// If no more bytes are left to read, break the loop
		if buf.Len() == 0 {
			break
		}

		// Read the length prefix (varint) of the next Protobuf message
		msgLen, err := binary.ReadUvarint(buf)
		if err != nil {
			return nil, nil, fmt.Errorf("Failed to read message length: %v", err)
		}

		// If no more bytes are left to read, break the loop
		if buf.Len() == 0 {
			break
		}

		// Read the Protobuf message using the length obtained
		msgBytes := buf.Next(int(msgLen))

		// Unmarshal the Protobuf message into a ContactDetails object
		contactDetails := &signalpb.ContactDetails{}
		if err := proto.Unmarshal(msgBytes, contactDetails); err != nil {
			return nil, nil, fmt.Errorf("Failed to unmarshal ContactDetails: %v", err)
		}

		// Append the ContactDetails object to the result slice
		contactDetailsList = append(contactDetailsList, contactDetails)

		// If the ContactDetails object has an avatar, read it into a byte slice
		if contactDetails.Avatar != nil && contactDetails.Avatar.Length != nil && *contactDetails.Avatar.Length > 0 {
			avatarBytes := buf.Next(int(*contactDetails.Avatar.Length))
			// TODO why is this making a copy?
			avatarBytesCopy := make([]byte, len(avatarBytes))
			copy(avatarBytesCopy, avatarBytes)
			avatarList = append(avatarList, avatarBytesCopy)
		} else {
			// If there isn't, append nil so the indicies line up
			avatarList = append(avatarList, nil)
		}
	}

	return contactDetailsList, avatarList, nil
}
