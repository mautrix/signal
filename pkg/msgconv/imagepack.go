// mautrix-signal - A Matrix-Signal puppeting bridge.
// Copyright (C) 2026 Tulir Asokan
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

package msgconv

import (
	"fmt"
	"strconv"

	"google.golang.org/protobuf/proto"
	"maunium.net/go/mautrix/event"

	signalpb "go.mau.fi/mautrix-signal/pkg/signalmeow/protobuf"
)

const StickerSourceID = "signal"
const PackURLFormat = "https://signal.art/addstickers/#pack_id=%x&pack_key=%x"

const PackIDLength = 16
const PackKeyLength = 32
const PackURLLength = len(PackURLFormat) - len("%x")*2 + PackIDLength*2 + PackKeyLength*2

var zeroPackID = make([]byte, PackIDLength)

func ParseStickerMeta(info *event.BridgedSticker) *signalpb.DataMessage_Sticker {
	if info.Network != StickerSourceID || len(info.PackURL) != PackURLLength {
		return nil
	}
	stickerID, err := strconv.ParseUint(info.ID, 10, 32)
	if err != nil {
		return nil
	}
	var packID, packKey []byte
	_, err = fmt.Sscanf(info.PackURL, PackURLFormat, &packID, &packKey)
	if err != nil || len(packID) != PackIDLength || len(packKey) != PackKeyLength {
		return nil
	}
	return &signalpb.DataMessage_Sticker{
		PackId:    packID,
		PackKey:   packKey,
		StickerId: proto.Uint32(uint32(stickerID)),
		Emoji:     &info.Emoji,
	}
}
