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
	"context"
	"fmt"
	"time"
	"unicode/utf16"

	"github.com/google/uuid"
	"github.com/rs/zerolog"
	"google.golang.org/protobuf/proto"
	"maunium.net/go/mautrix/bridgev2"
	"maunium.net/go/mautrix/bridgev2/database"
	"maunium.net/go/mautrix/bridgev2/networkid"
	"maunium.net/go/mautrix/event"

	"go.mau.fi/mautrix-signal/pkg/signalid"
	"go.mau.fi/mautrix-signal/pkg/signalmeow"
	"go.mau.fi/mautrix-signal/pkg/signalmeow/protobuf/signalpb"
)

const StoryLifetime = 24 * time.Hour

func (mc *MessageConverter) StoryToMatrix(
	ctx context.Context,
	client *signalmeow.Client,
	portal *bridgev2.Portal,
	sender uuid.UUID,
	intent bridgev2.MatrixAPI,
	story *signalpb.StoryMessage,
	timestamp uint64,
	caption string,
) *bridgev2.ConvertedMessage {
	story = proto.Clone(story).(*signalpb.StoryMessage)
	dm := &signalpb.DataMessage{
		Timestamp:  proto.Uint64(timestamp),
		BodyRanges: story.GetBodyRanges(),
	}
	if att := story.GetFileAttachment(); att != nil {
		dm.Attachments = []*signalpb.AttachmentPointer{att}
		if att.GetCaption() != "" {
			dm.Body = att.Caption
		}
	} else if text := story.GetTextAttachment(); text != nil {
		dm.Body = proto.String(text.GetText())
		if text.GetPreview() != nil {
			dm.Preview = []*signalpb.Preview{text.GetPreview()}
			if text.GetText() == "" {
				dm.Body = proto.String(text.GetPreview().GetUrl())
			}
		}
	}
	if caption != "" {
		prefixBody(dm, caption)
	}
	cm := mc.ToMatrix(ctx, client, portal, sender, intent, dm, nil)
	cm.Disappear = database.DisappearingSetting{
		Type:        event.DisappearingTypeAfterSend,
		Timer:       StoryLifetime,
		DisappearAt: time.UnixMilli(int64(timestamp)).Add(StoryLifetime),
	}
	return cm
}

func (mc *MessageConverter) convertStoryContextToMatrix(
	ctx context.Context,
	client *signalmeow.Client,
	portal *bridgev2.Portal,
	sender uuid.UUID,
	intent bridgev2.MatrixAPI,
	dm *signalpb.DataMessage,
	attMap AttachmentMap,
) *bridgev2.ConvertedMessage {
	storyAuthor, err := signalmeow.ParseStringOrBinaryUUID(dm.GetStoryContext().GetAuthorAci(), dm.GetStoryContext().GetAuthorAciBinary())
	if err != nil {
		zerolog.Ctx(ctx).Warn().Err(err).Msg("Failed to parse story context author")
	}
	storyID := signalid.MakeMessageID(storyAuthor, dm.GetStoryContext().GetSentTimestamp())
	whose := "a story"
	if storyAuthor == client.Store.ACI {
		whose = "your story"
	}
	dm = proto.Clone(dm).(*signalpb.DataMessage)
	dm.StoryContext = nil
	if dm.Reaction != nil {
		dm.Body = proto.String(fmt.Sprintf("Reacted %s to %s", dm.GetReaction().GetEmoji(), whose))
		dm.Reaction = nil
	} else if !mc.Bridge.Config.CrossRoomReplies {
		prefixBody(dm, "Replied to "+whose)
	}
	cm := mc.ToMatrix(ctx, client, portal, sender, intent, dm, attMap)
	cm.ReplyTo = &networkid.MessageOptionalPartID{MessageID: storyID}
	return cm
}

func prefixBody(dm *signalpb.DataMessage, prefix string) {
	if dm.GetBody() == "" {
		dm.Body = proto.String(prefix)
		return
	}
	prefix += ": "
	shift := uint32(len(utf16.Encode([]rune(prefix))))
	for _, br := range dm.BodyRanges {
		br.Start = proto.Uint32(br.GetStart() + shift)
	}
	dm.Body = proto.String(prefix + dm.GetBody())
}
