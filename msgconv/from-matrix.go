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

package msgconv

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/rs/zerolog"
	"go.mau.fi/util/exerrors"
	"go.mau.fi/util/exmime"
	"go.mau.fi/util/ffmpeg"
	"go.mau.fi/util/variationselector"
	"golang.org/x/exp/constraints"
	"google.golang.org/protobuf/proto"
	"maunium.net/go/mautrix/event"

	"go.mau.fi/mautrix-signal/msgconv/matrixfmt"
	"go.mau.fi/mautrix-signal/pkg/signalmeow"
	signalpb "go.mau.fi/mautrix-signal/pkg/signalmeow/protobuf"
)

var (
	ErrUnsupportedMsgType  = errors.New("unsupported msgtype")
	ErrMediaDownloadFailed = errors.New("failed to download media")
	ErrMediaDecryptFailed  = errors.New("failed to decrypt media")
	ErrMediaConvertFailed  = errors.New("failed to convert")
	ErrMediaUploadFailed   = errors.New("failed to upload media")
	ErrInvalidGeoURI       = errors.New("invalid `geo:` URI in message")
)

func (mc *MessageConverter) ToSignal(ctx context.Context, evt *event.Event, content *event.MessageEventContent, relaybotFormatted bool) (*signalpb.DataMessage, error) {
	if evt.Type == event.EventSticker {
		content.MsgType = event.MessageType(event.EventSticker.Type)
	}

	// Matrix timestamps can be faked, but if the user is using their own Signal account, faking timestamps is their problem.
	ts := uint64(evt.Timestamp)
	// However, when relaying, timestamps shouldn't be trusted because anyone can send a message with any timestamp.
	if relaybotFormatted {
		ts = uint64(time.Now().UnixMilli())
	}
	dm := &signalpb.DataMessage{
		Timestamp: &ts,
		Quote:     mc.GetSignalReply(ctx, content),
		Preview:   mc.convertURLPreviewToSignal(ctx, evt),
	}
	if expirationTime := mc.GetData(ctx).ExpirationTime; expirationTime != 0 {
		dm.ExpireTimer = proto.Uint32(uint32(expirationTime))
	}
	if content.MsgType == event.MsgEmote && !relaybotFormatted {
		content.Body = "/me " + content.Body
		if content.FormattedBody != "" {
			content.FormattedBody = "/me " + content.FormattedBody
		}
	}
	body, bodyRanges := matrixfmt.Parse(mc.MatrixFmtParams, content)
	switch content.MsgType {
	case event.MsgText, event.MsgNotice, event.MsgEmote:
		dm.Body = proto.String(body)
		dm.BodyRanges = bodyRanges
	case event.MsgImage, event.MsgVideo, event.MsgAudio, event.MsgFile:
		att, err := mc.convertFileToSignal(ctx, evt, content)
		if err != nil {
			return nil, fmt.Errorf("failed to convert attachment: %w", err)
		}
		if content.FileName != "" && (content.FileName != content.Body || content.Format == event.FormatHTML) {
			dm.Body = proto.String(body)
			dm.BodyRanges = bodyRanges
		}
		dm.Attachments = []*signalpb.AttachmentPointer{att}
	case event.MessageType(event.EventSticker.Type):
		if content.FileName == "" {
			content.FileName = "sticker" + exmime.ExtensionFromMimetype(content.Info.MimeType)
		}
		att, err := mc.convertFileToSignal(ctx, evt, content)
		if err != nil {
			return nil, fmt.Errorf("failed to convert sticker: %w", err)
		}
		att.Flags = proto.Uint32(uint32(signalpb.AttachmentPointer_BORDERLESS))
		var emoji *string
		// TODO check for single grapheme cluster?
		if len([]rune(content.Body)) == 1 {
			emoji = proto.String(variationselector.Remove(content.Body))
		}
		dm.Sticker = &signalpb.DataMessage_Sticker{
			// Signal iOS validates that pack id/key are of the correct length.
			// Android is fine with any non-nil values (like a zero-length byte string).
			PackId:    make([]byte, 16),
			PackKey:   make([]byte, 32),
			StickerId: proto.Uint32(0),

			Data:  att,
			Emoji: emoji,
		}
	case event.MsgLocation:
		// TODO implement
		fallthrough
	default:
		return nil, fmt.Errorf("%w %s", ErrUnsupportedMsgType, content.MsgType)
	}
	return dm, nil
}

func maybeInt[T constraints.Integer](v T) *T {
	if v == 0 {
		return nil
	}
	return &v
}

func (mc *MessageConverter) convertFileToSignal(ctx context.Context, evt *event.Event, content *event.MessageEventContent) (*signalpb.AttachmentPointer, error) {
	log := zerolog.Ctx(ctx)
	mxc := content.URL
	if content.File != nil {
		mxc = content.File.URL
	}
	data, err := mc.DownloadMatrixMedia(ctx, mxc)
	if err != nil {
		return nil, exerrors.NewDualError(ErrMediaDownloadFailed, err)
	}
	if content.File != nil {
		err = content.File.DecryptInPlace(data)
		if err != nil {
			return nil, exerrors.NewDualError(ErrMediaDecryptFailed, err)
		}
	}
	fileName := content.Body
	if content.FileName != "" {
		fileName = content.FileName
	}
	_, isVoice := evt.Content.Raw["org.matrix.msc3245.voice"]
	mime := content.GetInfo().MimeType
	if isVoice {
		data, err = ffmpeg.ConvertBytes(ctx, data, ".m4a", []string{}, []string{"-c:a", "aac"}, mime)
		if err != nil {
			return nil, err
		}
		mime = "audio/aac"
		fileName += ".m4a"
	} else if evt.Type == event.EventSticker && mime != "image/webp" && mime != "image/png" && mime != "image/apng" {
		switch mime {
		case "image/webp", "image/png", "image/apng":
			// allowed
		case "image/gif":
			if !mc.ConvertGIFToAPNG {
				return nil, fmt.Errorf("converting gif stickers is not supported")
			}
			data, err = ffmpeg.ConvertBytes(ctx, data, ".apng", []string{}, []string{}, mime)
			if err != nil {
				return nil, fmt.Errorf("%w gif to apng: %w", ErrMediaConvertFailed, err)
			}
			fileName += ".apng"
			mime = "image/apng"
		default:
			return nil, fmt.Errorf("unsupported content type for sticker %s", mime)
		}
	}
	att, err := signalmeow.UploadAttachment(ctx, mc.GetClient(ctx), data)
	if err != nil {
		log.Err(err).Msg("Failed to upload file")
		return nil, exerrors.NewDualError(ErrMediaUploadFailed, err)
	}
	if isVoice {
		att.Flags = proto.Uint32(uint32(signalpb.AttachmentPointer_VOICE_MESSAGE))
	}
	att.ContentType = proto.String(mime)
	att.FileName = &fileName
	att.Height = maybeInt(uint32(content.Info.Height))
	att.Width = maybeInt(uint32(content.Info.Width))
	blurhash, ok := evt.Content.Raw["blurhash"].(string)
	if !ok {
		blurhash, ok = evt.Content.Raw["xyz.amorgan.blurhash"].(string)
	}
	if ok {
		att.BlurHash = proto.String(blurhash)
	}
	return att, nil
}
