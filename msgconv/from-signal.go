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
	"bytes"
	"context"
	"encoding/base64"
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/emersion/go-vcard"
	"github.com/rs/zerolog"
	"go.mau.fi/util/exfmt"
	"go.mau.fi/util/exmime"
	"go.mau.fi/util/ffmpeg"
	"golang.org/x/exp/slices"
	"maunium.net/go/mautrix/crypto/attachment"
	"maunium.net/go/mautrix/event"

	"go.mau.fi/mautrix-signal/msgconv/signalfmt"
	"go.mau.fi/mautrix-signal/pkg/signalmeow"
	signalpb "go.mau.fi/mautrix-signal/pkg/signalmeow/protobuf"
)

type ConvertedMessage struct {
	Parts       []*ConvertedMessagePart
	Timestamp   uint64
	DisappearIn uint32
}

func (cm *ConvertedMessage) MergeCaption() {
	if len(cm.Parts) != 2 || cm.Parts[1].Content.MsgType != event.MsgText {
		return
	}
	switch cm.Parts[0].Content.MsgType {
	case event.MsgImage, event.MsgVideo, event.MsgAudio, event.MsgFile:
	default:
		return
	}
	mediaContent := cm.Parts[0].Content
	textContent := cm.Parts[1].Content
	mediaContent.FileName = mediaContent.Body
	mediaContent.Body = textContent.Body
	mediaContent.Format = textContent.Format
	mediaContent.FormattedBody = textContent.FormattedBody
	cm.Parts = cm.Parts[:1]
}

type ConvertedMessagePart struct {
	Type    event.Type
	Content *event.MessageEventContent
	Extra   map[string]any
}

func calculateLength(dm *signalpb.DataMessage) int {
	if dm.GetFlags()&uint32(signalpb.DataMessage_EXPIRATION_TIMER_UPDATE) != 0 {
		return 1
	}
	if dm.Sticker != nil {
		return 1
	}
	length := len(dm.Attachments) + len(dm.Contact)
	if dm.Body != nil {
		length++
	}
	if dm.Payment != nil {
		length++
	}
	if dm.GiftBadge != nil {
		length++
	}
	if length == 0 && dm.GetRequiredProtocolVersion() > uint32(signalpb.DataMessage_CURRENT) {
		length = 1
	}
	return length
}

func CanConvertSignal(dm *signalpb.DataMessage) bool {
	return calculateLength(dm) > 0
}

func (mc *MessageConverter) ToMatrix(ctx context.Context, dm *signalpb.DataMessage) *ConvertedMessage {
	cm := &ConvertedMessage{
		Timestamp:   dm.GetTimestamp(),
		DisappearIn: dm.GetExpireTimer(),
		Parts:       make([]*ConvertedMessagePart, 0, calculateLength(dm)),
	}
	if dm.GetFlags()&uint32(signalpb.DataMessage_EXPIRATION_TIMER_UPDATE) != 0 {
		cm.Parts = append(cm.Parts, mc.ConvertDisappearingTimerChangeToMatrix(ctx, dm.GetExpireTimer(), true))
		// Don't disappear disappearing timer changes
		cm.DisappearIn = 0
		// Don't allow any other parts in a disappearing timer change message
		return cm
	}
	if dm.Sticker != nil {
		cm.Parts = append(cm.Parts, mc.convertStickerToMatrix(ctx, dm.Sticker))
		// Don't allow any other parts in a sticker message
		return cm
	}
	for i, att := range dm.GetAttachments() {
		if att.GetContentType() != "text/x-signal-plain" {
			cm.Parts = append(cm.Parts, mc.convertAttachmentToMatrix(ctx, i, att))
		} else {
			longBody, err := mc.downloadSignalLongText(ctx, att)
			if err == nil {
				dm.Body = longBody
			} else {
				zerolog.Ctx(ctx).Err(err).Msg("Failed to download Signal long text")
			}
		}
	}
	for _, contact := range dm.GetContact() {
		cm.Parts = append(cm.Parts, mc.convertContactToMatrix(ctx, contact))
	}
	if dm.Payment != nil {
		cm.Parts = append(cm.Parts, mc.convertPaymentToMatrix(ctx, dm.Payment))
	}
	if dm.GiftBadge != nil {
		cm.Parts = append(cm.Parts, mc.convertGiftBadgeToMatrix(ctx, dm.GiftBadge))
	}
	if dm.Body != nil {
		cm.Parts = append(cm.Parts, mc.convertTextToMatrix(ctx, dm))
	}
	if len(cm.Parts) == 0 && dm.GetRequiredProtocolVersion() > uint32(signalpb.DataMessage_CURRENT) {
		cm.Parts = append(cm.Parts, &ConvertedMessagePart{
			Type: event.EventMessage,
			Content: &event.MessageEventContent{
				MsgType: event.MsgNotice,
				Body:    "The bridge does not support this message type yet.",
			},
		})
	}
	replyTo, sender := mc.GetMatrixReply(ctx, dm.Quote)
	for _, part := range cm.Parts {
		if part.Content.Mentions == nil {
			part.Content.Mentions = &event.Mentions{}
		}
		if replyTo != "" {
			part.Content.RelatesTo = (&event.RelatesTo{}).SetReplyTo(replyTo)
			if !slices.Contains(part.Content.Mentions.UserIDs, sender) {
				part.Content.Mentions.UserIDs = append(part.Content.Mentions.UserIDs, sender)
			}
		}
	}
	return cm
}

func (mc *MessageConverter) ConvertDisappearingTimerChangeToMatrix(ctx context.Context, timer uint32, updatePortal bool) *ConvertedMessagePart {
	part := &ConvertedMessagePart{
		Type: event.EventMessage,
		Content: &event.MessageEventContent{
			MsgType: event.MsgNotice,
			Body:    fmt.Sprintf("Disappearing messages set to %s", exfmt.Duration(time.Duration(timer)*time.Second)),
		},
	}
	if timer == 0 {
		part.Content.Body = "Disappearing messages disabled"
	}
	if updatePortal {
		portal := mc.GetData(ctx)
		portal.ExpirationTime = timer
		err := portal.Update(ctx)
		if err != nil {
			zerolog.Ctx(ctx).Err(err).Msg("Failed to update portal disappearing timer in database")
		}
	}
	return part
}

func (mc *MessageConverter) convertTextToMatrix(ctx context.Context, dm *signalpb.DataMessage) *ConvertedMessagePart {
	content := signalfmt.Parse(ctx, dm.GetBody(), dm.GetBodyRanges(), mc.SignalFmtParams)
	extra := map[string]any{}
	if len(dm.Preview) > 0 {
		extra["com.beeper.linkpreviews"] = mc.convertURLPreviewsToBeeper(ctx, dm.Preview)
	}
	return &ConvertedMessagePart{
		Type:    event.EventMessage,
		Content: content,
		Extra:   extra,
	}
}

func (mc *MessageConverter) convertPaymentToMatrix(_ context.Context, payment *signalpb.DataMessage_Payment) *ConvertedMessagePart {
	return &ConvertedMessagePart{
		Type: event.EventMessage,
		Content: &event.MessageEventContent{
			MsgType: event.MsgNotice,
			Body:    "Payments are not yet supported",
		},
		Extra: map[string]any{
			"fi.mau.signal.payment": payment,
		},
	}
}

func (mc *MessageConverter) convertGiftBadgeToMatrix(_ context.Context, giftBadge *signalpb.DataMessage_GiftBadge) *ConvertedMessagePart {
	return &ConvertedMessagePart{
		Type: event.EventMessage,
		Content: &event.MessageEventContent{
			MsgType: event.MsgNotice,
			Body:    "Gift badges are not yet supported",
		},
		Extra: map[string]any{
			"fi.mau.signal.gift_badge": giftBadge,
		},
	}
}

func (mc *MessageConverter) convertContactToVCard(ctx context.Context, contact *signalpb.DataMessage_Contact) vcard.Card {
	card := make(vcard.Card)
	card.SetValue(vcard.FieldVersion, "4.0")
	name := contact.GetName()
	if name.GetFamilyName() != "" || name.GetGivenName() != "" {
		card.SetName(&vcard.Name{
			FamilyName:      name.GetFamilyName(),
			GivenName:       name.GetGivenName(),
			AdditionalName:  name.GetMiddleName(),
			HonorificPrefix: name.GetPrefix(),
			HonorificSuffix: name.GetSuffix(),
		})
	}
	if name.GetDisplayName() != "" {
		card.SetValue(vcard.FieldFormattedName, name.GetDisplayName())
	}
	if contact.GetOrganization() != "" {
		card.SetValue(vcard.FieldOrganization, contact.GetOrganization())
	}
	for _, addr := range contact.GetAddress() {
		field := vcard.Field{
			Value: strings.Join([]string{
				addr.GetPobox(),
				"", // extended address,
				addr.GetStreet(),
				addr.GetCity(),
				addr.GetRegion(),
				addr.GetPostcode(),
				addr.GetCountry(),
				// TODO put neighborhood somewhere?
			}, ";"),
			Params: make(vcard.Params),
		}
		if addr.GetLabel() != "" {
			field.Params.Set("LABEL", addr.GetLabel())
		}
		field.Params.Set(vcard.ParamType, strings.ToLower(addr.GetType().String()))
		card.Add(vcard.FieldAddress, &field)
	}
	for _, email := range contact.GetEmail() {
		field := vcard.Field{
			Value:  email.GetValue(),
			Params: make(vcard.Params),
		}
		field.Params.Set(vcard.ParamType, strings.ToLower(email.GetType().String()))
		if email.GetLabel() != "" {
			field.Params.Set("LABEL", email.GetLabel())
		}
		card.Add(vcard.FieldEmail, &field)
	}
	for _, phone := range contact.GetNumber() {
		field := vcard.Field{
			Value:  phone.GetValue(),
			Params: make(vcard.Params),
		}
		field.Params.Set(vcard.ParamType, strings.ToLower(phone.GetType().String()))
		if phone.GetLabel() != "" {
			field.Params.Set("LABEL", phone.GetLabel())
		}
		card.Add(vcard.FieldTelephone, &field)
	}
	if contact.GetAvatar().GetAvatar() != nil {
		avatarData, err := signalmeow.DownloadAttachment(ctx, contact.GetAvatar().GetAvatar())
		if err != nil {
			zerolog.Ctx(ctx).Err(err).Msg("Failed to download contact avatar")
		} else {
			mimeType := contact.GetAvatar().GetAvatar().GetContentType()
			if mimeType == "" {
				mimeType = http.DetectContentType(avatarData)
			}
			card.SetValue(vcard.FieldPhoto, fmt.Sprintf("data:%s;base64,%s", mimeType, base64.StdEncoding.EncodeToString(avatarData)))
		}
	}
	return card
}

func (mc *MessageConverter) convertContactToMatrix(ctx context.Context, contact *signalpb.DataMessage_Contact) *ConvertedMessagePart {
	card := mc.convertContactToVCard(ctx, contact)
	contact.Avatar = nil
	extraData := map[string]any{
		"fi.mau.signal.contact": contact,
	}
	var buf bytes.Buffer
	err := vcard.NewEncoder(&buf).Encode(card)
	if err != nil {
		zerolog.Ctx(ctx).Err(err).Msg("Failed to encode vCard")
		return &ConvertedMessagePart{
			Type: event.EventMessage,
			Content: &event.MessageEventContent{
				MsgType: event.MsgNotice,
				Body:    "Failed to encode vCard",
			},
			Extra: extraData,
		}
	}
	data := buf.Bytes()
	var file *event.EncryptedFileInfo
	uploadMime := "text/vcard"
	uploadFileName := "contact.vcf"
	if mc.GetData(ctx).Encrypted {
		file = &event.EncryptedFileInfo{
			EncryptedFile: *attachment.NewEncryptedFile(),
			URL:           "",
		}
		file.EncryptInPlace(data)
		uploadMime = "application/octet-stream"
		uploadFileName = ""
	}
	mxc, err := mc.UploadMatrixMedia(ctx, data, uploadFileName, uploadMime)
	if err != nil {
		zerolog.Ctx(ctx).Err(err).Msg("Failed to upload vCard")
		return &ConvertedMessagePart{
			Type: event.EventMessage,
			Content: &event.MessageEventContent{
				MsgType: event.MsgNotice,
				Body:    "Failed to upload vCard",
			},
			Extra: extraData,
		}
	}
	displayName := contact.GetName().GetDisplayName()
	if displayName == "" {
		displayName = contact.GetName().GetGivenName()
		if contact.GetName().GetFamilyName() != "" {
			if displayName != "" {
				displayName += " "
			}
			displayName += contact.GetName().GetFamilyName()
		}
	}
	if displayName == "" {
		displayName = "contact"
	}
	content := &event.MessageEventContent{
		MsgType: event.MsgFile,
		Body:    displayName + ".vcf",
		Info: &event.FileInfo{
			MimeType: "text/vcf",
			Size:     len(data),
		},
	}
	if file != nil {
		file.URL = mxc
		content.File = file
	} else {
		content.URL = mxc
	}
	return &ConvertedMessagePart{
		Type:    event.EventMessage,
		Content: content,
		Extra:   extraData,
	}
}

func (mc *MessageConverter) convertAttachmentToMatrix(ctx context.Context, index int, att *signalpb.AttachmentPointer) *ConvertedMessagePart {
	part, err := mc.reuploadAttachment(ctx, att)
	if err != nil {
		zerolog.Ctx(ctx).Err(err).Int("attachment_index", index).Msg("Failed to handle attachment")
		return &ConvertedMessagePart{
			Type: event.EventMessage,
			Content: &event.MessageEventContent{
				MsgType: event.MsgNotice,
				Body:    fmt.Sprintf("Failed to handle attachment %s: %v", att.GetFileName(), err),
			},
		}
	}
	return part
}

func (mc *MessageConverter) convertStickerToMatrix(ctx context.Context, sticker *signalpb.DataMessage_Sticker) *ConvertedMessagePart {
	converted, err := mc.reuploadAttachment(ctx, sticker.GetData())
	if err != nil {
		zerolog.Ctx(ctx).Err(err).Msg("Failed to handle sticker")
		return &ConvertedMessagePart{
			Type: event.EventMessage,
			Content: &event.MessageEventContent{
				MsgType: event.MsgNotice,
				Body:    fmt.Sprintf("Failed to handle sticker: %v", err),
			},
		}
	}
	// Signal stickers are 512x512, so tell Matrix clients to render them as 256x256
	if converted.Content.Info.Width == 512 && converted.Content.Info.Height == 512 {
		converted.Content.Info.Width = 256
		converted.Content.Info.Height = 256
	}
	converted.Content.Body = sticker.GetEmoji()
	converted.Type = event.EventSticker
	converted.Content.MsgType = ""
	// TODO fetch full pack metadata like the old bridge did?
	converted.Extra["fi.mau.signal.sticker"] = map[string]any{
		"id":    sticker.GetStickerId(),
		"emoji": sticker.GetEmoji(),
		"pack": map[string]any{
			"id":  sticker.GetPackId(),
			"key": sticker.GetPackKey(),
		},
	}
	return converted
}

func (mc *MessageConverter) downloadSignalLongText(ctx context.Context, att *signalpb.AttachmentPointer) (*string, error) {
	data, err := signalmeow.DownloadAttachment(ctx, att)
	if err != nil {
		return nil, fmt.Errorf("failed to download attachment: %w", err)
	}
	longBody := string(data)
	return &longBody, nil
}

func (mc *MessageConverter) reuploadAttachment(ctx context.Context, att *signalpb.AttachmentPointer) (*ConvertedMessagePart, error) {
	data, err := signalmeow.DownloadAttachment(ctx, att)
	if err != nil {
		return nil, fmt.Errorf("failed to download attachment: %w", err)
	}
	mimeType := att.GetContentType()
	if mimeType == "" {
		mimeType = http.DetectContentType(data)
	}
	fileName := att.GetFileName()
	extra := map[string]any{}
	if mc.ConvertVoiceMessages && att.GetFlags()&uint32(signalpb.AttachmentPointer_VOICE_MESSAGE) != 0 {
		data, err = ffmpeg.ConvertBytes(ctx, data, ".ogg", []string{}, []string{"-c:a", "libopus"}, mimeType)
		if err != nil {
			return nil, fmt.Errorf("failed to convert audio to ogg/opus: %w", err)
		}
		fileName += ".ogg"
		mimeType = "audio/ogg"
		extra["org.matrix.msc3245.voice"] = map[string]any{}
		// TODO include duration here (and in info) if there's some easy way to extract it with ffmpeg
		//extra["org.matrix.msc1767.audio"] = map[string]any{"duration": ???}
	}
	var file *event.EncryptedFileInfo
	uploadMime := mimeType
	uploadFileName := fileName
	if mc.GetData(ctx).Encrypted {
		file = &event.EncryptedFileInfo{
			EncryptedFile: *attachment.NewEncryptedFile(),
			URL:           "",
		}
		file.EncryptInPlace(data)
		uploadMime = "application/octet-stream"
		uploadFileName = ""
	}
	mxc, err := mc.UploadMatrixMedia(ctx, data, uploadFileName, uploadMime)
	if err != nil {
		return nil, err
	}
	content := &event.MessageEventContent{
		Body: fileName,
		Info: &event.FileInfo{
			MimeType: mimeType,
			Width:    int(att.GetWidth()),
			Height:   int(att.GetHeight()),
			Size:     len(data),
		},
	}
	if att.GetBlurHash() != "" {
		content.Info.Blurhash = att.GetBlurHash()
		content.Info.AnoaBlurhash = att.GetBlurHash()
	}
	switch strings.Split(mimeType, "/")[0] {
	case "image":
		content.MsgType = event.MsgImage
	case "video":
		content.MsgType = event.MsgVideo
	case "audio":
		content.MsgType = event.MsgAudio
	default:
		content.MsgType = event.MsgFile
	}
	if content.Body == "" {
		content.Body = strings.TrimPrefix(string(content.MsgType), "m.") + exmime.ExtensionFromMimetype(mimeType)
	}
	if file != nil {
		file.URL = mxc
		content.File = file
	} else {
		content.URL = mxc
	}
	return &ConvertedMessagePart{
		Type:    event.EventMessage,
		Content: content,
		Extra:   extra,
	}, nil
}
