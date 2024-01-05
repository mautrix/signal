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
	"encoding/json"
	"regexp"
	"time"

	"github.com/rs/zerolog"
	"github.com/tidwall/gjson"
	"google.golang.org/protobuf/proto"
	"maunium.net/go/mautrix"
	"maunium.net/go/mautrix/event"

	signalpb "go.mau.fi/mautrix-signal/pkg/signalmeow/protobuf"
)

type BeeperLinkPreview struct {
	mautrix.RespPreviewURL
	MatchedURL      string                   `json:"matched_url"`
	ImageEncryption *event.EncryptedFileInfo `json:"beeper:image:encryption,omitempty"`
}

func (mc *MessageConverter) convertURLPreviewsToBeeper(ctx context.Context, preview []*signalpb.Preview) []*BeeperLinkPreview {
	output := make([]*BeeperLinkPreview, len(preview))
	for i, p := range preview {
		output[i] = mc.convertURLPreviewToBeeper(ctx, p)
	}
	return output
}

func (mc *MessageConverter) convertURLPreviewToBeeper(ctx context.Context, preview *signalpb.Preview) *BeeperLinkPreview {
	output := &BeeperLinkPreview{
		MatchedURL: preview.GetUrl(),
		RespPreviewURL: mautrix.RespPreviewURL{
			CanonicalURL: preview.GetUrl(),
			Title:        preview.GetTitle(),
			Description:  preview.GetDescription(),
		},
	}
	if preview.Image != nil {
		msg, err := mc.reuploadAttachment(ctx, preview.Image)
		if err != nil {
			zerolog.Ctx(ctx).Err(err).Msg("Failed to reupload link preview image")
		} else {
			output.ImageURL = msg.Content.URL
			output.ImageEncryption = msg.Content.File
			output.ImageType = msg.Content.Info.MimeType
			output.ImageSize = msg.Content.Info.Size
			output.ImageHeight = msg.Content.Info.Height
			output.ImageWidth = msg.Content.Info.Width
		}
	}
	return output
}

var URLRegex = regexp.MustCompile(`https?://[^\s/_*]+(?:/\S*)?`)

func (mc *MessageConverter) convertURLPreviewToSignal(ctx context.Context, evt *event.Event) []*signalpb.Preview {
	var previews []*BeeperLinkPreview

	log := zerolog.Ctx(ctx)
	rawPreview := gjson.GetBytes(evt.Content.VeryRaw, `com\.beeper\.linkpreviews`)
	if rawPreview.Exists() && rawPreview.IsArray() {
		if err := json.Unmarshal([]byte(rawPreview.Raw), &previews); err != nil || len(previews) == 0 {
			return nil
		}
	} /* else if portal.bridge.Config.Bridge.URLPreviews {
		if matchedURL := URLRegex.FindString(evt.Content.AsMessage().Body); len(matchedURL) == 0 {
			return nil
		} else if parsed, err := url.Parse(matchedURL); err != nil {
			return nil
		} else if parsed.Host, err = idna.ToASCII(parsed.Host); err != nil {
			return nil
		} else if mxPreview, err := portal.MainIntent().GetURLPreview(parsed.String()); err != nil {
			log.Err(err).Str("matched_url", matchedURL).Msg("Failed to fetch preview for URL found in message")
			return nil
		} else {
			previews = []*BeeperLinkPreview{{
				RespPreviewURL: *mxPreview,
				MatchedURL:     matchedURL,
			}}
		}
	}*/
	if len(previews) == 0 {
		return nil
	}
	output := make([]*signalpb.Preview, len(previews))
	for i, preview := range previews {
		output[i] = &signalpb.Preview{
			Url:         proto.String(preview.MatchedURL),
			Title:       proto.String(preview.Title),
			Description: proto.String(preview.Description),
			Date:        proto.Uint64(uint64(time.Now().UnixMilli())),
		}
		imageMXC := preview.ImageURL
		if preview.ImageEncryption != nil {
			imageMXC = preview.ImageEncryption.URL
		}
		if imageMXC != "" {
			data, err := mc.DownloadMatrixMedia(ctx, imageMXC)
			if err != nil {
				log.Err(err).Int("preview_index", i).Msg("Failed to download URL preview image")
				continue
			}
			if preview.ImageEncryption != nil {
				err = preview.ImageEncryption.DecryptInPlace(data)
				if err != nil {
					log.Err(err).Int("preview_index", i).Msg("Failed to decrypt URL preview image")
					continue
				}
			}
			uploaded, err := mc.GetClient(ctx).UploadAttachment(ctx, data)
			if err != nil {
				log.Err(err).Int("preview_index", i).Msg("Failed to reupload URL preview image")
				continue
			}
			uploaded.ContentType = proto.String(preview.ImageType)
			uploaded.Width = proto.Uint32(uint32(preview.ImageWidth))
			uploaded.Height = proto.Uint32(uint32(preview.ImageHeight))
			output[i].Image = uploaded
		}
	}
	return output
}
