// mautrix-signal - A Matrix-Signal puppeting bridge.
// Copyright (C) 2023 Tulir Asokan
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

package signalfmt

import (
	"cmp"
	"html"
	"strings"

	"golang.org/x/exp/maps"
	"golang.org/x/exp/slices"
	"maunium.net/go/mautrix/event"
	"maunium.net/go/mautrix/id"

	signalpb "go.mau.fi/mautrix-signal/pkg/signalmeow/protobuf"
)

type UserInfo struct {
	MXID id.UserID
	Name string
}

type FormatParams struct {
	GetUserInfo func(uuid string) UserInfo
}

type formatContext struct {
	IsInCodeblock bool
}

func (ctx formatContext) TextToHTML(text string) string {
	if ctx.IsInCodeblock {
		return html.EscapeString(text)
	}
	return event.TextToHTML(text)
}

func Parse(message string, ranges []*signalpb.BodyRange, params *FormatParams) *event.MessageEventContent {
	content := &event.MessageEventContent{
		MsgType:  event.MsgText,
		Body:     message,
		Mentions: &event.Mentions{},
	}
	if len(ranges) == 0 {
		return content
	}
	// LinkedRangeTree.Add depends on the ranges being sorted.
	slices.SortFunc(ranges, func(a, b *signalpb.BodyRange) int {
		x := cmp.Compare(*a.Start, *b.Start)
		if x == 0 {
			return cmp.Compare(*a.Length, *b.Length)
		}
		return x
	})

	lrt := &LinkedRangeTree{}
	mentions := map[id.UserID]struct{}{}
	for _, r := range ranges {
		br := &BodyRange{
			Start:  int(*r.Start),
			Length: int(*r.Length),
		}
		switch rv := r.GetAssociatedValue().(type) {
		case *signalpb.BodyRange_Style_:
			br.Value = Style(rv.Style)
		case *signalpb.BodyRange_MentionUuid:
			userInfo := params.GetUserInfo(rv.MentionUuid)
			if userInfo.MXID == "" {
				continue
			}
			mentions[userInfo.MXID] = struct{}{}
			// This could replace the wrong thing if there's a mention without fffc.
			// Maybe use NewUTF16String and do index replacements for the plaintext body too?
			content.Body = strings.Replace(content.Body, "\uFFFC", userInfo.Name, 1)
			br.Value = Mention(userInfo)
		}
		lrt.Add(br)
	}

	content.Mentions.UserIDs = maps.Keys(mentions)
	content.FormattedBody = lrt.Format(NewUTF16String(message), formatContext{})
	content.Format = event.FormatHTML
	return content
}
