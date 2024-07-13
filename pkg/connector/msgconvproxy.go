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
	"context"

	"google.golang.org/protobuf/proto"
	"maunium.net/go/mautrix/bridgev2"
	"maunium.net/go/mautrix/bridgev2/database"
	"maunium.net/go/mautrix/event"
	"maunium.net/go/mautrix/id"

	legacydb "go.mau.fi/mautrix-signal/database"
	"go.mau.fi/mautrix-signal/msgconv"
	"go.mau.fi/mautrix-signal/pkg/signalmeow"
	signalpb "go.mau.fi/mautrix-signal/pkg/signalmeow/protobuf"
)

type contextKey int

var msgconvContextKey contextKey

type msgconvContext struct {
	Connector *SignalConnector
	Intent    bridgev2.MatrixAPI
	Client    *SignalClient
	Portal    *bridgev2.Portal
	ReplyTo   *database.Message
}

type msgconvPortalMethods struct{}

var _ msgconv.PortalMethods = (*msgconvPortalMethods)(nil)

func (mpm *msgconvPortalMethods) UploadMatrixMedia(ctx context.Context, data []byte, fileName, contentType string) (id.ContentURIString, error) {
	mcCtx := ctx.Value(msgconvContextKey).(*msgconvContext)
	uri, _, err := mcCtx.Intent.UploadMedia(ctx, "", data, fileName, contentType)
	return uri, err
}

func (mpm *msgconvPortalMethods) DownloadMatrixMedia(ctx context.Context, uri id.ContentURIString) ([]byte, error) {
	return ctx.Value(msgconvContextKey).(*msgconvContext).Connector.Bridge.Bot.DownloadMedia(ctx, uri, nil)
}

func (mpm *msgconvPortalMethods) GetMatrixReply(ctx context.Context, msg *signalpb.DataMessage_Quote) (replyTo id.EventID, replyTargetSender id.UserID) {
	// Matrix replies are handled in bridgev2 code
	return "", ""
}

func (mpm *msgconvPortalMethods) GetSignalReply(ctx context.Context, content *event.MessageEventContent) *signalpb.DataMessage_Quote {
	mcCtx := ctx.Value(msgconvContextKey).(*msgconvContext)
	if mcCtx.ReplyTo == nil {
		return nil
	}
	quote := &signalpb.DataMessage_Quote{
		Id:        proto.Uint64(uint64(mcCtx.ReplyTo.Timestamp.UnixMilli())),
		AuthorAci: proto.String(string(mcCtx.ReplyTo.SenderID)),
		Type:      signalpb.DataMessage_Quote_NORMAL.Enum(),
	}
	if mcCtx.ReplyTo.Metadata.(*MessageMetadata).ContainsAttachments {
		quote.Attachments = make([]*signalpb.DataMessage_Quote_QuotedAttachment, 1)
	}
	return quote
}

func (mpm *msgconvPortalMethods) GetClient(ctx context.Context) *signalmeow.Client {
	return ctx.Value(msgconvContextKey).(*msgconvContext).Client.Client
}

func (mpm *msgconvPortalMethods) GetData(ctx context.Context) *legacydb.Portal {
	mcCtx := ctx.Value(msgconvContextKey).(*msgconvContext)
	portal := mcCtx.Portal
	userID, groupID, _ := parsePortalID(portal.ID)
	chatID := string(groupID)
	if chatID == "" {
		chatID = userID.String()
	}
	pk := legacydb.PortalKey{
		ChatID: chatID,
	}
	if len(chatID) != 44 {
		pk.Receiver = mcCtx.Client.Client.Store.ACI
	}
	return &legacydb.Portal{
		PortalKey: pk,
		MXID:      portal.MXID,
		Name:      portal.Name,
		Topic:     portal.Topic,
		//AvatarPath:     "",
		//AvatarHash:     "",
		//AvatarURL:      id.ContentURI{},
		NameSet:   portal.NameSet,
		AvatarSet: portal.AvatarSet,
		TopicSet:  portal.TopicSet,
		Revision:  portal.Metadata.(*PortalMetadata).Revision,
		Encrypted: true,
		//RelayUserID:    portal.Relay.UserMXID,
		ExpirationTime: uint32(portal.Disappear.Timer.Seconds()),
	}
}
