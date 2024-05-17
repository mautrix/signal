// mautrix-signal - A Matrix-signal puppeting bridge.
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

	"maunium.net/go/mautrix/event"
	"maunium.net/go/mautrix/id"

	"go.mau.fi/mautrix-signal/database"
	"go.mau.fi/mautrix-signal/msgconv/matrixfmt"
	"go.mau.fi/mautrix-signal/msgconv/signalfmt"
	"go.mau.fi/mautrix-signal/pkg/signalmeow"
	signalpb "go.mau.fi/mautrix-signal/pkg/signalmeow/protobuf"
)

type PortalMethods interface {
	UploadMatrixMedia(ctx context.Context, data []byte, fileName, contentType string) (id.ContentURIString, error)
	DownloadMatrixMedia(ctx context.Context, uri id.ContentURIString) ([]byte, error)
	GetMatrixReply(ctx context.Context, msg *signalpb.DataMessage_Quote) (replyTo id.EventID, replyTargetSender id.UserID)
	GetSignalReply(ctx context.Context, content *event.MessageEventContent) *signalpb.DataMessage_Quote

	GetClient(ctx context.Context) *signalmeow.Client

	GetData(ctx context.Context) *database.Portal
}

type ExtendedPortalMethods interface {
	QueueFileTransfer(ctx context.Context, msgTS uint64, fileName string, ap *signalpb.AttachmentPointer) (id.ContentURIString, error)
}

type MessageConverter struct {
	PortalMethods

	SignalFmtParams *signalfmt.FormatParams
	MatrixFmtParams *matrixfmt.HTMLParser

	ConvertVoiceMessages bool
	ConvertGIFToAPNG     bool
	MaxFileSize          int64
	AsyncFiles           bool

	LocationFormat string
}

func (mc *MessageConverter) IsPrivateChat(ctx context.Context) bool {
	return !mc.GetData(ctx).UserID().IsEmpty()
}
