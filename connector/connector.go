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
	"fmt"
	"strconv"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/rs/zerolog"
	"go.mau.fi/util/dbutil"
	"golang.org/x/exp/slices"
	"google.golang.org/protobuf/proto"

	"maunium.net/go/mautrix/bridgev2"
	"maunium.net/go/mautrix/bridgev2/database"
	"maunium.net/go/mautrix/bridgev2/networkid"
	"maunium.net/go/mautrix/event"
	"maunium.net/go/mautrix/id"

	legacydb "go.mau.fi/mautrix-signal/database"
	"go.mau.fi/mautrix-signal/msgconv"
	"go.mau.fi/mautrix-signal/msgconv/matrixfmt"
	"go.mau.fi/mautrix-signal/msgconv/signalfmt"
	"go.mau.fi/mautrix-signal/pkg/libsignalgo"
	"go.mau.fi/mautrix-signal/pkg/signalmeow"
	"go.mau.fi/mautrix-signal/pkg/signalmeow/events"
	signalpb "go.mau.fi/mautrix-signal/pkg/signalmeow/protobuf"
	"go.mau.fi/mautrix-signal/pkg/signalmeow/store"
	"go.mau.fi/mautrix-signal/pkg/signalmeow/types"
)

type SignalConnector struct {
	MsgConv *msgconv.MessageConverter
	Store   *store.Container
	Bridge  *bridgev2.Bridge
}

func NewConnector() *SignalConnector {
	return &SignalConnector{}
}

func (s *SignalConnector) Init(bridge *bridgev2.Bridge) {
	s.Store = store.NewStore(bridge.DB.Database, dbutil.ZeroLogger(bridge.Log.With().Str("db_section", "signalmeow").Logger()))
	s.Bridge = bridge
	s.MsgConv = &msgconv.MessageConverter{
		PortalMethods: &msgconvPortalMethods{},
		SignalFmtParams: &signalfmt.FormatParams{
			GetUserInfo: func(ctx context.Context, uuid uuid.UUID) signalfmt.UserInfo {
				ghost, err := s.Bridge.GetGhostByID(ctx, makeUserID(uuid))
				if err != nil {
					// TODO log?
					return signalfmt.UserInfo{}
				}
				userInfo := signalfmt.UserInfo{
					MXID: ghost.MXID,
					Name: ghost.Name,
				}
				userLogin := s.Bridge.GetCachedUserLoginByID(networkid.UserLoginID(uuid.String()))
				if userLogin != nil {
					userInfo.MXID = userLogin.UserMXID
					// TODO find matrix user displayname?
				}
				return userInfo
			},
		},
		MatrixFmtParams: &matrixfmt.HTMLParser{
			GetUUIDFromMXID: func(ctx context.Context, userID id.UserID) uuid.UUID {
				parsed, ok := s.Bridge.Matrix.ParseGhostMXID(userID)
				if ok {
					u, _ := uuid.Parse(string(parsed))
					return u
				}
				user, _ := s.Bridge.GetExistingUserByMXID(ctx, userID)
				// TODO log errors?
				if user != nil {
					preferredLogin, _ := ctx.Value(msgconvContextKey).(*msgconvContext).Portal.FindPreferredLogin(ctx, user)
					if preferredLogin != nil {
						u, _ := uuid.Parse(string(preferredLogin.ID))
						return u
					}
				}
				return uuid.Nil
			},
		},
		ConvertVoiceMessages: true,
		ConvertGIFToAPNG:     true,
		MaxFileSize:          100 * 1024 * 1024,
		AsyncFiles:           true,
		LocationFormat:       "",
	}
}

func (s *SignalConnector) Start(ctx context.Context) error {
	return s.Store.Upgrade(ctx)
}

var _ bridgev2.NetworkConnector = (*SignalConnector)(nil)
var _ bridgev2.NetworkAPI = (*SignalClient)(nil)
var _ msgconv.PortalMethods = (*msgconvPortalMethods)(nil)

func (s *SignalConnector) PrepareLogin(ctx context.Context, login *bridgev2.UserLogin) error {
	aci, err := uuid.Parse(string(login.ID))
	if err != nil {
		return fmt.Errorf("failed to parse user login ID: %w", err)
	}
	device, err := s.Store.DeviceByACI(ctx, aci)
	if err != nil {
		return fmt.Errorf("failed to get device from store: %w", err)
	} else if device == nil {
		return fmt.Errorf("%w: device not found in store", bridgev2.ErrNotLoggedIn)
	}
	sc := &SignalClient{
		Main:      s,
		UserLogin: login,
		Client: &signalmeow.Client{
			Store: device,
		},
	}
	sc.Client.EventHandler = sc.handleSignalEvent
	login.Client = sc
	return nil
}

type SignalClient struct {
	Main      *SignalConnector
	UserLogin *bridgev2.UserLogin
	Client    *signalmeow.Client
}

func (s *SignalClient) GetChatInfo(ctx context.Context, portal *bridgev2.Portal) (*bridgev2.PortalInfo, error) {
	return &bridgev2.PortalInfo{}, nil
}

func (s *SignalClient) Connect(ctx context.Context) error {
	_, err := s.Client.StartReceiveLoops(ctx)
	if err != nil {
		return err
	}
	// TODO status
	return nil
}

func (s *SignalClient) IsLoggedIn() bool {
	return s.Client.IsLoggedIn()
}

func (s *SignalClient) parsePortalID(portalID networkid.PortalID) (string, error) {
	parts := strings.Split(string(portalID), "|")
	if len(parts) == 1 {
		if len(parts[0]) == 44 {
			return parts[0], nil
		}
		return "", fmt.Errorf("invalid portal ID: expected group ID to be 44 characters")
	} else if len(parts) == 2 {
		ourACI := s.Client.Store.ACI.String()
		if parts[0] == ourACI {
			return parts[1], nil
		} else if parts[1] == ourACI {
			return parts[0], nil
		} else {
			return "", fmt.Errorf("invalid portal ID: expected one side to be our ACI")
		}
	}
	return "", fmt.Errorf("invalid portal ID: unexpected number of pipe-separated parts")
}

func (s *SignalClient) getPortalID(chatID string) networkid.PortalID {
	if len(chatID) == 44 {
		// Group ID
		return networkid.PortalID(chatID)
	} else if strings.HasPrefix(chatID, "PNI:") {
		// Temporary new DM ID: always put our own ACI first, the portal will never be shared anyway
		return networkid.PortalID(fmt.Sprintf("%s|%s", s.Client.Store.ACI, chatID))
	} else {
		// DM ID: sort the two parts so the ID is always the same regardless of which side is receiving the message
		parts := []string{s.Client.Store.ACI.String(), chatID}
		slices.Sort(parts)
		return networkid.PortalID(strings.Join(parts, "|"))
	}
}

func makeMessageID(sender uuid.UUID, timestamp uint64) networkid.MessageID {
	return networkid.MessageID(fmt.Sprintf("%s|%d", sender, timestamp))
}

func makeUserID(user uuid.UUID) networkid.UserID {
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

type contextKey int

var msgconvContextKey contextKey

type msgconvContext struct {
	Connector *SignalConnector
	Intent    bridgev2.MatrixAPI
	Client    *SignalClient
	Portal    *bridgev2.Portal
	ReplyTo   *database.Message
}

func (s *SignalClient) convertMessage(ctx context.Context, portal *bridgev2.Portal, data *events.ChatEvent) (*bridgev2.ConvertedMessage, error) {
	dataMsg := data.Event.(*signalpb.DataMessage)
	converted := s.Main.MsgConv.ToMatrix(ctx, dataMsg)
	var replyTo *networkid.MessageOptionalPartID
	if dataMsg.GetQuote() != nil {
		quoteAuthor, _ := uuid.Parse(dataMsg.Quote.GetAuthorAci())
		replyTo = &networkid.MessageOptionalPartID{
			MessageID: makeMessageID(quoteAuthor, dataMsg.Quote.GetId()),
		}
	}
	convertedParts := make([]*bridgev2.ConvertedMessagePart, len(converted.Parts))
	for i, part := range converted.Parts {
		convertedParts[i] = &bridgev2.ConvertedMessagePart{
			ID:      makeMessagePartID(i),
			Type:    part.Type,
			Content: part.Content,
			Extra:   part.Extra,
		}

	}
	return &bridgev2.ConvertedMessage{
		ID:          makeMessageID(data.Info.Sender, dataMsg.GetTimestamp()),
		EventSender: s.makeEventSender(data.Info.Sender),
		Timestamp:   time.UnixMilli(int64(converted.Timestamp)),
		ReplyTo:     replyTo,
		Parts:       convertedParts,
	}, nil
}

func (s *SignalClient) handleSignalEvent(rawEvt events.SignalEvent) {
	switch evt := rawEvt.(type) {
	case *events.ChatEvent:
		switch innerEvt := evt.Event.(type) {
		case *signalpb.DataMessage:
			s.Main.Bridge.QueueRemoteEvent(s.UserLogin, &bridgev2.SimpleRemoteEvent[*events.ChatEvent]{
				Type: bridgev2.RemoteEventMessage,
				LogContext: func(c zerolog.Context) zerolog.Context {
					return c.
						Uint64("message_id", innerEvt.GetTimestamp()).
						Stringer("sender_id", evt.Info.Sender)
				},
				PortalID:     s.getPortalID(evt.Info.ChatID),
				Data:         evt,
				CreatePortal: true,

				ConvertMessageFunc: s.convertMessage,
			})
		case *signalpb.EditMessage:
		case *signalpb.TypingMessage:
		}
	case *events.DecryptionError:
	case *events.Receipt:
	case *events.ReadSelf:
	case *events.Call:
	case *events.ContactList:
	case *events.ACIFound:
	}
}

func (s *SignalClient) HandleMatrixMessage(ctx context.Context, msg *bridgev2.MatrixMessage) (message *database.Message, err error) {
	mcCtx := &msgconvContext{
		Connector: s.Main,
		Intent:    nil,
		Client:    s,
		Portal:    msg.Portal,
		ReplyTo:   msg.ReplyTo,
	}
	ctx = context.WithValue(ctx, msgconvContextKey, mcCtx)
	chatID, err := s.parsePortalID(msg.Portal.ID)
	if err != nil {
		return nil, err
	}
	var userID libsignalgo.ServiceID
	var groupID types.GroupIdentifier
	if len(chatID) == 44 {
		groupID = types.GroupIdentifier(chatID)
	} else {
		userID, err = libsignalgo.ServiceIDFromString(chatID)
		if err != nil {
			return nil, err
		}
	}
	converted, err := s.Main.MsgConv.ToSignal(ctx, msg.Event, msg.Content, msg.OrigSender != nil)
	if err != nil {
		return nil, err
	}
	wrappedContent := &signalpb.Content{
		DataMessage: converted,
	}
	if groupID != "" {
		res, err := s.Client.SendGroupMessage(ctx, groupID, wrappedContent)
		if err != nil {
			return nil, err
		}
		// TODO check result
		fmt.Println(res)
	} else {
		res := s.Client.SendMessage(ctx, userID, wrappedContent)
		// TODO check result
		fmt.Println(res)
	}
	meta := map[string]any{
		"reply_to_file": len(converted.Attachments) > 0,
	}
	dbMsg := &database.Message{
		ID:        makeMessageID(s.Client.Store.ACI, converted.GetTimestamp()),
		MXID:      msg.Event.ID,
		RoomID:    msg.Portal.ID,
		SenderID:  makeUserID(s.Client.Store.ACI),
		Timestamp: time.UnixMilli(int64(converted.GetTimestamp())),
		Metadata:  meta,
	}
	if msg.ReplyTo != nil {
		dbMsg.RelatesToRowID = msg.ReplyTo.RowID
	}
	return dbMsg, nil
}

func (s *SignalClient) HandleMatrixEdit(ctx context.Context, msg *bridgev2.MatrixEdit) error {
	//TODO implement me
	panic("implement me")
}

func (s *SignalClient) HandleMatrixReaction(ctx context.Context, msg *bridgev2.MatrixReaction) (emojiID networkid.EmojiID, err error) {
	//TODO implement me
	panic("implement me")
}

func (s *SignalClient) HandleMatrixReactionRemove(ctx context.Context, msg *bridgev2.MatrixReactionRemove) error {
	//TODO implement me
	panic("implement me")
}

func (s *SignalClient) HandleMatrixMessageRemove(ctx context.Context, msg *bridgev2.MatrixMessageRemove) error {
	//TODO implement me
	panic("implement me")
}

type msgconvPortalMethods struct{}

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
	if mcCtx.ReplyTo.Metadata["reply_to_file"] != false {
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
	chatID, _ := mcCtx.Client.parsePortalID(portal.ID)
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
		//Revision:       portal.Metadata["revision"].(uint32),
		Encrypted: true,
		//RelayUserID:    portal.Relay.UserMXID,
		//ExpirationTime: portal.Metadata["expiration_timer"].(uint32),
	}
}
