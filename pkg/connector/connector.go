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
	"text/template"
	"time"

	"github.com/google/uuid"
	"github.com/rs/zerolog"
	"go.mau.fi/util/dbutil"
	"go.mau.fi/util/variationselector"
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

type SignalConfig struct {
	DisplaynameTemplate string `yaml:"displayname_template"`
	UseContactAvatars   bool   `yaml:"use_contact_avatars"`
	UseOutdatedProfiles bool   `yaml:"use_outdated_profiles"`
	NumberInTopic       bool   `yaml:"number_in_topic"`
	DeviceName          string `yaml:"device_name"`

	displaynameTemplate *template.Template `yaml:"-"`
}

type DisplaynameParams struct {
	ProfileName string
	ContactName string
	Username    string
	PhoneNumber string
	UUID        string
	ACI         string
	PNI         string
	AboutEmoji  string
}

func (c *SignalConfig) FormatDisplayname(contact *types.Recipient) string {
	var nameBuf strings.Builder
	err := c.displaynameTemplate.Execute(&nameBuf, &DisplaynameParams{
		ProfileName: contact.Profile.Name,
		ContactName: contact.ContactName,
		Username:    "",
		PhoneNumber: contact.E164,
		UUID:        contact.ACI.String(),
		ACI:         contact.ACI.String(),
		PNI:         contact.PNI.String(),
		AboutEmoji:  contact.Profile.AboutEmoji,
	})
	if err != nil {
		panic(err)
	}
	return nameBuf.String()
}

type SignalConnector struct {
	MsgConv *msgconv.MessageConverter
	Store   *store.Container
	Bridge  *bridgev2.Bridge
	Config  *SignalConfig
}

func NewConnector() *SignalConnector {
	return &SignalConnector{
		Config: &SignalConfig{},
	}
}

func (s *SignalConnector) Init(bridge *bridgev2.Bridge) {
	var err error
	s.Config.displaynameTemplate, err = template.New("displayname").Parse(s.Config.DisplaynameTemplate)
	if err != nil {
		// TODO return error or do this later?
		panic(err)
	}
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

func (s *SignalConnector) LoadUserLogin(ctx context.Context, login *bridgev2.UserLogin) error {
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

func (s *SignalClient) LogoutRemote(ctx context.Context) {
	err := s.Client.StopReceiveLoops()
	if err != nil {
		zerolog.Ctx(ctx).Err(err).Msg("Failed to stop receive loops for logout")
	}
	err = s.Main.Store.DeleteDevice(context.TODO(), &s.Client.Store.DeviceData)
	if err != nil {
		zerolog.Ctx(ctx).Err(err).Msg("Failed to delete device from store")
	}
}

func (s *SignalClient) contactToUserInfo(contact *types.Recipient) *bridgev2.UserInfo {
	isBot := false
	ui := &bridgev2.UserInfo{
		IsBot: &isBot,
	}
	name := s.Main.Config.FormatDisplayname(contact)
	ui.Name = &name
	if s.Main.Config.UseContactAvatars && contact.ContactAvatar.Hash != "" {
		ui.Avatar = &bridgev2.Avatar{
			ID: networkid.AvatarID("hash:" + contact.ContactAvatar.Hash),
			Get: func(ctx context.Context) ([]byte, error) {
				if contact.ContactAvatar.Image == nil {
					return nil, fmt.Errorf("contact avatar not available")
				}
				return contact.ContactAvatar.Image, nil
			},
		}
	} else if contact.Profile.AvatarPath != "" {
		ui.Avatar = &bridgev2.Avatar{
			ID: makeAvatarPathID(contact.Profile.AvatarPath),
			Get: func(ctx context.Context) ([]byte, error) {
				return s.Client.DownloadUserAvatar(ctx, contact.Profile.AvatarPath, contact.Profile.Key)
			},
		}
	} else {
		ui.Avatar = &bridgev2.Avatar{
			ID:     "",
			Remove: true,
		}
	}
	return ui
}

func (s *SignalClient) GetUserInfo(ctx context.Context, ghost *bridgev2.Ghost) (*bridgev2.UserInfo, error) {
	userID, err := parseUserID(ghost.ID)
	if err != nil {
		return nil, err
	}
	contact, err := s.Client.ContactByACI(ctx, userID)
	if err != nil {
		return nil, err
	}
	return s.contactToUserInfo(contact), nil
}

func makeAvatarPathID(avatarPath string) networkid.AvatarID {
	if avatarPath == "" {
		return ""
	}
	return networkid.AvatarID("path:" + avatarPath)
}

func (s *SignalClient) GetChatInfo(ctx context.Context, portal *bridgev2.Portal) (*bridgev2.PortalInfo, error) {
	userID, groupID, err := s.parsePortalID(portal.ID)
	if err != nil {
		return nil, err
	}
	isSpace := false
	if groupID != "" {
		groupInfo, err := s.Client.RetrieveGroupByID(ctx, groupID, 0)
		if err != nil {
			return nil, err
		}
		isDM := false
		members := make([]networkid.UserID, len(groupInfo.Members))
		for i, member := range groupInfo.Members {
			members[i] = makeUserID(member.ACI)
		}
		return &bridgev2.PortalInfo{
			Name:  &groupInfo.Title,
			Topic: &groupInfo.Description,
			Avatar: &bridgev2.Avatar{
				ID: makeAvatarPathID(groupInfo.AvatarPath),
				Get: func(ctx context.Context) ([]byte, error) {
					return s.Client.DownloadGroupAvatar(ctx, groupInfo)
				},
				Remove: groupInfo.AvatarPath == "",
			},
			Members:      members,
			IsDirectChat: &isDM,
			IsSpace:      &isSpace,
		}, nil
	} else if userID.Type == libsignalgo.ServiceIDTypePNI {
		contact, err := s.Client.Store.RecipientStore.LoadAndUpdateRecipient(ctx, uuid.Nil, userID.UUID, nil)
		if err != nil {
			return nil, err
		}
		var topic, name string
		name = s.Main.Config.FormatDisplayname(contact)
		if s.Main.Config.NumberInTopic && contact.E164 != "" {
			topic = fmt.Sprintf("")
			// TODO set topic
		}
		isDM := true
		return &bridgev2.PortalInfo{
			Members:      []networkid.UserID{makeUserID(s.Client.Store.ACI)},
			Name:         &name,
			Topic:        &topic,
			IsDirectChat: &isDM,
			IsSpace:      &isSpace,
		}, nil
	} else {
		var topic, name string
		if s.Main.Config.NumberInTopic {
			// TODO set topic
		}
		isDM := true
		return &bridgev2.PortalInfo{
			Members:      []networkid.UserID{makeUserID(userID.UUID), makeUserID(s.Client.Store.ACI)},
			Name:         &name,
			Topic:        &topic,
			IsDirectChat: &isDM,
			IsSpace:      &isSpace,
		}, nil
	}
}

func (s *SignalClient) IsThisUser(_ context.Context, userID networkid.UserID) bool {
	return userID == makeUserID(s.Client.Store.ACI)
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

func parseUserID(userID networkid.UserID) (uuid.UUID, error) {
	return uuid.Parse(string(userID))
}

func (s *SignalClient) parsePortalID(portalID networkid.PortalID) (userID libsignalgo.ServiceID, groupID types.GroupIdentifier, err error) {
	parts := strings.Split(string(portalID), "|")
	if len(parts) == 1 {
		if len(parts[0]) == 44 {
			groupID = types.GroupIdentifier(parts[0])
		} else {
			err = fmt.Errorf("invalid portal ID: expected group ID to be 44 characters")
		}
	} else if len(parts) == 2 {
		ourACI := s.Client.Store.ACI.String()
		if parts[0] == ourACI {
			userID, err = libsignalgo.ServiceIDFromString(parts[1])
		} else if parts[1] == ourACI {
			userID, err = libsignalgo.ServiceIDFromString(parts[0])
		} else {
			err = fmt.Errorf("invalid portal ID: expected one side to be our ACI")
		}
	} else {
		err = fmt.Errorf("invalid portal ID: unexpected number of pipe-separated parts")
	}
	return
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

func parseMessageID(messageID networkid.MessageID) (sender uuid.UUID, timestamp uint64, err error) {
	parts := strings.Split(string(messageID), "|")
	if len(parts) != 2 {
		err = fmt.Errorf("invalid message ID: expected two pipe-separated parts")
		return
	}
	sender, err = uuid.Parse(parts[0])
	if err != nil {
		return
	}
	timestamp, err = strconv.ParseUint(parts[1], 10, 64)
	return
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

func (s *SignalClient) convertMessage(ctx context.Context, portal *bridgev2.Portal, intent bridgev2.MatrixAPI, data *events.ChatEvent) (*bridgev2.ConvertedMessage, error) {
	mcCtx := &msgconvContext{
		Connector: s.Main,
		Intent:    intent,
		Client:    s,
		Portal:    portal,
	}
	ctx = context.WithValue(ctx, msgconvContextKey, mcCtx)
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
		//ID:          makeMessageID(data.Info.Sender, dataMsg.GetTimestamp()),
		//EventSender: s.makeEventSender(data.Info.Sender),
		Timestamp: time.UnixMilli(int64(converted.Timestamp)),
		ReplyTo:   replyTo,
		Parts:     convertedParts,
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
				ID:           makeMessageID(evt.Info.Sender, innerEvt.GetTimestamp()),
				Sender:       s.makeEventSender(evt.Info.Sender),
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
		s.handleSignalContactList(evt)
	case *events.ACIFound:
	}
}

func (s *SignalClient) handleSignalContactList(evt *events.ContactList) {
	log := s.UserLogin.Log.With().Str("action", "handle contact list").Logger()
	ctx := log.WithContext(context.TODO())
	for _, contact := range evt.Contacts {
		if contact.ACI != uuid.Nil {
			fullContact, err := s.Client.ContactByACI(ctx, contact.ACI)
			if err != nil {
				log.Err(err).Msg("Failed to get full contact info from store")
				continue
			}
			fullContact.ContactAvatar = contact.ContactAvatar
			ghost, err := s.Main.Bridge.GetGhostByID(ctx, makeUserID(contact.ACI))
			if err != nil {
				log.Err(err).Msg("Failed to get ghost to update contact info")
				continue
			}
			ghost.UpdateInfo(ctx, s.contactToUserInfo(contact))
		}
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
	converted, err := s.Main.MsgConv.ToSignal(ctx, msg.Event, msg.Content, msg.OrigSender != nil)
	if err != nil {
		return nil, err
	}
	res, err := s.sendMessage(ctx, msg.Portal.ID, &signalpb.Content{DataMessage: converted})
	if err != nil {
		return nil, err
	}
	// TODO check result
	fmt.Println(res)
	meta := map[string]any{
		"contains_attachments": len(converted.Attachments) > 0,
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
	_, targetSentTimestamp, err := parseMessageID(msg.EditTarget.ID)
	if err != nil {
		return fmt.Errorf("failed to parse target message ID: %w", err)
	} else if msg.EditTarget.SenderID != makeUserID(s.Client.Store.ACI) {
		return fmt.Errorf("cannot edit other people's messages")
	}
	mcCtx := &msgconvContext{
		Connector: s.Main,
		Intent:    nil,
		Client:    s,
		Portal:    msg.Portal,
	}
	if msg.EditTarget.RelatesToRowID != 0 {
		var err error
		mcCtx.ReplyTo, err = s.Main.Bridge.DB.Message.GetByRowID(ctx, msg.EditTarget.RelatesToRowID)
		if err != nil {
			return fmt.Errorf("failed to get message reply target: %w", err)
		}
	}
	ctx = context.WithValue(ctx, msgconvContextKey, mcCtx)
	converted, err := s.Main.MsgConv.ToSignal(ctx, msg.Event, msg.Content, msg.OrigSender != nil)
	if err != nil {
		return err
	}
	res, err := s.sendMessage(ctx, msg.Portal.ID, &signalpb.Content{EditMessage: &signalpb.EditMessage{
		TargetSentTimestamp: proto.Uint64(targetSentTimestamp),
		DataMessage:         converted,
	}})
	if err != nil {
		return err
	}
	// TODO check result
	fmt.Println(res)
	msg.EditTarget.ID = makeMessageID(s.Client.Store.ACI, converted.GetTimestamp())
	msg.EditTarget.Metadata["contains_attachments"] = len(converted.Attachments) > 0
	return nil
}

func (s *SignalClient) sendMessage(ctx context.Context, portalID networkid.PortalID, content *signalpb.Content) (signalmeow.SendResult, error) {
	userID, groupID, err := s.parsePortalID(portalID)
	if err != nil {
		return nil, err
	}
	if groupID != "" {
		res, err := s.Client.SendGroupMessage(ctx, groupID, content)
		if err != nil {
			return nil, err
		}
		return res, nil
	} else {
		res := s.Client.SendMessage(ctx, userID, content)
		return &res, nil
	}
}

func (s *SignalClient) HandleMatrixReaction(ctx context.Context, msg *bridgev2.MatrixReaction) (reaction *database.Reaction, err error) {
	senderID := makeUserID(s.Client.Store.ACI)
	// emojiID is always empty because only one reaction is allowed per message+user
	var emojiID networkid.EmojiID
	signalEmoji := variationselector.FullyQualify(msg.Content.RelatesTo.Key)
	if existing, err := msg.GetExisting(ctx, senderID, emojiID); err != nil {
		return nil, fmt.Errorf("failed to check for duplicate reaction: %w", err)
	} else if existing != nil && existing.Metadata["emoji"] == signalEmoji {
		return nil, nil
	}
	targetAuthorACI, targetSentTimestamp, err := parseMessageID(msg.TargetMessage.ID)
	if err != nil {
		return nil, fmt.Errorf("failed to parse target message ID: %w", err)
	}
	wrappedContent := &signalpb.Content{
		DataMessage: &signalpb.DataMessage{
			Timestamp:               proto.Uint64(uint64(msg.Event.Timestamp)),
			RequiredProtocolVersion: proto.Uint32(uint32(signalpb.DataMessage_REACTIONS)),
			Reaction: &signalpb.DataMessage_Reaction{
				Emoji:               proto.String(signalEmoji),
				Remove:              proto.Bool(false),
				TargetAuthorAci:     proto.String(targetAuthorACI.String()),
				TargetSentTimestamp: proto.Uint64(targetSentTimestamp),
			},
		},
	}
	res, err := s.sendMessage(ctx, msg.Portal.ID, wrappedContent)
	if err != nil {
		return nil, err
	}
	// TODO check result
	fmt.Println(res)
	return &database.Reaction{
		RoomID:        msg.Portal.ID,
		MessageID:     msg.TargetMessage.ID,
		MessagePartID: msg.TargetMessage.PartID,
		SenderID:      senderID,
		EmojiID:       emojiID,
		MXID:          msg.Event.ID,
		Timestamp:     time.UnixMilli(msg.Event.Timestamp),
		Metadata: map[string]any{
			"emoji": signalEmoji,
		},
	}, nil
}

func (s *SignalClient) HandleMatrixReactionRemove(ctx context.Context, msg *bridgev2.MatrixReactionRemove) error {
	emoji, _ := msg.TargetReaction.Metadata["emoji"].(string)
	targetAuthorACI, targetSentTimestamp, err := parseMessageID(msg.TargetReaction.MessageID)
	if err != nil {
		return fmt.Errorf("failed to parse target message ID: %w", err)
	}
	wrappedContent := &signalpb.Content{
		DataMessage: &signalpb.DataMessage{
			Timestamp:               proto.Uint64(uint64(msg.Event.Timestamp)),
			RequiredProtocolVersion: proto.Uint32(uint32(signalpb.DataMessage_REACTIONS)),
			Reaction: &signalpb.DataMessage_Reaction{
				Emoji:               proto.String(emoji),
				Remove:              proto.Bool(true),
				TargetAuthorAci:     proto.String(targetAuthorACI.String()),
				TargetSentTimestamp: proto.Uint64(targetSentTimestamp),
			},
		},
	}
	res, err := s.sendMessage(ctx, msg.Portal.ID, wrappedContent)
	if err != nil {
		return err
	}
	// TODO check result
	fmt.Println(res)
	return nil
}

func (s *SignalClient) HandleMatrixMessageRemove(ctx context.Context, msg *bridgev2.MatrixMessageRemove) error {
	_, targetSentTimestamp, err := parseMessageID(msg.TargetMessage.ID)
	if err != nil {
		return fmt.Errorf("failed to parse target message ID: %w", err)
	} else if msg.TargetMessage.SenderID != makeUserID(s.Client.Store.ACI) {
		return fmt.Errorf("cannot delete other people's messages")
	}
	wrappedContent := &signalpb.Content{
		DataMessage: &signalpb.DataMessage{
			Timestamp: proto.Uint64(uint64(msg.Event.Timestamp)),
			Delete: &signalpb.DataMessage_Delete{
				TargetSentTimestamp: proto.Uint64(targetSentTimestamp),
			},
		},
	}
	res, err := s.sendMessage(ctx, msg.Portal.ID, wrappedContent)
	if err != nil {
		return err
	}
	// TODO check result
	fmt.Println(res)
	return nil
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
	if mcCtx.ReplyTo.Metadata["contains_attachments"] != false {
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
	userID, groupID, _ := mcCtx.Client.parsePortalID(portal.ID)
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
		//Revision:       portal.Metadata["revision"].(uint32),
		Encrypted: true,
		//RelayUserID:    portal.Relay.UserMXID,
		//ExpirationTime: portal.Metadata["expiration_timer"].(uint32),
	}
}
