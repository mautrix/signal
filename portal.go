package main

import (
	"fmt"
	"reflect"
	"sync"
	"time"

	log "maunium.net/go/maulogger/v2"

	"maunium.net/go/mautrix"
	"maunium.net/go/mautrix/appservice"
	"maunium.net/go/mautrix/bridge"
	"maunium.net/go/mautrix/bridge/bridgeconfig"
	"maunium.net/go/mautrix/event"
	"maunium.net/go/mautrix/id"
	"maunium.net/go/mautrix/util"

	"go.mau.fi/mautrix-signal/database"
	"go.mau.fi/mautrix-signal/pkg/signalmeow"
)

type portalSignalMessage struct {
	msg  string
	user *User
}

type portalMatrixMessage struct {
	evt  *event.Event
	user *User
}

type Portal struct {
	*database.Portal

	bridge *SignalBridge
	log    log.Logger

	roomCreateLock sync.Mutex
	encryptLock    sync.Mutex

	signalMessages chan portalSignalMessage
	matrixMessages chan portalMatrixMessage

	recentMessages *util.RingBuffer[string, *signalmeow.Message]

	currentlyTyping     []id.UserID
	currentlyTypingLock sync.Mutex
}

const recentMessageBufferSize = 32

func init() {
	event.TypeMap[event.StateBridge] = reflect.TypeOf(CustomBridgeInfoContent{})
	event.TypeMap[event.StateHalfShotBridge] = reflect.TypeOf(CustomBridgeInfoContent{})
}

//** Interfaces that Portal implements **

var _ bridge.Portal = (*Portal)(nil)

//var _ bridge.ReadReceiptHandlingPortal = (*Portal)(nil)
//var _ bridge.MembershipHandlingPortal = (*Portal)(nil)
//var _ bridge.TypingPortal = (*Portal)(nil)
//var _ bridge.MetaHandlingPortal = (*Portal)(nil)
//var _ bridge.DisappearingPortal = (*Portal)(nil)

// ** bridge.Portal Interface **

func (portal *Portal) IsEncrypted() bool {
	return portal.Encrypted
}

func (portal *Portal) MarkEncrypted() {
	portal.Encrypted = true
	portal.Update()
}

func (portal *Portal) ReceiveMatrixEvent(user bridge.User, evt *event.Event) {
	if user.GetPermissionLevel() >= bridgeconfig.PermissionLevelUser {
		portal.matrixMessages <- portalMatrixMessage{user: user.(*User), evt: evt}
	}
}

func (portal *Portal) IsPrivateChat() bool {
	// Assuming that if the receiver is set, it's a private chat
	return portal.Receiver != ""
}

func (portal *Portal) MainIntent() *appservice.IntentAPI {
	if portal.IsPrivateChat() {
		portal.log.Debugln("MainIntent: Private chat, returning custom intent")
		return portal.bridge.GetPuppetBySignalID(portal.ChatID).DefaultIntent()
	}

	return portal.bridge.Bot
}

type CustomBridgeInfoContent struct {
	event.BridgeEventContent
	RoomType string `json:"com.beeper.room_type,omitempty"`
}

func (portal *Portal) getBridgeInfo() (string, CustomBridgeInfoContent) {
	bridgeInfo := event.BridgeEventContent{
		BridgeBot: portal.bridge.Bot.UserID,
		Creator:   portal.MainIntent().UserID,
		Protocol: event.BridgeInfoSection{
			ID:          "signal",
			DisplayName: "Signal",
			AvatarURL:   portal.bridge.Config.AppService.Bot.ParsedAvatar.CUString(),
			ExternalURL: "https://signal.org/",
		},
		Channel: event.BridgeInfoSection{
			ID:          portal.Key().ChatID,
			DisplayName: portal.Name,
		},
	}
	var bridgeInfoStateKey string
	bridgeInfoStateKey = fmt.Sprintf("fi.mau.signal://signal/%s", portal.Key().ChatID)
	bridgeInfo.Channel.ExternalURL = fmt.Sprintf("https://signal.me/#p/%s", portal.Key().ChatID)
	var roomType string
	if portal.IsPrivateChat() {
		roomType = "dm"
	}
	return bridgeInfoStateKey, CustomBridgeInfoContent{bridgeInfo, roomType}
}

func (portal *Portal) UpdateBridgeInfo() {
	if len(portal.MXID) == 0 {
		portal.log.Debugln("Not updating bridge info: no Matrix room created")
		return
	}
	portal.log.Debugln("Updating bridge info...")
	stateKey, content := portal.getBridgeInfo()
	_, err := portal.MainIntent().SendStateEvent(portal.MXID, event.StateBridge, stateKey, content)
	if err != nil {
		portal.log.Warnln("Failed to update m.bridge:", err)
	}
	// TODO remove this once https://github.com/matrix-org/matrix-doc/pull/2346 is in spec
	_, err = portal.MainIntent().SendStateEvent(portal.MXID, event.StateHalfShotBridge, stateKey, content)
	if err != nil {
		portal.log.Warnln("Failed to update uk.half-shot.bridge:", err)
	}
}

// ** bridge.ChildOverride methods (for SignalBridge in main.go) **

func (br *SignalBridge) GetAllIPortals() (iportals []bridge.Portal) {
	portals := br.getAllPortals()
	iportals = make([]bridge.Portal, len(portals))
	for i, portal := range portals {
		iportals[i] = portal
	}
	return iportals
}

func (br *SignalBridge) getAllPortals() []*Portal {
	return br.dbPortalsToPortals(br.DB.Portal.GetAll())
}

func (br *SignalBridge) dbPortalsToPortals(dbPortals []*database.Portal) []*Portal {
	br.portalsLock.Lock()
	defer br.portalsLock.Unlock()

	output := make([]*Portal, len(dbPortals))
	for index, dbPortal := range dbPortals {
		if dbPortal == nil {
			continue
		}

		portal, ok := br.portalsByID[dbPortal.Key()]
		if !ok {
			portal = br.loadPortal(dbPortal, nil)
		}

		output[index] = portal
	}

	return output
}

// ** Portal Creation and Message Handling **

func (br *SignalBridge) NewPortal(dbPortal *database.Portal) *Portal {
	portal := &Portal{
		Portal: dbPortal,
		bridge: br,
		log:    br.Log.Sub(fmt.Sprintf("Portal/%s", dbPortal.Key())),

		signalMessages: make(chan portalSignalMessage, br.Config.Bridge.PortalMessageBuffer),
		matrixMessages: make(chan portalMatrixMessage, br.Config.Bridge.PortalMessageBuffer),

		//recentMessages: util.NewRingBuffer[string, *discordgo.Message](recentMessageBufferSize),
		//commands: make(map[string]*discordgo.ApplicationCommand),
	}

	go portal.messageLoop()

	return portal
}

func (portal *Portal) messageLoop() {
	for {
		portal.log.Debugln("Waiting for message...")
		select {
		case msg := <-portal.matrixMessages:
			portal.log.Debugln("Got message from matrix")
			portal.handleMatrixMessages(msg)
		case msg := <-portal.signalMessages:
			portal.log.Debugln("Got message from signal")
			portal.handleSignalMessages(msg)
		}
	}
}

func (portal *Portal) handleMatrixMessages(msg portalMatrixMessage) {
	switch msg.evt.Type {
	case event.EventMessage, event.EventSticker:
		//portal.handleMatrixMessage(msg.user, msg.evt)
	case event.EventRedaction:
		//portal.handleMatrixRedaction(msg.user, msg.evt)
	case event.EventReaction:
		//portal.handleMatrixReaction(msg.user, msg.evt)
	default:
		portal.log.Debugln("unknown event type", msg.evt.Type)
	}
}

func (portal *Portal) handleSignalMessages(msg portalSignalMessage) {
	if portal.MXID == "" {
		portal.log.Debugln("Creating Matrix room from incoming message")
		if err := portal.CreateMatrixRoom(msg.user, nil); err != nil {
			portal.log.Errorln("Failed to create portal room:", err)
			return
		} else {
			portal.log.Infoln("Created Matrix room:", portal.MXID)
		}
	}

	intent := portal.getMessageIntent(msg.user)
	if intent == nil {
		portal.log.Errorln("Failed to get message intent")
		return
	}

	timestamp := time.Now() //TODO get this from signal message
	content := &event.MessageEventContent{
		Body:    msg.msg,
		MsgType: event.MsgText,
	}
	resp, err := portal.sendMessage(
		intent,
		event.EventMessage,
		content,
		nil,
		timestamp.UnixMilli(), // TODO: message timestamp from Signal
	)
	if err != nil {
		portal.log.Errorln("Failed to send message:", err)
		return
	}
	eventID := resp.EventID
	if eventID == "" {
		portal.log.Errorln("Failed to send message: empty event ID")
		return
	}
	dbMessage := portal.bridge.DB.Message.New()
	dbMessage.MXID = eventID
	dbMessage.MXRoom = portal.MXID
	//dbMessage.Sender = "TODO" //TODO
	dbMessage.Timestamp = timestamp
	dbMessage.SignalChatID = portal.ChatID
	dbMessage.SignalReceiver = portal.Receiver
	dbMessage.Insert(nil)

	// TODO: send receipt
	// TODO: expire if it's an expiring message

	//switch convertedMsg := msg.msg.(type) {
	//case *discordgo.MessageCreate:
	//		portal.handleDiscordMessageCreate(msg.user, convertedMsg.Message, msg.thread)
	//case *discordgo.MessageUpdate:
	//		portal.handleDiscordMessageUpdate(msg.user, convertedMsg.Message)
	//case *discordgo.MessageDelete:
	//		portal.handleDiscordMessageDelete(msg.user, convertedMsg.Message)
	//case *discordgo.MessageReactionAdd:
	//		portal.handleDiscordReaction(msg.user, convertedMsg.MessageReaction, true, msg.thread, convertedMsg.Member)
	//case *discordgo.MessageReactionRemove:
	//		portal.handleDiscordReaction(msg.user, convertedMsg.MessageReaction, false, msg.thread, nil)
	//default:
	//		portal.log.Warnln("unknown message type")
	//}
}

func (portal *Portal) sendMainIntentMessage(content *event.MessageEventContent) (*mautrix.RespSendEvent, error) {
	return portal.sendMessage(portal.MainIntent(), event.EventMessage, content, nil, 0)
}

func (portal *Portal) encrypt(intent *appservice.IntentAPI, content *event.Content, eventType event.Type) (event.Type, error) {
	if !portal.Encrypted || portal.bridge.Crypto == nil {
		return eventType, nil
	}
	intent.AddDoublePuppetValue(content)
	// TODO maybe the locking should be inside mautrix-go?
	portal.encryptLock.Lock()
	defer portal.encryptLock.Unlock()
	err := portal.bridge.Crypto.Encrypt(portal.MXID, eventType, content)
	if err != nil {
		return eventType, fmt.Errorf("failed to encrypt event: %w", err)
	}
	return event.EventEncrypted, nil
}

func (portal *Portal) sendMessage(intent *appservice.IntentAPI, eventType event.Type, content *event.MessageEventContent, extraContent map[string]interface{}, timestamp int64) (*mautrix.RespSendEvent, error) {
	wrappedContent := event.Content{Parsed: content, Raw: extraContent}
	var err error
	eventType, err = portal.encrypt(intent, &wrappedContent, eventType)
	if err != nil {
		return nil, err
	}

	_, _ = intent.UserTyping(portal.MXID, false, 0)
	if timestamp == 0 {
		return intent.SendMessageEvent(portal.MXID, eventType, &wrappedContent)
	} else {
		return intent.SendMassagedMessageEvent(portal.MXID, eventType, &wrappedContent, timestamp)
	}
}

func (portal *Portal) getMessagePuppet(user *User) (puppet *Puppet) {
	//if info.IsFromMe {
	//return portal.bridge.GetPuppetBySignalID(user.SignalID)
	if portal.IsPrivateChat() {
		puppet = portal.bridge.GetPuppetByNumber(portal.Key().Receiver)
	} // else if !info.Sender.IsEmpty() {
	//	puppet = portal.bridge.GetPuppetBySignalID(info.Sender)
	//}
	if puppet == nil {
		//	portal.log.Warnfln("Message %+v doesn't seem to have a valid sender (%s): puppet is nil", *info, info.Sender)
		return nil
	}
	//user.EnqueuePortalResync(portal)
	//puppet.SyncContact(user, true, true, "handling message")
	return puppet
}

func (portal *Portal) getMessageIntent(user *User) *appservice.IntentAPI {
	puppet := portal.getMessagePuppet(user)
	if puppet == nil {
		return nil
	}
	intent := puppet.IntentFor(portal)
	if !intent.IsCustomPuppet && portal.IsPrivateChat() { //&& info.Sender.User == portal.Key.Receiver.User && portal.Key.Receiver != portal.Key.JID {
		portal.log.Debugfln("Not handling: user doesn't have double puppeting enabled")
		return nil
	}
	return intent
}

func (portal *Portal) getEncryptionEventContent() (evt *event.EncryptionEventContent) {
	evt = &event.EncryptionEventContent{Algorithm: id.AlgorithmMegolmV1}
	if rot := portal.bridge.Config.Bridge.Encryption.Rotation; rot.EnableCustom {
		evt.RotationPeriodMillis = rot.Milliseconds
		evt.RotationPeriodMessages = rot.Messages
	}
	return
}

func (portal *Portal) shouldSetDMRoomMetadata() bool {
	return !portal.IsPrivateChat() || portal.bridge.Config.Bridge.PrivateChatPortalMeta
}

func (portal *Portal) ensureUserInvited(user *User) bool {
	return user.ensureInvited(portal.MainIntent(), portal.MXID, portal.IsPrivateChat())
}

func (portal *Portal) CreateMatrixRoom(user *User, meta *any) error {
	portal.roomCreateLock.Lock()
	defer portal.roomCreateLock.Unlock()
	if portal.MXID != "" {
		portal.log.Debugln("Room already exists")
		return nil
	}
	portal.log.Infoln("Creating Matrix room for meta, user WAT")

	//meta = portal.UpdateInfo(user, meta)
	//if meta == nil {
	//	return fmt.Errorf("didn't find metadata")
	//}

	intent := portal.MainIntent()
	portal.log.Infof("Intent: %+v", intent)

	portal.log.Infoln("0")

	if err := intent.EnsureRegistered(); err != nil {
		portal.log.Errorln("Failed to ensure registered:", err)
		return err
	}

	portal.log.Infoln("1")

	bridgeInfoStateKey, bridgeInfo := portal.getBridgeInfo()
	initialState := []*event.Event{{
		Type:     event.StateBridge,
		Content:  event.Content{Parsed: bridgeInfo},
		StateKey: &bridgeInfoStateKey,
	}, {
		// TODO remove this once https://github.com/matrix-org/matrix-doc/pull/2346 is in spec
		Type:     event.StateHalfShotBridge,
		Content:  event.Content{Parsed: bridgeInfo},
		StateKey: &bridgeInfoStateKey,
	}}

	portal.log.Infoln("2")

	if !portal.AvatarURL.IsEmpty() {
		initialState = append(initialState, &event.Event{
			Type: event.StateRoomAvatar,
			Content: event.Content{Parsed: &event.RoomAvatarEventContent{
				URL: portal.AvatarURL,
			}},
		})
	}

	portal.log.Infoln("3")

	creationContent := make(map[string]interface{})
	if !portal.bridge.Config.Bridge.FederateRooms {
		creationContent["m.federate"] = false
	}

	var invite []id.UserID

	if portal.bridge.Config.Bridge.Encryption.Default {
		initialState = append(initialState, &event.Event{
			Type: event.StateEncryption,
			Content: event.Content{
				Parsed: portal.getEncryptionEventContent(),
			},
		})
		portal.Encrypted = true

		if portal.IsPrivateChat() {
			invite = append(invite, portal.bridge.Bot.UserID)
		}
	}

	portal.log.Infoln("4")

	resp, err := intent.CreateRoom(&mautrix.ReqCreateRoom{
		Visibility:      "private",
		Name:            portal.Name,
		Topic:           portal.Topic,
		Invite:          invite,
		Preset:          "private_chat",
		IsDirect:        portal.IsPrivateChat(),
		InitialState:    initialState,
		CreationContent: creationContent,
	})
	if err != nil {
		portal.log.Warnln("Failed to create room:", err)
		return err
	}

	portal.log.Infoln("5")

	portal.NameSet = true
	//portal.TopicSet = true
	portal.AvatarSet = !portal.AvatarURL.IsEmpty()
	portal.MXID = resp.RoomID
	portal.bridge.portalsLock.Lock()
	portal.bridge.portalsByMXID[portal.MXID] = portal
	portal.bridge.portalsLock.Unlock()
	portal.Update()
	portal.log.Infoln("Matrix room created:", portal.MXID)

	portal.log.Infoln("6")

	if portal.Encrypted && portal.IsPrivateChat() {
		err = portal.bridge.Bot.EnsureJoined(portal.MXID, appservice.EnsureJoinedParams{BotOverride: portal.MainIntent().Client})
		if err != nil {
			portal.log.Errorfln("Failed to ensure bridge bot is joined to private chat portal: %v", err)
		}
	}

	portal.log.Infoln("7")

	user.ensureInvited(portal.MainIntent(), portal.MXID, portal.IsPrivateChat())
	user.syncChatDoublePuppetDetails(portal, true)

	portal.log.Infoln("8")

	//portal.syncParticipants(user, channel.Recipients)

	if portal.IsPrivateChat() {
		portal.log.Debugln("Portal is private chat, updating direct chats")
		puppet := user.bridge.GetPuppetBySignalID(portal.Receiver)

		chats := map[id.UserID][]id.RoomID{puppet.MXID: {portal.MXID}}
		user.UpdateDirectChats(chats)
	}

	portal.log.Infoln("9")

	_, err = portal.MainIntent().SendMessageEvent(portal.MXID, portalCreationDummyEvent, struct{}{})
	if err != nil {
		portal.log.Errorln("Failed to send dummy event to mark portal creation:", err)
	} else {
		portal.log.Debugln("Sent dummy event to mark portal creation")
		portal.Update()
	}

	portal.log.Infoln("10")

	return nil
}

func (portal *Portal) UpdateInfo(user *User, meta *any) *any {
	return nil
}

// ** Portal loading and fetching **
var (
	portalCreationDummyEvent = event.Type{Type: "fi.mau.dummy.portal_created", Class: event.MessageEventType}
)

func (br *SignalBridge) loadPortal(dbPortal *database.Portal, key *database.PortalKey) *Portal {
	if dbPortal == nil {
		if key == nil {
			br.Log.Errorln("loadPortal called with nil dbPortal and nil key")
			return nil
		}

		dbPortal = br.DB.Portal.New()
		dbPortal.SetPortalKey(*key)
		dbPortal.Insert()
	}

	portal := br.NewPortal(dbPortal)

	br.portalsByID[portal.Key()] = portal
	if portal.MXID != "" {
		br.portalsByMXID[portal.MXID] = portal
	}

	return portal
}

func (br *SignalBridge) GetPortalByMXID(mxid id.RoomID) *Portal {
	br.portalsLock.Lock()
	defer br.portalsLock.Unlock()

	portal, ok := br.portalsByMXID[mxid]
	if !ok {
		return br.loadPortal(br.DB.Portal.GetByMXID(mxid), nil)
	}

	return portal
}

func (br *SignalBridge) GetPortalByChatID(key database.PortalKey) *Portal {
	br.portalsLock.Lock()
	defer br.portalsLock.Unlock()
	portal, ok := br.portalsByID[key]
	if !ok {
		return br.loadPortal(br.DB.Portal.GetByChatID(key), &key)
	}
	return portal
}
