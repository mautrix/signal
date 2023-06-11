package main

import (
	"fmt"
	"reflect"
	"sync"

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
	msg  any
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
		log:    br.Log.Sub(fmt.Sprintf("Portal/%s", dbPortal.Key)),

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
		select {
		case msg := <-portal.matrixMessages:
			portal.handleMatrixMessages(msg)
		case msg := <-portal.signalMessages:
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
		}
	}

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
		return nil
	}
	portal.log.Infoln("Creating Matrix room for meta")

	//meta = portal.UpdateInfo(user, meta)
	//if meta == nil {
	//	return fmt.Errorf("didn't find metadata")
	//}

	intent := portal.MainIntent()
	if err := intent.EnsureRegistered(); err != nil {
		return err
	}

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

	if !portal.AvatarURL.IsEmpty() {
		initialState = append(initialState, &event.Event{
			Type: event.StateRoomAvatar,
			Content: event.Content{Parsed: &event.RoomAvatarEventContent{
				URL: portal.AvatarURL,
			}},
		})
	}

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

	portal.NameSet = true
	//portal.TopicSet = true
	portal.AvatarSet = !portal.AvatarURL.IsEmpty()
	portal.MXID = resp.RoomID
	portal.bridge.portalsLock.Lock()
	portal.bridge.portalsByMXID[portal.MXID] = portal
	portal.bridge.portalsLock.Unlock()
	portal.Update()
	portal.log.Infoln("Matrix room created:", portal.MXID)

	if portal.Encrypted && portal.IsPrivateChat() {
		err = portal.bridge.Bot.EnsureJoined(portal.MXID, appservice.EnsureJoinedParams{BotOverride: portal.MainIntent().Client})
		if err != nil {
			portal.log.Errorfln("Failed to ensure bridge bot is joined to private chat portal: %v", err)
		}
	}

	//user.ensureInvited(portal.MainIntent(), portal.MXID, portal.IsPrivateChat())
	//user.syncChatDoublePuppetDetails(portal, true)

	//portal.syncParticipants(user, channel.Recipients)

	if portal.IsPrivateChat() {
		puppet := user.bridge.GetPuppetBySignalID(portal.Receiver)

		chats := map[id.UserID][]id.RoomID{puppet.MXID: {portal.MXID}}
		user.UpdateDirectChats(chats)
	}

	_, err = portal.MainIntent().SendMessageEvent(portal.MXID, portalCreationDummyEvent, struct{}{})
	if err != nil {
		portal.log.Errorln("Failed to send dummy event to mark portal creation:", err)
	} else {
		portal.Update()
	}

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
