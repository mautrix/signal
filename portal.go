package main

import (
	"errors"
	"fmt"
	"reflect"
	"sync"
	"time"

	log "maunium.net/go/maulogger/v2"

	"maunium.net/go/mautrix"
	"maunium.net/go/mautrix/appservice"
	"maunium.net/go/mautrix/bridge"
	"maunium.net/go/mautrix/bridge/bridgeconfig"
	"maunium.net/go/mautrix/bridge/status"
	"maunium.net/go/mautrix/crypto/attachment"
	"maunium.net/go/mautrix/event"
	"maunium.net/go/mautrix/id"
	"maunium.net/go/mautrix/util"

	"go.mau.fi/mautrix-signal/database"
	"go.mau.fi/mautrix-signal/pkg/signalmeow"
)

type portalSignalMessage struct {
	msg  interface{}
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
	matrixMessages  chan portalMatrixMessage

	recentMessages *util.RingBuffer[string, *signalmeow.Message]

	currentlyTyping     []id.UserID
	currentlyTypingLock sync.Mutex
}

const recentMessageBufferSize = 32

var _ bridge.Portal = (*Portal)(nil)
//var _ bridge.ReadReceiptHandlingPortal = (*Portal)(nil)
//var _ bridge.MembershipHandlingPortal = (*Portal)(nil)
//var _ bridge.TypingPortal = (*Portal)(nil)

//var _ bridge.MetaHandlingPortal = (*Portal)(nil)
//var _ bridge.DisappearingPortal = (*Portal)(nil)

func (portal *Portal) IsEncrypted() bool {
	return portal.Encrypted
}

func (portal *Portal) MarkEncrypted() {
	portal.Encrypted = true
	portal.Update()
}

func (portal *Portal) ReceiveMatrixEvent(user bridge.User, evt *event.Event) {
	if user.GetPermissionLevel() >= bridgeconfig.PermissionLevelUser || portal.RelayWebhookID != "" {
		portal.matrixMessages <- portalMatrixMessage{user: user.(*User), evt: evt}
	}
}

func (portal *Portal) IsPrivateChat() bool {
	return false
}

func (portal *Portal) MainIntent() *appservice.IntentAPI {
	if portal.IsPrivateChat() && portal.OtherUserID != "" {
		return portal.bridge.GetPuppetByID(portal.OtherUserID).DefaultIntent()
	}

	return portal.bridge.Bot
}

type CustomBridgeInfoContent struct {
	event.BridgeEventContent
	RoomType string `json:"com.beeper.room_type,omitempty"`
}

func init() {
	event.TypeMap[event.StateBridge] = reflect.TypeOf(CustomBridgeInfoContent{})
	event.TypeMap[event.StateHalfShotBridge] = reflect.TypeOf(CustomBridgeInfoContent{})
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
			ID:          portal.Key.ChannelID,
			DisplayName: portal.Name,
		},
	}
	var bridgeInfoStateKey string
  bridgeInfoStateKey = fmt.Sprintf("fi.mau.signal://signal/%s", portal.Key.ChannelID)
  bridgeInfo.Channel.ExternalURL = fmt.Sprintf("https://signal.me/#p/%s", portal.Key.ChannelID)
	var roomType string
	if true { //portal.Type == discordgo.ChannelTypeDM || portal.Type == discordgo.ChannelTypeGroupDM {
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

