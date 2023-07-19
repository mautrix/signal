package signalmeow

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"strconv"
	"strings"
	"time"

	"go.mau.fi/mautrix-signal/pkg/libsignalgo"
	signalpb "go.mau.fi/mautrix-signal/pkg/signalmeow/protobuf"
	"go.mau.fi/mautrix-signal/pkg/signalmeow/web"
	"google.golang.org/protobuf/proto"
)

// Sending

func senderCertificate(d *Device) (*libsignalgo.SenderCertificate, error) {
	if d.Connection.SenderCertificate != nil {
		// TODO: check for expired certificate
		return d.Connection.SenderCertificate, nil
	}

	username, password := d.Data.BasicAuthCreds()
	opts := &web.HTTPReqOpt{Username: &username, Password: &password}
	resp, err := web.SendHTTPRequest("GET", "/v1/certificate/delivery", opts)
	defer resp.Body.Close()
	if err != nil {
		return nil, err
	}
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return nil, fmt.Errorf("HTTP error: %v", resp.StatusCode)
	}

	type response struct {
		Base64Certificate string `json:"certificate"`
	}
	var r response
	err = json.NewDecoder(resp.Body).Decode(&r)
	if err != nil {
		return nil, err
	}
	rawCertificate, err := base64.StdEncoding.DecodeString(r.Base64Certificate)
	if err != nil {
		return nil, err
	}
	cert, err := libsignalgo.DeserializeSenderCertificate([]byte(rawCertificate))
	d.Connection.SenderCertificate = cert
	return cert, err
}

type MyMessage struct {
	Type                      int    `json:"type"`
	DestinationDeviceID       int    `json:"destinationDeviceId"`
	DestinationRegistrationID int    `json:"destinationRegistrationId"`
	Content                   string `json:"content"`
}

type MyMessages struct {
	Timestamp int64       `json:"timestamp"`
	Online    bool        `json:"online"`
	Urgent    bool        `json:"urgent"`
	Messages  []MyMessage `json:"messages"`
}

func padBlock(block *[]byte, pos int) error {
	if pos >= len(*block) {
		return errors.New("Padding error: position exceeds block length")
	}

	(*block)[pos] = 0x80
	for i := pos + 1; i < len(*block); i++ {
		(*block)[i] = 0
	}

	return nil
}

func addPadding(version uint32, contents []byte) ([]byte, error) {
	if version < 2 {
		return nil, fmt.Errorf("Unknown version %d", version)
	} else if version == 2 {
		return contents, nil
	} else {
		messageLength := len(contents)
		messageLengthWithTerminator := len(contents) + 1
		messagePartCount := messageLengthWithTerminator / 160
		if messageLengthWithTerminator%160 != 0 {
			messagePartCount++
		}

		messageLengthWithPadding := messagePartCount * 160

		buffer := make([]byte, messageLengthWithPadding)
		copy(buffer[:messageLength], contents)

		err := padBlock(&buffer, messageLength)
		if err != nil {
			return nil, errors.New(fmt.Sprintf("Invalid message padding: %v", err))
		}
		return buffer, nil
	}
}

func checkForErrorWithSessions(err error, addresses []*libsignalgo.Address, sessionRecords []*libsignalgo.SessionRecord) error {
	if err != nil {
		return err
	}
	if addresses == nil || sessionRecords == nil {
		return fmt.Errorf("Addresses or session records are nil")
	}
	if len(addresses) != len(sessionRecords) {
		return fmt.Errorf("Mismatched number of addresses (%d) and session records (%d)", len(addresses), len(sessionRecords))
	}
	if len(addresses) == 0 || len(sessionRecords) == 0 {
		return fmt.Errorf("No addresses or session records")
	}
	return nil
}

func howManyOtherDevicesDoWeHave(ctx context.Context, d *Device) int {
	addresses, _, err := d.SessionStoreExtras.AllSessionsForUUID(d.Data.AciUuid, ctx)
	if err != nil {
		return 0
	}
	// Filter out our deviceID
	otherDevices := 0
	for _, address := range addresses {
		deviceID, err := address.DeviceID()
		if err != nil {
			log.Printf("Error getting deviceID from address: %v", err)
			continue
		}
		if deviceID != uint(d.Data.DeviceId) {
			otherDevices++
		}
	}
	return otherDevices
}

func buildAuthedMessagesToSend(d *Device, recipientUuid string, content *signalpb.Content, ctx context.Context) ([]MyMessage, error) {
	messages := []MyMessage{}

	addresses, sessionRecords, err := d.SessionStoreExtras.AllSessionsForUUID(recipientUuid, ctx)
	err = checkForErrorWithSessions(err, addresses, sessionRecords)
	if err != nil {
		return nil, err
	}

	for i, recipientAddress := range addresses {
		recipientDeviceID, err := recipientAddress.DeviceID()
		if err != nil {
			return nil, err
		}

		// Marshal and encrypt the message
		serializedMessage, err := proto.Marshal(content)
		if err != nil {
			return nil, err
		}
		session := sessionRecords[i]
		paddedMessage, err := addPadding(3, []byte(serializedMessage)) // TODO: figure out how to get actual version
		cipherTextMessage, err := libsignalgo.Encrypt(
			[]byte(paddedMessage),
			recipientAddress,
			d.SessionStore,
			d.IdentityStore,
			libsignalgo.NewCallbackContext(ctx),
		)
		encryptedPayload, err := cipherTextMessage.Serialize()
		if err != nil {
			return nil, err
		}

		// OMG Signal are you serious why can't your magic numbers just align
		cipherMessageType, _ := cipherTextMessage.MessageType()
		var envelopeType = 0
		if cipherMessageType == libsignalgo.CiphertextMessageTypePreKey { // 3 -> 3
			envelopeType = int(signalpb.Envelope_PREKEY_BUNDLE)
		} else if cipherMessageType == libsignalgo.CiphertextMessageTypeWhisper { // 2 -> 1
			envelopeType = int(signalpb.Envelope_CIPHERTEXT)
		} else {
			return nil, fmt.Errorf("Unknown message type: %v", cipherMessageType)
		}
		log.Printf("Sending message type %v", envelopeType)

		destinationRegistrationID, err := session.GetRemoteRegistrationID()
		if err != nil {
			return nil, err
		}

		// Build payload to send over websocket
		outgoingMessage := MyMessage{
			Type:                      envelopeType,
			DestinationDeviceID:       int(recipientDeviceID),
			DestinationRegistrationID: int(destinationRegistrationID),
			Content:                   base64.StdEncoding.EncodeToString(encryptedPayload),
		}
		messages = append(messages, outgoingMessage)
	}

	return messages, nil
}

func buildSSMessagesToSend(d *Device, recipientUuid string, content *signalpb.Content, ctx context.Context) ([]MyMessage, error) {
	messages := []MyMessage{}

	// Grab our sender cert
	cert, err := senderCertificate(d)
	if err != nil {
		return nil, err
	}

	addresses, sessionRecords, err := d.SessionStoreExtras.AllSessionsForUUID(recipientUuid, ctx)
	err = checkForErrorWithSessions(err, addresses, sessionRecords)
	if err != nil {
		return nil, err
	}

	for i, recipientAddress := range addresses {
		recipientDeviceID, err := recipientAddress.DeviceID()
		if err != nil {
			return nil, err
		}

		// Build message payload
		serializedMessage, err := proto.Marshal(content)
		if err != nil {
			return nil, err
		}
		paddedMessage, err := addPadding(3, []byte(serializedMessage)) // TODO: figure out how to get actual version
		encryptedPayload, err := libsignalgo.SealedSenderEncryptPlaintext(
			[]byte(paddedMessage),
			recipientAddress,
			cert,
			d.SessionStore,
			d.IdentityStore,
			libsignalgo.NewCallbackContext(ctx),
		)
		sessionRecord := sessionRecords[i]
		destinationRegistrationID, err := sessionRecord.GetRemoteRegistrationID()
		if err != nil {
			return nil, err
		}
		outgoingMessage := MyMessage{
			Type:                      int(signalpb.Envelope_UNIDENTIFIED_SENDER),
			DestinationDeviceID:       int(recipientDeviceID),
			DestinationRegistrationID: int(destinationRegistrationID),
			Content:                   base64.StdEncoding.EncodeToString(encryptedPayload),
		}
		messages = append(messages, outgoingMessage)
	}

	return messages, nil
}

type GroupMessageSendResult struct {
	SuccessfullySentTo []GroupMember
	FailedToSendTo     []GroupMember
}

func dataMessageFromText(text string, timestamp uint64) *signalpb.DataMessage {
	return &signalpb.DataMessage{
		Body:      proto.String(text),
		Timestamp: &timestamp,
	}
}
func contentFromDataMessage(dataMessage *signalpb.DataMessage) *signalpb.Content {
	return &signalpb.Content{
		DataMessage: dataMessage,
	}
}
func syncMessageFromDataMessage(dataMessage *signalpb.DataMessage, recipient *string) *signalpb.Content {
	return &signalpb.Content{
		SyncMessage: &signalpb.SyncMessage{
			Sent: &signalpb.SyncMessage_Sent{
				Message:         dataMessage,
				DestinationUuid: recipient,
				Timestamp:       dataMessage.Timestamp,
			},
		},
	}
}

func SendGroupMessage(ctx context.Context, device *Device, groupID GroupID, text string) (*GroupMessageSendResult, error) {
	group, err := RetrieveGroupById(ctx, device, groupID)
	if err != nil {
		return nil, err
	}

	// Assemble the content to send
	messageTimestamp := currentMessageTimestamp()
	dataMessage := dataMessageFromText(text, messageTimestamp)
	dataMessage.GroupV2 = groupMetadataForDataMessage(*group)
	content := &signalpb.Content{
		DataMessage: dataMessage,
	}

	// Send to each member of the group
	result := &GroupMessageSendResult{
		SuccessfullySentTo: []GroupMember{},
		FailedToSendTo:     []GroupMember{},
	}
	for _, member := range group.Members {
		if member.UserId == device.Data.AciUuid {
			// No need to send to ourselves if we don't have any other devices
			if howManyOtherDevicesDoWeHave(ctx, device) > 0 {
				syncContent := syncMessageFromDataMessage(dataMessage, nil)
				err := sendContent(ctx, device, member.UserId, messageTimestamp, syncContent, 0)
				if err != nil {
					log.Printf("Failed to send sync message to myself (%v): %v", member.UserId, err)
				}
			}
			continue
		}
		err := sendContent(ctx, device, member.UserId, messageTimestamp, content, 0)
		if err != nil {
			result.FailedToSendTo = append(result.FailedToSendTo, *member)
			log.Printf("Failed to send to %v: %v", member.UserId, err)
		} else {
			result.SuccessfullySentTo = append(result.SuccessfullySentTo, *member)
			log.Printf("Successfully sent to %v", member.UserId)
		}
	}

	return result, nil
}

func SendMessage(ctx context.Context, device *Device, recipientUuid string, text string) error {
	// Assemble the content to send
	messageTimestamp := currentMessageTimestamp()
	dataMessage := dataMessageFromText(text, messageTimestamp)
	content := &signalpb.Content{
		DataMessage: dataMessage,
	}

	// Send to the recipient
	err := sendContent(ctx, device, recipientUuid, messageTimestamp, content, 0)
	if err != nil {
		return err
	}

	// TODO: don't fetch every time
	// (But for now this makes sure we know about all our other devices)
	FetchAndProcessPreKey(ctx, device, device.Data.AciUuid, -1)

	// If we have other devices, send to them too
	if howManyOtherDevicesDoWeHave(ctx, device) > 0 {
		syncContent := syncMessageFromDataMessage(dataMessage, &recipientUuid)
		selfSendErr := sendContent(ctx, device, device.Data.AciUuid, messageTimestamp, syncContent, 0)
		if err != nil {
			log.Printf("Failed to send sync message to myself: %v", selfSendErr)
		}
	}
	return nil
}

func currentMessageTimestamp() uint64 {
	return uint64(time.Now().UnixMilli())
}

func sendContent(
	ctx context.Context,
	d *Device,
	recipientUuid string,
	messageTimestamp uint64,
	content *signalpb.Content,
	retryCount int, // For ending recursive retries
) error {
	// TODO: also handle non sealed-sender messages
	// TODO: also handle pre-key messages (for the aformentioned session establishment)
	// TODO: function returns before message is sent - need async status to caller

	//unidentifiedAccessKey := "a key" // TODO: derive key from their profile key

	if retryCount > 3 {
		return fmt.Errorf("Too many retries")
	}

	useUnidentifiedSender := true
	profileKey, err := ProfileKeyForSignalID(ctx, d, recipientUuid)
	if err != nil || profileKey == nil {
		log.Printf("Error getting profile key: %v", err)
		useUnidentifiedSender = false
	}
	accessKey, err := profileKey.DeriveAccessKey()
	if err != nil {
		log.Printf("Error deriving access key: %v", err)
		useUnidentifiedSender = false
	}

	// Encrypt messages
	var messages []MyMessage
	if useUnidentifiedSender {
		messages, err = buildSSMessagesToSend(d, recipientUuid, content, ctx)
	} else {
		messages, err = buildAuthedMessagesToSend(d, recipientUuid, content, ctx)
	}

	outgoingMessages := MyMessages{
		Timestamp: int64(messageTimestamp),
		Online:    false,
		Urgent:    true,
		Messages:  messages,
	}
	jsonBytes, err := json.Marshal(outgoingMessages)
	if err != nil {
		return err
	}
	path := fmt.Sprintf("/v1/messages/%v", recipientUuid)
	request := web.CreateWSRequest("PUT", path, jsonBytes, nil, nil)

	var responseChan <-chan *signalpb.WebSocketResponseMessage
	if useUnidentifiedSender {
		log.Printf("Sending message to %v with unidentified sender", recipientUuid)
		base64AccessKey := base64.StdEncoding.EncodeToString(accessKey[:])
		request.Headers = append(request.Headers, "unidentified-access-key:"+base64AccessKey)
		responseChan, err = d.Connection.UnauthedWS.SendRequest(ctx, request)
	} else {
		log.Printf("Sending message to %v with authed sender", recipientUuid)
		responseChan, err = d.Connection.AuthedWS.SendRequest(ctx, request)
	}
	if err != nil {
		return err
	}

	response := <-responseChan
	log.Printf("Received a RESPONSE! id: %v, code: %v", *response.Id, *response.Status)

	retryableStatuses := []uint32{409, 428, 500, 503}

	// Check to see if our status is retryable
	retryable := false
	for _, status := range retryableStatuses {
		if *response.Status == status {
			retryable = true
			break
		}
	}

	if retryable {
		var err error
		if *response.Status == 409 {
			err = handle409(ctx, d, recipientUuid, response)
		} else if *response.Status == 428 {
			err = handle428(ctx, d, recipientUuid, response)
		}
		if err != nil {
			return err
		}
		// Try to send again (**RECURSIVELY**)
		err = sendContent(ctx, d, recipientUuid, messageTimestamp, content, retryCount+1)
		if err != nil {
			log.Printf("2nd try sendMessage error: %v", err)
			return err
		}
	} else if *response.Status != 200 {
		log.Printf("Unexpected status code: %v", *response.Status)
		log.Printf("Full response: %v", response)
		return fmt.Errorf("Unexpected status code: %v", *response.Status)
	}

	// Open our unauthenticated websocket to send
	//payload.Request.Headers = append(payload.Request.Headers, "Unidentified-Access-Key: "+unidentifiedAccessKey)

	return nil
}

// A 409 means our device list was out of date, so we will fix it up
func handle409(ctx context.Context, device *Device, recipientUuid string, response *signalpb.WebSocketResponseMessage) error {
	// Decode json body
	var body map[string]interface{}
	err := json.Unmarshal(response.Body, &body)
	if err != nil {
		log.Printf("Unmarshal error: %v", err)
		return err
	}
	// check for missingDevices and extraDevices
	if body["missingDevices"] != nil {
		missingDevices := body["missingDevices"].([]interface{})
		log.Printf("-----> missingDevices: %v", missingDevices)
		// TODO: establish session with missing devices
		for _, missingDevice := range missingDevices {
			//do the thing
			log.Printf("-----> missingDevice: %v", missingDevice)
			FetchAndProcessPreKey(ctx, device, recipientUuid, int(missingDevice.(float64)))
		}
	}
	if body["extraDevices"] != nil {
		extraDevices := body["extraDevices"].([]interface{})
		log.Printf("-----> extraDevices: %v", extraDevices)
		for _, extraDevice := range extraDevices {
			// Remove extra device from the sessionstore
			recipient, err := libsignalgo.NewAddress(
				recipientUuid,
				uint(extraDevice.(float64)),
			)
			if err != nil {
				log.Printf("NewAddress error: %v", err)
				return err
			}
			err = device.SessionStoreExtras.RemoveSession(recipient, ctx)
			if err != nil {
				log.Printf("RemoveSession error: %v", err)
				return err
			}
		}
	}
	return err
}

// We got rate limited. We will try sending a "pushChallenge" response, but if that doesn't work
// we just gotta wait.
// TODO: explore captcha response
func handle428(ctx context.Context, device *Device, recipientUuid string, response *signalpb.WebSocketResponseMessage) error {
	// Decode json body
	var body map[string]interface{}
	err := json.Unmarshal(response.Body, &body)
	if err != nil {
		log.Printf("Unmarshal error: %v", err)
		return err
	}

	// Sample response:
	//id:25 status:428 message:"Precondition Required" headers:"Retry-After:86400"
	//headers:"Content-Type:application/json" headers:"Content-Length:88"
	//body:"{\"token\":\"07af0d73-e05d-42c3-9634-634922061966\",\"options\":[\"recaptcha\",\"pushChallenge\"]}"
	var retryAfterSeconds uint64 = 0
	// Find retry after header
	for _, header := range response.Headers {
		key, value := strings.Split(header, ":")[0], strings.Split(header, ":")[1]
		if key == "Retry-After" {
			retryAfterSeconds, err = strconv.ParseUint(value, 10, 64)
			if err != nil {
				log.Printf("ParseUint error: %v", err)
			}
		}
	}
	if retryAfterSeconds > 0 {
		log.Printf("Got rate limited, need to wait %v seconds", retryAfterSeconds)
	}
	if body["options"] != nil {
		options := body["options"].([]interface{})
		for _, option := range options {
			// TODO: this currently doesn't work, server just returns 422
			if option == "pushChallenge" {
				log.Printf("Got pushChallenge, sending response")
				token := body["token"].(string)
				username, password := device.Data.BasicAuthCreds()
				response, err := web.SendHTTPRequest(
					"PUT",
					"/v1/challenge",
					&web.HTTPReqOpt{
						Body:     []byte(fmt.Sprintf("{\"token\":\"%v\",\"type\":\"pushChallenge\"}", token)),
						Username: &username,
						Password: &password,
					},
				)
				if err != nil {
					log.Printf("SendHTTPRequest error: %v", err)
					return err
				}
				log.Printf("Got response: %v", response)
				if response.StatusCode != 200 {
					log.Printf("Unexpected status code: %v", response.StatusCode)
					return fmt.Errorf("Unexpected status code: %v", response.StatusCode)
				}
			}
		}
	}
	return nil
}
