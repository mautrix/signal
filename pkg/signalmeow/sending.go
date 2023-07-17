package signalmeow

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"log"
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

func buildAuthedMessagesToSend(d *Device, recipientUuid string, content *signalpb.Content, ctx context.Context) ([]MyMessage, error) {
	messages := []MyMessage{}

	recipients, sessionRecords, err := d.SessionStoreExtras.AllSessionsForUUID(recipientUuid, ctx)
	if err != nil {
		return nil, err
	}
	if recipients == nil || sessionRecords == nil {
		return nil, fmt.Errorf("No sessions found for recipient %s", recipientUuid)
	}
	if len(recipients) != len(sessionRecords) {
		return nil, fmt.Errorf("Mismatched number of recipients (%d) and session records (%d)", len(recipients), len(sessionRecords))
	}
	if len(recipients) == 0 || len(sessionRecords) == 0 {
		return nil, fmt.Errorf("No sessions found for recipient %s", recipientUuid)
	}

	for i, recipient := range recipients {
		// Encrypt our content in an sealed sender envelope
		serializedMessage, err := proto.Marshal(content)
		if err != nil {
			return nil, err
		}
		session := sessionRecords[i]
		paddedMessage, err := addPadding(3, []byte(serializedMessage)) // TODO: figure out how to get actual version
		cipherTextMessage, err := libsignalgo.Encrypt(
			[]byte(paddedMessage),
			recipient,
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
			//panic(fmt.Sprintf("Unknown message type: %v", cipherMessageType))
			return nil, fmt.Errorf("Unknown message type: %v", cipherMessageType)
		}
		log.Printf("Sending message type %v", envelopeType)

		destinationRegistrationID, err := session.GetRemoteRegistrationID()
		if err != nil {
			return nil, err
		}
		deviceID, err := recipient.DeviceID()
		if err != nil {
			return nil, err
		}

		// Build payload to send over websocket
		outgoingMessage := MyMessage{
			Type:                      envelopeType,
			DestinationDeviceID:       int(deviceID),
			DestinationRegistrationID: int(destinationRegistrationID),
			Content:                   base64.StdEncoding.EncodeToString(encryptedPayload),
		}
		messages = append(messages, outgoingMessage)
	}

	return messages, nil
}

func buildSSMessagesToSend(d *Device, recipientUuid string, message *signalpb.Content, ctx context.Context) ([]MyMessage, error) {
	messages := []MyMessage{}

	// Grab our sender cert
	cert, err := senderCertificate(d)
	if err != nil {
		return nil, err
	}

	for _, deviceId := range []uint{1, 2} { // TODO: get actual devices
		// Make an address
		recipient, err := libsignalgo.NewAddress(
			recipientUuid,
			deviceId,
		)
		if err != nil {
			return nil, err
		}
		// Encrypt our message in an sealed sender envelope
		serializedMessage := message.String()
		sessionRecord, err := d.SessionStore.LoadSession(recipient, ctx)
		if err != nil {
			return nil, err
		} else if sessionRecord == nil {
			return nil, fmt.Errorf("no session found for %v", recipient)
		}
		paddedMessage, err := addPadding(3, []byte(serializedMessage)) // TODO: figure out how to get actual version
		encryptedPayload, err := libsignalgo.SealedSenderEncryptPlaintext(
			[]byte(paddedMessage),
			recipient,
			cert,
			d.SessionStore,
			d.IdentityStore,
			libsignalgo.NewCallbackContext(ctx),
		)

		session, err := d.SessionStore.LoadSession(recipient, ctx)
		if err != nil {
			return nil, err
		} else if session == nil {
			return nil, fmt.Errorf("no session found for %v", recipient)
		}
		destinationRegistrationID, err := session.GetRemoteRegistrationID()
		if err != nil {
			return nil, err
		}
		deviceID, err := recipient.DeviceID()
		if err != nil {
			return nil, err
		}

		// Build payload to send over websocket
		outgoingMessage := MyMessage{
			Type:                      int(signalpb.Envelope_UNIDENTIFIED_SENDER),
			DestinationDeviceID:       int(deviceID),
			DestinationRegistrationID: int(destinationRegistrationID),
			Content:                   base64.StdEncoding.EncodeToString(encryptedPayload),
		}
		messages = append(messages, outgoingMessage)
	}

	return messages, nil
}

func sendMessage(
	ctx context.Context,
	d *Device,
	recipientUuid string,
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

	messageTimestamp := uint64(time.Now().UnixMilli())

	if content.DataMessage != nil {
		content.DataMessage.Timestamp = &messageTimestamp
	}

	// Encrypt messages
	messages, err := buildAuthedMessagesToSend(d, recipientUuid, content, ctx)

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
	log.Printf("Sending content: %v", string(jsonBytes))
	path := fmt.Sprintf("/v1/messages/%v", recipientUuid)
	request := web.CreateWSRequest("PUT", path, jsonBytes, nil, nil)

	responseChan, err := d.Connection.AuthedWS.SendRequest(ctx, request)
	if err != nil {
		return err
	}

	var asyncError error

	go func() {
		response := <-responseChan
		log.Printf("Received a RESPONSE! id: %v, code: %v", *response.Id, *response.Status)
		if *response.Status == 409 {
			err := handle409(ctx, d, recipientUuid, response)
			if err != nil {
				log.Printf("handle409 error: %v", err)
				asyncError = err
				return
			}
			// Try to send again (**RECURSIVELY**)

			err = sendMessage(ctx, d, recipientUuid, content, retryCount+1)
			if err != nil {
				log.Printf("2nd try sendMessage error: %v", err)
				asyncError = err
				return
			}
		}
	}()

	// Open our unauthenticated websocket to send
	//payload.Request.Headers = append(payload.Request.Headers, "Unidentified-Access-Key: "+unidentifiedAccessKey)

	return asyncError
}

func SendMessage(ctx context.Context, device *Device, recipientUuid string, text string) error {
	message := &signalpb.Content{
		DataMessage: &signalpb.DataMessage{
			Body: proto.String(text),
		},
	}
	return sendMessage(ctx, device, recipientUuid, message, 0)
}

func handle409(ctx context.Context, device *Device, recipientUuid string, response *signalpb.WebSocketResponseMessage) error {
	// Decode json body
	var body map[string]interface{}
	err := json.Unmarshal(response.Body, &body)
	if err != nil {
		log.Printf("Unmarshal error: %v", err)
		return err
	}
	log.Printf("-----> body: %v", body)
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
