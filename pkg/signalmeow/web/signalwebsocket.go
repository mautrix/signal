package web

import (
	"context"
	"encoding/base64"
	"fmt"
	"log"
	"net/http"
	"time"

	"github.com/pkg/errors"
	signalpb "go.mau.fi/mautrix-signal/pkg/signalmeow/protobuf"
	"go.mau.fi/mautrix-signal/pkg/signalmeow/wspb"
	"nhooyr.io/websocket"
)

const WebsocketProvisioningPath = "/v1/websocket/provisioning/"
const WebsocketPath = "/v1/websocket/"

type SimpleResponse struct {
	Status int
}
type RequestHandlerFunc func(context.Context, *signalpb.WebSocketRequestMessage) (*SimpleResponse, error)

type SignalWebsocket struct {
	ws          *websocket.Conn
	path        string
	sendChannel chan *SignalWebsocketSendMessage
}

func NewSignalWebsocket(ctx context.Context, path string) *SignalWebsocket {
	return &SignalWebsocket{
		path:        path,
		sendChannel: make(chan *SignalWebsocketSendMessage),
	}
}

type SignalWebsocketConnectError struct {
	Err    error
	Status int
}

func (s *SignalWebsocket) Close() error {
	if s.ws != nil {
		return s.ws.Close(websocket.StatusNormalClosure, "")
	}
	return nil
}

// TODO: expose request and error channels instead of using
// a callback function and just printing errors
func (s *SignalWebsocket) Connect(
	ctx context.Context,
	//requestChan chan *signalpb.WebSocketRequestMessage,
	//errorChan chan *SignalWebsocketConnectError,
	requestHandler *RequestHandlerFunc,
) {
	go s.connectLoop(ctx, requestHandler)
}

func (s *SignalWebsocket) connectLoop(
	ctx context.Context,
	requestHandler *RequestHandlerFunc,
	//requestChan chan *signalpb.WebSocketRequestMessage,
	//errorChan chan *SignalWebsocketConnectError,
) {
	// TODO: pass in requestChan and errorChan instead of creating them here
	requestChan := make(chan *signalpb.WebSocketRequestMessage)
	errorChan := make(chan *SignalWebsocketConnectError)
	s.sendChannel = make(chan *SignalWebsocketSendMessage)
	defer close(requestChan)
	defer close(errorChan)
	defer close(s.sendChannel)

	const backoffIncrement = 5 * time.Second
	const maxBackoff = 60 * time.Second

	if s.ws != nil {
		panic("Already connected")
	}

	backoff := backoffIncrement
	retrying := false

	// First set up temporary error sink and request handler loop
	// These exist outside of the connection loop because we want to
	// maintain them across reconnections

	// Sink errorChan so it doesn't block things
	go func() {
		for err := range errorChan {
			if ctx.Err() != nil {
				return
			}
			log.Printf("Received error from errorChan: %v", err)
		}
		log.Printf("errorChan has been closed.")
	}()

	// Request handling loop
	go func() {
		for {
			select {
			case <-ctx.Done():
				log.Printf("ctx done, stopping request loop")
				return
			case request, ok := <-requestChan:
				if !ok {
					log.Printf("requestChan closed, stopping request loop")
					panic("requestChan closed")
				}
				if request == nil {
					errorChan <- &SignalWebsocketConnectError{
						Err:    errors.New("Received nil request"),
						Status: 0,
					}
					panic("Received nil request")
				}
				if requestHandler == nil {
					errorChan <- &SignalWebsocketConnectError{
						Err:    errors.New("Received request but no handler"),
						Status: 0,
					}
					panic("Received request but no handler")
				}
				response, err := (*requestHandler)(ctx, request)
				if err != nil {
					errorChan <- &SignalWebsocketConnectError{
						Err:    errors.Wrap(err, "Error handling request"),
						Status: 0,
					}
					log.Printf("Error handling request: %v", err)
					continue
				}
				if response != nil {
					log.Printf("Sending response: %v", response)
					s.sendChannel <- &SignalWebsocketSendMessage{
						RequestMessage:  request,
						ResponseMessage: response,
					}
				}
			}
		}
	}()

	// Main connection loop - if there's a problem with anything just
	// kill everything (including the websocket) and build it all up again
	for {
		if retrying {
			if backoff > maxBackoff {
				backoff = maxBackoff
			}
			fmt.Printf("Failed to connect, retrying in %v seconds...\n", backoff.Seconds())
			time.Sleep(backoff)
			backoff += backoffIncrement
		}

		ws, resp, err := OpenWebsocket(ctx, s.path)
		if err != nil || resp.StatusCode != 101 {
			if err != nil {
				errorChan <- &SignalWebsocketConnectError{
					Err:    errors.Wrap(err, "Error opening websocket"),
					Status: 0,
				}
			} else if resp.StatusCode != 101 {
				errorChan <- &SignalWebsocketConnectError{
					Err:    errors.Errorf("Bad status opening websocket: %v", resp.Status),
					Status: resp.StatusCode,
				}
				if resp.StatusCode < 500 {
					panic("Bad status opening websocket - status: " + resp.Status)
				}
			}
			retrying = true
			continue
		}

		// Succssfully connected
		s.ws = ws
		retrying = false
		backoff = backoffIncrement

		responseChannels := make(map[uint64]chan *signalpb.WebSocketResponseMessage)
		loopCtx, loopCancel := context.WithCancelCause(ctx)

		// Read loop (for reading incoming reqeusts and responses to outgoing requests)
		go func() {
			err := readLoop(loopCtx, ws, requestChan, &responseChannels)
			if err != nil {
				fmt.Printf("Error in readLoop: %v\n", err)
			}
			loopCancel(err)
			log.Printf("readLoop exited")
		}()

		// Write loop (for sending outgoing requests and responses to incoming requests)
		go func() {
			err := writeLoop(loopCtx, ws, s.sendChannel, &responseChannels)
			if err != nil {
				fmt.Printf("Error in writeLoop: %v\n", err)
			}
			loopCancel(err)
			log.Printf("writeLoop exited")
		}()

		// Ping loop (send a keepalive Ping every 30s)
		go func() {
			ticker := time.NewTicker(30 * time.Second)
			defer ticker.Stop()

			for {
				select {
				case <-ticker.C:
					err := ws.Ping(loopCtx)
					if err != nil {
						log.Printf("Error sending keepalive: %v", err)
						loopCancel(err)
						return
					}
					log.Printf("Sent keepalive")
				case <-loopCtx.Done():
					return
				}
			}
		}()

		// Wait for receive or write loop to exit (which means there was an error)
		log.Printf("Waiting for read or write loop to exit")
		select {
		case <-loopCtx.Done():
			log.Printf("received loopCtx done")
			if context.Cause(loopCtx) != nil {
				log.Printf("loopCtx error: %v", context.Cause(loopCtx))
				errorChan <- &SignalWebsocketConnectError{
					Err:    context.Cause(loopCtx),
					Status: 0,
				}
			}
		}
		log.Printf("Read or write loop exited")

		// Clean up
		ws.Close(200, "Done")
		for _, responseChannel := range responseChannels {
			close(responseChannel)
		}
		loopCancel(nil)
		log.Printf("Finished cleanup")
	}
}

func readLoop(
	ctx context.Context,
	ws *websocket.Conn,
	requestChan chan *signalpb.WebSocketRequestMessage,
	responseChannels *(map[uint64]chan *signalpb.WebSocketResponseMessage),
) error {
	for {
		if ctx.Err() != nil {
			return ctx.Err()
		}
		msg := &signalpb.WebSocketMessage{}
		//ctx, _ := context.WithTimeout(ctx, 10*time.Second) // For testing
		err := wspb.Read(ctx, ws, msg)
		if err != nil {
			return errors.Wrap(err, "Error reading message")
		}
		if msg.Type == nil {
			return errors.New("Received message with no type")
		} else if *msg.Type == signalpb.WebSocketMessage_REQUEST {
			if msg.Request == nil {
				return errors.New("Received request message with no request")
			}
			requestChan <- msg.Request
		} else if *msg.Type == signalpb.WebSocketMessage_RESPONSE {
			if msg.Response == nil {
				log.Fatal("Received response with no response")
			}
			if msg.Response.Id == nil {
				log.Fatal("Received response with no id")
			}
			responseChannel, ok := (*responseChannels)[*msg.Response.Id]
			if !ok {
				log.Printf("Received response with unknown id: %v", *msg.Response.Id)
				continue
			}
			responseChannel <- msg.Response
			delete(*responseChannels, *msg.Response.Id)
			log.Printf("Deleted response channel for id: %v", *msg.Response.Id)
			close(responseChannel)
		} else if *msg.Type == signalpb.WebSocketMessage_UNKNOWN {
			return errors.Errorf("Received message with unknown type: %v", *msg.Type)
		} else {
			return errors.Errorf("Received message with actually unknown type: %v", *msg.Type)
		}
	}
}

type SignalWebsocketSendMessage struct {
	// Populate if we're sending a request:
	ResponseChannel chan *signalpb.WebSocketResponseMessage
	// Populate if we're sending a response:
	ResponseMessage *SimpleResponse
	// Populate this for request AND response
	RequestMessage *signalpb.WebSocketRequestMessage
}

func writeLoop(
	ctx context.Context,
	ws *websocket.Conn,
	sendChannel chan *SignalWebsocketSendMessage,
	responseChannels *(map[uint64]chan *signalpb.WebSocketResponseMessage),
) error {
	for i := uint64(1); ; i++ {
		select {
		case <-ctx.Done():
			return ctx.Err()
		case request, ok := <-sendChannel:
			if !ok {
				return errors.New("Send channel closed")
			}
			if request == nil {
				return errors.New("Received nil request")
			}
			if request.RequestMessage != nil && request.ResponseChannel != nil {
				msgType := signalpb.WebSocketMessage_REQUEST
				message := &signalpb.WebSocketMessage{
					Type:    &msgType,
					Request: request.RequestMessage,
				}
				request.RequestMessage.Id = &i
				(*responseChannels)[i] = request.ResponseChannel
				err := wspb.Write(ctx, ws, message)
				if err != nil {
					close(request.ResponseChannel)
					return errors.Wrap(err, "Error writing request message")
				}
			} else if request.RequestMessage != nil && request.ResponseMessage != nil {
				message := CreateWSResponse(*request.RequestMessage.Id, request.ResponseMessage.Status)
				err := wspb.Write(ctx, ws, message)
				if err != nil {
					return errors.Wrap(err, "Error writing response message")
				}
			} else {
				return errors.Errorf("Invalid request: %+v", request)
			}
		}
	}
}

func (s *SignalWebsocket) SendRequest(
	ctx context.Context,
	request *signalpb.WebSocketRequestMessage,
	username *string,
	password *string,
) (<-chan *signalpb.WebSocketResponseMessage, error) {
	//request.Headers = append(request.Headers, "Content-Type: application/json")
	//if username != nil && password != nil {
	//basicAuth := base64.StdEncoding.EncodeToString([]byte(*username + ":" + *password))
	//request.Headers = append(request.Headers, "authorization:Basic "+basicAuth)
	//}
	responseChannel := make(chan *signalpb.WebSocketResponseMessage, 1)
	if s.sendChannel == nil {
		return nil, errors.New("Send channel not initialized")
	}
	s.sendChannel <- &SignalWebsocketSendMessage{
		RequestMessage:  request,
		ResponseChannel: responseChannel,
	}
	return responseChannel, nil
}

func OpenWebsocket(ctx context.Context, path string) (*websocket.Conn, *http.Response, error) {
	opt := &websocket.DialOptions{
		HTTPClient: proxiedHTTPClient(),
	}
	urlStr := "wss://" + urlHost + path
	ws, resp, err := websocket.Dial(ctx, urlStr, opt)

	if err != nil {
		log.Printf("failed on open %v", resp)
	}
	return ws, resp, err
}

func CreateWSResponse(id uint64, status int) *signalpb.WebSocketMessage {
	if status != 200 && status != 400 {
		// TODO support more responses?
		log.Fatal("Error creating response (non 200/400 not supported yet)")
		return nil
	}
	msg_type := signalpb.WebSocketMessage_RESPONSE
	message := "OK"
	if status == 400 {
		message = "Unknown"
	}
	status32 := uint32(status)
	response := &signalpb.WebSocketMessage{
		Type: &msg_type,
		Response: &signalpb.WebSocketResponseMessage{
			Id:      &id,
			Message: &message,
			Status:  &status32,
			Headers: []string{},
		},
	}
	return response
}

func CreateWSRequest(method string, path string, body []byte, username *string, password *string) *signalpb.WebSocketRequestMessage {
	request := &signalpb.WebSocketRequestMessage{
		Verb: &method,
		Path: &path,
		Body: body,
	}
	request.Headers = []string{}
	request.Headers = append(request.Headers, "content-type:application/json; charset=utf-8")
	if username != nil && password != nil {
		basicAuth := base64.StdEncoding.EncodeToString([]byte(*username + ":" + *password))
		request.Headers = append(request.Headers, "authorization:Basic "+basicAuth)
	}
	return request
}
