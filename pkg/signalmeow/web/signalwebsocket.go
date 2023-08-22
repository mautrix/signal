package web

import (
	"context"
	"encoding/base64"
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
	ws            *websocket.Conn
	name          string // Purely for logging
	path          string
	basicAuth     *string
	sendChannel   chan SignalWebsocketSendMessage
	statusChannel chan SignalWebsocketConnectionStatus
}

func NewSignalWebsocket(ctx context.Context, name string, path string, username *string, password *string) *SignalWebsocket {
	var basicAuth *string
	if username != nil && password != nil {
		b := base64.StdEncoding.EncodeToString([]byte(*username + ":" + *password))
		basicAuth = &b
	}
	return &SignalWebsocket{
		name:          name,
		path:          path,
		basicAuth:     basicAuth,
		sendChannel:   make(chan SignalWebsocketSendMessage),
		statusChannel: make(chan SignalWebsocketConnectionStatus),
	}
}

type SignalWebsocketConnectionEvent int

const (
	SignalWebsocketConnectionEventConnecting SignalWebsocketConnectionEvent = iota // Implicit to catch default value (0), doesn't get sent
	SignalWebsocketConnectionEventConnected
	SignalWebsocketConnectionEventDisconnected
	SignalWebsocketConnectionEventError
)

type SignalWebsocketConnectionStatus struct {
	Event SignalWebsocketConnectionEvent
	Err   error
}

func (s *SignalWebsocket) Close() error {
	if s.ws != nil {
		return s.ws.Close(websocket.StatusNormalClosure, "")
	}
	return nil
}

func (s *SignalWebsocket) Connect(ctx context.Context, requestHandler *RequestHandlerFunc) chan SignalWebsocketConnectionStatus {
	go s.connectLoop(ctx, requestHandler)
	return s.statusChannel
}

func (s *SignalWebsocket) connectLoop(
	ctx context.Context,
	requestHandler *RequestHandlerFunc,
) {
	incomingRequestChan := make(chan *signalpb.WebSocketRequestMessage, 10000)
	s.sendChannel = make(chan SignalWebsocketSendMessage)
	defer close(incomingRequestChan)
	defer close(s.statusChannel)
	defer close(s.sendChannel)

	const backoffIncrement = 5 * time.Second
	const maxBackoff = 60 * time.Second

	if s.ws != nil {
		panic("Already connected")
	}

	backoff := backoffIncrement
	retrying := false

	// First set up request handler loop. This exists outside of the
	// connection loops because we want to maintain it across reconnections
	go func() {
		for {
			select {
			case <-ctx.Done():
				zlog.Info().Msg("ctx done, stopping request loop")
				return
			case request, ok := <-incomingRequestChan:
				if !ok {
					zlog.Fatal().Msg("incomingRequestChan closed (this should never happen)")
				}
				if request == nil {
					zlog.Fatal().Msg("Received nil request")
				}
				if requestHandler == nil {
					zlog.Fatal().Msg("Received request but no handler")
				}

				// Handle the request with the request handler function
				response, err := (*requestHandler)(ctx, request)

				if err != nil {
					zlog.Err(err).Msg("Error handling request")
					continue
				}
				if response != nil {
					s.sendChannel <- SignalWebsocketSendMessage{
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
			zlog.Warn().Msgf("Failed to connect, retrying in %v seconds...\n", backoff.Seconds())
			time.Sleep(backoff)
			backoff += backoffIncrement
		}

		ws, resp, err := OpenWebsocket(ctx, s.path)
		if err != nil || resp.StatusCode != 101 {
			if err != nil {
				s.statusChannel <- SignalWebsocketConnectionStatus{
					Event: SignalWebsocketConnectionEventDisconnected,
					Err:   errors.Wrap(err, "Error opening websocket"),
				}
			} else if resp.StatusCode != 101 {
				if resp.StatusCode >= 500 {
					// We can try again if it's a 5xx
					s.statusChannel <- SignalWebsocketConnectionStatus{
						Event: SignalWebsocketConnectionEventDisconnected,
						Err:   errors.Errorf("Bad status opening websocket: %v", resp.Status),
					}
				} else {
					// Something is very wrong
					s.statusChannel <- SignalWebsocketConnectionStatus{
						Event: SignalWebsocketConnectionEventError,
						Err:   errors.Errorf("Bad status opening websocket: %v", resp.Status),
					}
					ctx.Done()
					return
				}
			}
			retrying = true
			continue
		}

		// Succssfully connected
		s.statusChannel <- SignalWebsocketConnectionStatus{
			Event: SignalWebsocketConnectionEventConnected,
		}
		s.ws = ws
		retrying = false
		backoff = backoffIncrement

		responseChannels := make(map[uint64]chan *signalpb.WebSocketResponseMessage)
		loopCtx, loopCancel := context.WithCancelCause(ctx)

		// Read loop (for reading incoming reqeusts and responses to outgoing requests)
		go func() {
			err := readLoop(loopCtx, ws, s.name, incomingRequestChan, &responseChannels)
			loopCancel(errors.Wrap(err, "Error in readLoop"))
			zlog.Info().Msgf("readLoop exited (%s)", s.name)
		}()

		// Write loop (for sending outgoing requests and responses to incoming requests)
		go func() {
			err := writeLoop(loopCtx, ws, s.name, s.sendChannel, &responseChannels)
			loopCancel(errors.Wrap(err, "Error in writeLoop"))
			zlog.Info().Msgf("writeLoop exited (%s)", s.name)
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
						loopCancel(errors.Wrap(err, "Error sending keepalive"))
						return
					}
					zlog.Info().Msgf("Sent keepalive (%s)", s.name)
				case <-loopCtx.Done():
					return
				}
			}
		}()

		// Wait for read or write or ping loop to exit (which means there was an error)
		zlog.Info().Msgf("Waiting for read or write loop to exit (%s)", s.name)
		select {
		case <-loopCtx.Done():
			zlog.Info().Msgf("received loopCtx done (%s)", s.name)
			if context.Cause(loopCtx) != nil {
				err := context.Cause(loopCtx)
				if err != nil {
					zlog.Err(err).Msg("loopCtx error")
				}
				s.statusChannel <- SignalWebsocketConnectionStatus{
					Event: SignalWebsocketConnectionEventDisconnected,
					Err:   err,
				}
			}
		}
		zlog.Info().Msgf("Read or write loop exited (%s)", s.name)

		// Clean up
		ws.Close(200, "Done")
		for _, responseChannel := range responseChannels {
			close(responseChannel)
		}
		loopCancel(nil)
		zlog.Debug().Msg("Finished websocket cleanup")
	}
}

func readLoop(
	ctx context.Context,
	ws *websocket.Conn,
	name string,
	incomingRequestChan chan *signalpb.WebSocketRequestMessage,
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
			zlog.Debug().Msgf("Received WS request %v:%v, verb: %v, path: %v", name, *msg.Request.Id, *msg.Request.Verb, *msg.Request.Path)
			incomingRequestChan <- msg.Request
		} else if *msg.Type == signalpb.WebSocketMessage_RESPONSE {
			if msg.Response == nil {
				zlog.Fatal().Msg("Received response with no response")
			}
			if msg.Response.Id == nil {
				zlog.Fatal().Msg("Received response with no id")
			}
			responseChannel, ok := (*responseChannels)[*msg.Response.Id]
			if !ok {
				zlog.Warn().Msgf("Received response with unknown id: %v", *msg.Response.Id)
				continue
			}
			zlog.Debug().Msgf("Received WS response %v:%v, status :%v", name, *msg.Response.Id, *msg.Response.Status)
			responseChannel <- msg.Response
			delete(*responseChannels, *msg.Response.Id)
			zlog.Trace().Msgf("Deleted response channel for id: %v", *msg.Response.Id)
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
	name string,
	sendChannel chan SignalWebsocketSendMessage,
	responseChannels *(map[uint64]chan *signalpb.WebSocketResponseMessage),
) error {
	for i := uint64(1); ; i++ {
		select {
		case <-ctx.Done():
			if ctx.Err() != nil && ctx.Err() != context.Canceled {
				return ctx.Err()
			}
			return nil
		case request, ok := <-sendChannel:
			if !ok {
				return errors.New("Send channel closed")
			}
			if request.RequestMessage != nil && request.ResponseChannel != nil {
				msgType := signalpb.WebSocketMessage_REQUEST
				message := &signalpb.WebSocketMessage{
					Type:    &msgType,
					Request: request.RequestMessage,
				}
				request.RequestMessage.Id = &i
				(*responseChannels)[i] = request.ResponseChannel
				path := *request.RequestMessage.Path
				if len(path) > 30 {
					path = path[:40]
				}
				zlog.Debug().Msgf("Sending WS request %v:%v, verb: %v, path: %v", name, i, *request.RequestMessage.Verb, path)
				err := wspb.Write(ctx, ws, message)
				if err != nil {
					close(request.ResponseChannel)
					return errors.Wrap(err, "Error writing request message")
				}
			} else if request.RequestMessage != nil && request.ResponseMessage != nil {
				message := CreateWSResponse(*request.RequestMessage.Id, request.ResponseMessage.Status)
				zlog.Debug().Msgf("Sending WS response %v:%v, status: %v", name, *request.RequestMessage.Id, request.ResponseMessage.Status)
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
) (<-chan *signalpb.WebSocketResponseMessage, error) {
	//request.Headers = append(request.Headers, "Content-Type: application/json")
	if s.basicAuth != nil {
		request.Headers = append(request.Headers, "authorization:Basic "+*s.basicAuth)
	}
	responseChannel := make(chan *signalpb.WebSocketResponseMessage, 1)
	if s.sendChannel == nil {
		return nil, errors.New("Send channel not initialized")
	}
	s.sendChannel <- SignalWebsocketSendMessage{
		RequestMessage:  request,
		ResponseChannel: responseChannel,
	}
	return responseChannel, nil
}

func OpenWebsocket(ctx context.Context, path string) (*websocket.Conn, *http.Response, error) {
	opt := &websocket.DialOptions{
		HTTPClient: proxiedHTTPClient(),
	}
	urlStr := "wss://" + UrlHost + path
	ws, resp, err := websocket.Dial(ctx, urlStr, opt)
	return ws, resp, err
}

func CreateWSResponse(id uint64, status int) *signalpb.WebSocketMessage {
	if status != 200 && status != 400 {
		// TODO support more responses to Signal? Are there more?
		zlog.Fatal().Msgf("Error creating response %v (non 200/400 not supported yet)", status)
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
