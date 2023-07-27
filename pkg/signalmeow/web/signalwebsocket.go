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
	ws          *websocket.Conn
	name        string // Purely for logging
	path        string
	basicAuth   *string
	sendChannel chan *SignalWebsocketSendMessage
}

func NewSignalWebsocket(ctx context.Context, name string, path string, username *string, password *string) *SignalWebsocket {
	var basicAuth *string
	if username != nil && password != nil {
		b := base64.StdEncoding.EncodeToString([]byte(*username + ":" + *password))
		basicAuth = &b
	}
	return &SignalWebsocket{
		name:        name,
		path:        path,
		basicAuth:   basicAuth,
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
		for websocketError := range errorChan {
			if ctx.Err() != nil {
				zlog.Err(ctx.Err()).Msg("websocket ctx error, stopping error loop")
				return
			}
			zlog.Err(websocketError.Err).Msgf("Received error from errorChan, status: %v", websocketError.Status)
		}
		zlog.Info().Msg("errorChan has been closed")
	}()

	// Request handling loop
	go func() {
		for {
			select {
			case <-ctx.Done():
				zlog.Info().Msg("ctx done, stopping request loop")
				return
			case request, ok := <-requestChan:
				if !ok {
					zlog.Fatal().Msg("requestChan closed, stopping request loop")
				}
				if request == nil {
					errorChan <- &SignalWebsocketConnectError{
						Err:    errors.New("Received nil request"),
						Status: 0,
					}
					zlog.Fatal().Msg("Received nil request")
				}
				if requestHandler == nil {
					errorChan <- &SignalWebsocketConnectError{
						Err:    errors.New("Received request but no handler"),
						Status: 0,
					}
					zlog.Fatal().Msg("Received request but no handler")
				}
				response, err := (*requestHandler)(ctx, request)
				if err != nil {
					errorChan <- &SignalWebsocketConnectError{
						Err:    errors.Wrap(err, "Error handling request"),
						Status: 0,
					}
					zlog.Err(err).Msg("Error handling request")
					continue
				}
				if response != nil {
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
			zlog.Warn().Msgf("Failed to connect, retrying in %v seconds...\n", backoff.Seconds())
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
			err := readLoop(loopCtx, ws, s.name, requestChan, &responseChannels)
			if err != nil {
				zlog.Err(err).Msgf("Error in readLoop (%s)", s.name)
			}
			loopCancel(err)
			zlog.Info().Msgf("readLoop exited (%s)", s.name)
		}()

		// Write loop (for sending outgoing requests and responses to incoming requests)
		go func() {
			err := writeLoop(loopCtx, ws, s.name, s.sendChannel, &responseChannels)
			if err != nil {
				zlog.Err(err).Msgf("Error in writeLoop (%s)", s.name)
			}
			loopCancel(err)
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
						zlog.Err(err).Msgf("Error sending keepalive (%s)", s.name)
						loopCancel(err)
						return
					}
					zlog.Info().Msgf("Sent keepalive (%s)", s.name)
				case <-loopCtx.Done():
					return
				}
			}
		}()

		// Wait for receive or write loop to exit (which means there was an error)
		zlog.Info().Msgf("Waiting for read or write loop to exit (%s)", s.name)
		select {
		case <-loopCtx.Done():
			zlog.Info().Msgf("received loopCtx done (%s)", s.name)
			if context.Cause(loopCtx) != nil {
				err := context.Cause(loopCtx)
				zlog.Err(err).Msg("loopCtx error")
				errorChan <- &SignalWebsocketConnectError{
					Err:    err,
					Status: 0,
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
			zlog.Debug().Msgf("Received WS request %v:%v, verb: %v, path: %v", name, *msg.Request.Id, *msg.Request.Verb, *msg.Request.Path)
			requestChan <- msg.Request
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
