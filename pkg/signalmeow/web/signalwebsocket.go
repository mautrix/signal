// mautrix-signal - A Matrix-signal puppeting bridge.
// Copyright (C) 2023 Scott Weber
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

package web

import (
	"context"
	"encoding/base64"
	"errors"
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/rs/zerolog"
	"nhooyr.io/websocket"

	signalpb "go.mau.fi/mautrix-signal/pkg/signalmeow/protobuf"
	"go.mau.fi/mautrix-signal/pkg/signalmeow/wspb"
)

const WebsocketProvisioningPath = "/v1/websocket/provisioning/"
const WebsocketPath = "/v1/websocket/"

type SimpleResponse struct {
	Status int
}
type RequestHandlerFunc func(context.Context, *signalpb.WebSocketRequestMessage) (*SimpleResponse, error)

type SignalWebsocket struct {
	ws            *websocket.Conn
	path          string
	basicAuth     *string
	sendChannel   chan SignalWebsocketSendMessage
	statusChannel chan SignalWebsocketConnectionStatus
}

func NewSignalWebsocket(path string, username *string, password *string) *SignalWebsocket {
	var basicAuth *string
	if username != nil && password != nil {
		b := base64.StdEncoding.EncodeToString([]byte(*username + ":" + *password))
		basicAuth = &b
	}
	return &SignalWebsocket{
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
	SignalWebsocketConnectionEventLoggedOut
	SignalWebsocketConnectionEventError
	SignalWebsocketConnectionEventCleanShutdown
)

// mapping from SignalWebsocketConnectionEvent to its string representation
var signalWebsocketConnectionEventNames = map[SignalWebsocketConnectionEvent]string{
	SignalWebsocketConnectionEventConnecting:    "SignalWebsocketConnectionEventConnecting",
	SignalWebsocketConnectionEventConnected:     "SignalWebsocketConnectionEventConnected",
	SignalWebsocketConnectionEventDisconnected:  "SignalWebsocketConnectionEventDisconnected",
	SignalWebsocketConnectionEventLoggedOut:     "SignalWebsocketConnectionEventLoggedOut",
	SignalWebsocketConnectionEventError:         "SignalWebsocketConnectionEventError",
	SignalWebsocketConnectionEventCleanShutdown: "SignalWebsocketConnectionEventCleanShutdown",
}

// Implement the fmt.Stringer interface
func (s SignalWebsocketConnectionEvent) String() string {
	return signalWebsocketConnectionEventNames[s]
}

type SignalWebsocketConnectionStatus struct {
	Event SignalWebsocketConnectionEvent
	Err   error
}

func (s *SignalWebsocket) IsConnected() bool {
	return s.ws != nil
}

func (s *SignalWebsocket) Close() error {
	defer func() {
		if s != nil {
			s.ws = nil
		}
	}()
	if s != nil && s.ws != nil {
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
	log := zerolog.Ctx(ctx).With().
		Str("loop", "signal_websocket_connect_loop").
		Logger()
	ctx, cancel := context.WithCancel(ctx)

	incomingRequestChan := make(chan *signalpb.WebSocketRequestMessage, 10000)
	defer func() {
		close(incomingRequestChan)
		close(s.statusChannel)
		close(s.sendChannel)
		incomingRequestChan = nil
		s.statusChannel = nil
		s.sendChannel = nil
		cancel()
	}()

	const backoffIncrement = 5 * time.Second
	const maxBackoff = 60 * time.Second

	if s.ws != nil {
		panic("Already connected")
	}

	// First set up request handler loop. This exists outside of the
	// connection loops because we want to maintain it across reconnections
	go func() {
		for {
			select {
			case <-ctx.Done():
				log.Info().Msg("ctx done, stopping request loop")
				return
			case request, ok := <-incomingRequestChan:
				if !ok {
					// Main connection loop must have closed, so we should stop
					log.Info().Msg("incomingRequestChan closed, stopping request loop")
					return
				}
				if request == nil {
					log.Fatal().Msg("Received nil request")
				}
				if requestHandler == nil {
					log.Fatal().Msg("Received request but no handler")
				}

				// Handle the request with the request handler function
				response, err := (*requestHandler)(ctx, request)

				if err != nil {
					log.Err(err).Msg("Error handling request")
					continue
				}
				if response != nil && s.sendChannel != nil {
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
	backoff := backoffIncrement
	retrying := false
	errorCount := 0
	for {
		if retrying {
			if backoff > maxBackoff {
				backoff = maxBackoff
			}
			log.Warn().Dur("backoff", backoff).Msg("Failed to connect, waiting to retry...")
			time.Sleep(backoff)
			backoff += backoffIncrement
		}
		if ctx.Err() != nil {
			log.Info().Msg("ctx done, stopping connection loop")
			return
		}

		ws, resp, err := OpenWebsocket(ctx, s.path)
		if resp != nil {
			if resp.StatusCode != 101 {
				// Server didn't want to open websocket
				if resp.StatusCode >= 500 {
					// We can try again if it's a 5xx
					s.statusChannel <- SignalWebsocketConnectionStatus{
						Event: SignalWebsocketConnectionEventDisconnected,
						Err:   fmt.Errorf("5xx opening websocket: %v", resp.Status),
					}
				} else if resp.StatusCode == 403 {
					// We are logged out, so we should stop trying to reconnect
					s.statusChannel <- SignalWebsocketConnectionStatus{
						Event: SignalWebsocketConnectionEventLoggedOut,
						Err:   fmt.Errorf("403 opening websocket, we are logged out"),
					}
					return // NOT RETRYING, KILLING THE CONNECTION LOOP
				} else if resp.StatusCode > 0 && resp.StatusCode < 500 {
					// Unexpected status code
					s.statusChannel <- SignalWebsocketConnectionStatus{
						Event: SignalWebsocketConnectionEventError,
						Err:   fmt.Errorf("bad status opening websocket: %v", resp.Status),
					}
					return // NOT RETRYING, KILLING THE CONNECTION LOOP
				} else {
					// Something is very wrong
					s.statusChannel <- SignalWebsocketConnectionStatus{
						Event: SignalWebsocketConnectionEventError,
						Err:   fmt.Errorf("unexpected error opening websocket: %v", resp.Status),
					}
				}
				// Retry the connection
				retrying = true
				continue
			}
		}
		if err != nil {
			// Unexpected error opening websocket
			if backoff < maxBackoff {
				s.statusChannel <- SignalWebsocketConnectionStatus{
					Event: SignalWebsocketConnectionEventDisconnected,
					Err:   fmt.Errorf("hopefully transient error opening websocket: %w", err),
				}
			} else {
				s.statusChannel <- SignalWebsocketConnectionStatus{
					Event: SignalWebsocketConnectionEventError,
					Err:   fmt.Errorf("continuing error opening websocket: %w", err),
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
			err := readLoop(loopCtx, ws, incomingRequestChan, &responseChannels)
			// Don't want to put an err into loopCancel if we don't have one
			if err != nil {
				err = fmt.Errorf("error in readLoop: %w", err)
			}
			loopCancel(err)
			log.Info().Msg("readLoop exited")
		}()

		// Write loop (for sending outgoing requests and responses to incoming requests)
		go func() {
			err := writeLoop(loopCtx, ws, s.sendChannel, &responseChannels)
			// Don't want to put an err into loopCancel if we don't have one
			if err != nil {
				err = fmt.Errorf("error in writeLoop: %w", err)
			}
			loopCancel(err)
			log.Info().Msg("writeLoop exited")
		}()

		// Ping loop (send a keepalive Ping every 30s)
		go func() {
			ticker := time.NewTicker(30 * time.Second)
			defer ticker.Stop()

			for {
				select {
				case <-ticker.C:
					pingCtx, cancel := context.WithTimeout(loopCtx, 20*time.Second)
					err := ws.Ping(pingCtx)
					cancel()
					if err != nil {
						log.Err(err).Msg("Error pinging")
						loopCancel(err)
						return
					}
					log.Debug().Msg("Sent keepalive")
				case <-loopCtx.Done():
					return
				}
			}
		}()

		// Wait for read or write or ping loop to exit (which means there was an error)
		log.Info().Msg("Waiting for read or write loop to exit")
		select {
		case <-loopCtx.Done():
			log.Info().Msg("received loopCtx done")
			if context.Cause(loopCtx) != nil {
				err := context.Cause(loopCtx)
				if err != nil && err != context.Canceled {
					log.Err(err).Msg("loopCtx error")
					errorCount++
				}
			}
			if context.Cause(loopCtx) != nil && context.Cause(loopCtx) == context.Canceled {
				s.statusChannel <- SignalWebsocketConnectionStatus{
					Event: SignalWebsocketConnectionEventCleanShutdown,
				}
			} else {
				s.statusChannel <- SignalWebsocketConnectionStatus{
					Event: SignalWebsocketConnectionEventDisconnected,
					Err:   err,
				}
			}
		case <-ctx.Done():
			log.Info().AnErr("ctx_err", ctx.Err()).AnErr("ctx_cause", context.Cause(ctx)).Msg("received ctx done")
			if context.Cause(ctx) != nil && context.Cause(ctx) == context.Canceled {
				s.statusChannel <- SignalWebsocketConnectionStatus{
					Event: SignalWebsocketConnectionEventCleanShutdown,
				}
				return
			} else {
				s.statusChannel <- SignalWebsocketConnectionStatus{
					Event: SignalWebsocketConnectionEventDisconnected,
					Err:   err,
				}
			}
		}
		log.Info().Msg("Read or write loop exited")

		// Clean up
		ws.Close(200, "Done")
		for _, responseChannel := range responseChannels {
			close(responseChannel)
		}
		loopCancel(nil)
		log.Debug().Msg("Finished websocket cleanup")
		if errorCount > 500 {
			// Something is really wrong, we better panic.
			// This is a last defense against a runaway error loop,
			// like the WS continually closing and reconnecting
			log.Fatal().Int("error_count", errorCount).Msg("Too many errors, panicking")
		}
	}
}

func readLoop(
	ctx context.Context,
	ws *websocket.Conn,
	incomingRequestChan chan *signalpb.WebSocketRequestMessage,
	responseChannels *(map[uint64]chan *signalpb.WebSocketResponseMessage),
) error {
	log := zerolog.Ctx(ctx).With().
		Str("loop", "signal_websocket_read_loop").
		Logger()
	for {
		if ctx.Err() != nil {
			return ctx.Err()
		}
		msg := &signalpb.WebSocketMessage{}
		//ctx, _ := context.WithTimeout(ctx, 10*time.Second) // For testing
		err := wspb.Read(ctx, ws, msg)
		if err != nil {
			if err == context.Canceled {
				log.Info().Msg("readLoop context canceled")
			}
			if strings.Contains(err.Error(), "StatusNormalClosure") {
				log.Info().Msg("readLoop received StatusNormalClosure")
				return nil
			}
			return fmt.Errorf("error reading message: %w", err)
		}
		if msg.Type == nil {
			return errors.New("received message with no type")
		} else if *msg.Type == signalpb.WebSocketMessage_REQUEST {
			if msg.Request == nil {
				return errors.New("received request message with no request")
			}
			log.Debug().
				Uint64("request_id", *msg.Request.Id).
				Str("request_verb", *msg.Request.Verb).
				Str("request_path", *msg.Request.Path).
				Msg("Received WS request")
			incomingRequestChan <- msg.Request
		} else if *msg.Type == signalpb.WebSocketMessage_RESPONSE {
			if msg.Response == nil {
				log.Fatal().Msg("Received response with no response")
			}
			if msg.Response.Id == nil {
				log.Fatal().Msg("Received response with no id")
			}
			responseChannel, ok := (*responseChannels)[*msg.Response.Id]
			if !ok {
				log.Warn().
					Uint64("response_id", *msg.Response.Id).
					Msg("Received response with unknown id")
				continue
			}
			log.Debug().
				Uint64("response_id", *msg.Response.Id).
				Uint32("response_status", *msg.Response.Status).
				Msg("Received WS response")
			responseChannel <- msg.Response
			delete(*responseChannels, *msg.Response.Id)
			log.Debug().
				Uint64("response_id", *msg.Response.Id).
				Msg("Deleted response channel for ID")
			close(responseChannel)
		} else if *msg.Type == signalpb.WebSocketMessage_UNKNOWN {
			return fmt.Errorf("received message with unknown type: %v", *msg.Type)
		} else {
			return fmt.Errorf("received message with actually unknown type: %v", *msg.Type)
		}
	}
}

type SignalWebsocketSendMessage struct {
	// Populate if we're sending a request:
	RequestTime     time.Time
	ResponseChannel chan *signalpb.WebSocketResponseMessage
	// Populate if we're sending a response:
	ResponseMessage *SimpleResponse
	// Populate this for request AND response
	RequestMessage *signalpb.WebSocketRequestMessage
}

func writeLoop(
	ctx context.Context,
	ws *websocket.Conn,
	sendChannel chan SignalWebsocketSendMessage,
	responseChannels *(map[uint64]chan *signalpb.WebSocketResponseMessage),
) error {
	log := zerolog.Ctx(ctx).With().
		Str("loop", "signal_websocket_write_loop").
		Logger()
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
				if request.RequestTime != (time.Time{}) {
					elapsed := time.Since(request.RequestTime)
					if elapsed > 1*time.Minute {
						return fmt.Errorf("Took too long, not sending (elapsed: %v)", elapsed)
					} else if elapsed > 10*time.Second {
						log.Warn().
							Uint64("request_id", i).
							Str("request_verb", *request.RequestMessage.Verb).
							Str("request_path", path).
							Dur("elapsed", elapsed).
							Msg("Sending WS request")
					} else {
						log.Debug().
							Uint64("request_id", i).
							Str("request_verb", *request.RequestMessage.Verb).
							Str("request_path", path).
							Dur("elapsed", elapsed).
							Msg("Sending WS request")
					}
				}
				err := wspb.Write(ctx, ws, message)
				if err != nil {
					if ctx.Err() != nil && ctx.Err() != context.Canceled {
						return ctx.Err()
					}
					return fmt.Errorf("error writing request message: %w", err)
				}
			} else if request.RequestMessage != nil && request.ResponseMessage != nil {
				message := CreateWSResponse(ctx, *request.RequestMessage.Id, request.ResponseMessage.Status)
				log.Debug().
					Uint64("request_id", *request.RequestMessage.Id).
					Int("response_status", request.ResponseMessage.Status).
					Msg("Sending WS response")
				err := wspb.Write(ctx, ws, message)
				if err != nil {
					return fmt.Errorf("error writing response message: %w", err)
				}
			} else {
				return fmt.Errorf("invalid request: %+v", request)
			}
		}
	}
}

func (s *SignalWebsocket) SendRequest(
	ctx context.Context,
	request *signalpb.WebSocketRequestMessage,
) (*signalpb.WebSocketResponseMessage, error) {
	startTime := time.Now()
	return s.sendRequestInternal(ctx, request, startTime, 0)
}

func (s *SignalWebsocket) sendRequestInternal(
	ctx context.Context,
	request *signalpb.WebSocketRequestMessage,
	startTime time.Time,
	retryCount int,
) (*signalpb.WebSocketResponseMessage, error) {
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
		RequestTime:     startTime,
	}
	response := <-responseChannel

	if response == nil {
		// If out of retries, return error no matter what
		if retryCount >= 3 {
			// TODO: I think error isn't getting passed in this context (as it's not the one in writeLoop)
			if ctx.Err() != nil {
				return nil, fmt.Errorf("retried 3 times, giving up: %w", ctx.Err())
			} else {
				return nil, errors.New("Retried 3 times, giving up")
			}
		}
		if ctx.Err() != nil {
			// if error contains "Took too long" don't retry
			if strings.Contains(ctx.Err().Error(), "Took too long") {
				return nil, ctx.Err()
			}
		}
		zerolog.Ctx(ctx).Warn().Int("retry_count", retryCount).Msg("Received nil response, retrying recursively")
		return s.sendRequestInternal(ctx, request, startTime, retryCount+1)
	}
	return response, nil
}

func OpenWebsocket(ctx context.Context, path string) (*websocket.Conn, *http.Response, error) {
	return OpenWebsocketURL(ctx, "wss://"+APIHostname+path)
}

func OpenWebsocketURL(ctx context.Context, url string) (*websocket.Conn, *http.Response, error) {
	opt := &websocket.DialOptions{
		HTTPClient: SignalHTTPClient,
		HTTPHeader: make(http.Header, 2),
	}
	opt.HTTPHeader.Set("User-Agent", UserAgent)
	opt.HTTPHeader.Set("X-Signal-Agent", SignalAgent)
	ws, resp, err := websocket.Dial(ctx, url, opt)
	if ws != nil {
		ws.SetReadLimit(1 << 20) // Increase read limit to 1MB from default of 32KB
	}
	return ws, resp, err
}

func CreateWSResponse(ctx context.Context, id uint64, status int) *signalpb.WebSocketMessage {
	if status != 200 && status != 400 {
		// TODO support more responses to Signal? Are there more?
		zerolog.Ctx(ctx).Fatal().Int("status", status).Msg("Error creating response. Non 200/400 not supported yet.")
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
