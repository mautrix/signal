package web

import (
	"context"
	"encoding/base64"
	"fmt"
	"log"
	"net/http"
	"sync"
	"time"

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
	mu                     sync.Mutex
	ws                     *websocket.Conn
	parentCtx              context.Context
	ctx                    context.Context
	cancel                 context.CancelFunc
	path                   string
	incomingRequestHandler RequestHandlerFunc
	responseChannels       map[uint64]chan *signalpb.WebSocketResponseMessage
	currentRequestId       uint64
}

func NewSignalWebsocket(ctx context.Context, path string, incomingRequestHandler RequestHandlerFunc) (*SignalWebsocket, error) {
	s := &SignalWebsocket{}
	s.path = path
	s.parentCtx = ctx
	s.incomingRequestHandler = incomingRequestHandler
	s.responseChannels = make(map[uint64]chan *signalpb.WebSocketResponseMessage)
	s.mu.Lock()
	err := s.connect()
	s.mu.Unlock()
	if err != nil {
		return nil, fmt.Errorf("Error connecting: %v", err)
	}
	go s.receiveLoop()
	// send a keepalive every 30s
	go func() {
		for {
			time.Sleep(30 * time.Second)
			s.mu.Lock()
			if s.ws != nil {
				err := s.ws.Ping(s.ctx)
				if err != nil {
					log.Printf("Error sending keepalive: %v", err)
				}
			}
			s.mu.Unlock()
		}
	}()
	return s, nil
}

// Error type for fatal error logging in
type SignalWebsocketConnectError struct {
	Err         error
	Status      int
	ShouldRetry bool
}

func (s *SignalWebsocket) connect() *SignalWebsocketConnectError {
	// If there's an existing connection, close it
	if s.ws != nil {
		err := s.ws.Close(websocket.StatusNormalClosure, "")
		if err != nil {
			log.Printf("Error closing websocket: %v", err)
		}
		s.cancel()
		s.ctx = nil
		s.cancel = nil
		s.ws = nil
	}
	// Make a new connection
	s.ctx, s.cancel = context.WithCancel(s.parentCtx)
	ws, resp, err := OpenWebsocket(s.ctx, s.path)
	if err != nil {
		return &SignalWebsocketConnectError{
			Err:         fmt.Errorf("Error opening websocket: %v", err),
			Status:      0,
			ShouldRetry: true,
		}
	}
	if resp.StatusCode != 101 {
		return &SignalWebsocketConnectError{
			Err:         fmt.Errorf("Bad status opening websocket: %v", resp.Status),
			Status:      resp.StatusCode,
			ShouldRetry: resp.StatusCode >= 500,
		}
	}
	s.ws = ws
	return nil
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

func CreateWSRequest(method string, path string, body []byte, requestId *uint64, username *string, password *string) *signalpb.WebSocketRequestMessage {
	request := &signalpb.WebSocketRequestMessage{
		Id:   requestId,
		Verb: &method,
		Path: &path,
		Body: body,
	}
	request.Headers = append(request.Headers, "Content-Type: application/json")
	if username != nil && password != nil {
		basicAuth := base64.StdEncoding.EncodeToString([]byte(*username + ":" + *password))
		request.Headers = append(request.Headers, "authorization:Basic "+basicAuth)
	}
	return request
}

func (s *SignalWebsocket) receiveLoop() {
	for {
		if s.ws == nil {
			log.Printf("No websocket, reconnecting")
			s.mu.Lock()
			connectErr := s.connect()
			if connectErr != nil {
				log.Printf("Error reconnecting: %v", connectErr)
				if !connectErr.ShouldRetry {
					log.Fatal("Fatal error, exiting")
				}
			}
			s.mu.Unlock()
			time.Sleep(30 * time.Second)
			continue
		}
		msg := &signalpb.WebSocketMessage{}
		err := wspb.Read(s.ctx, s.ws, msg)
		if err != nil {
			log.Printf("Error reading message: %v", err)
			s.mu.Lock()
			connectErr := s.connect()
			if connectErr != nil {
				log.Printf("Error reconnecting: %v", connectErr)
				if !connectErr.ShouldRetry {
					log.Fatal("Fatal error, exiting")
				}
			}
			s.mu.Unlock()
			time.Sleep(30 * time.Second)
			continue
		}
		if msg.Type == nil {
			log.Fatal("Received message with no type")
		} else if *msg.Type == signalpb.WebSocketMessage_REQUEST {
			if s.incomingRequestHandler == nil {
				log.Fatal("Received request with no handler")
			}
			if msg.Request == nil {
				log.Fatal("Received request with no request")
			}
			response, err := s.incomingRequestHandler(s.ctx, msg.Request)
			if err != nil {
				log.Printf("Error handling request: %v", err)
				continue
			}
			if response == nil {
				log.Printf("Error handling request: no response")
				continue
			}
			responseMessage := CreateWSResponse(*msg.Request.Id, response.Status)
			s.mu.Lock()
			err = wspb.Write(s.ctx, s.ws, responseMessage)
			s.mu.Unlock()
			if err != nil {
				log.Printf("Error writing response: %v", err)
				continue
			}
		} else if *msg.Type == signalpb.WebSocketMessage_RESPONSE {
			if msg.Response == nil {
				log.Fatal("Received response with no response")
			}
			if msg.Response.Id == nil {
				log.Fatal("Received response with no id")
			}
			s.mu.Lock()
			responseChannel, ok := s.responseChannels[*msg.Response.Id]
			if !ok {
				log.Printf("Received response with unknown id: %v", *msg.Response.Id)
				s.mu.Unlock()
				continue
			}
			responseChannel <- msg.Response
			delete(s.responseChannels, *msg.Response.Id)
			close(responseChannel)
			s.mu.Unlock()
		} else if *msg.Type == signalpb.WebSocketMessage_UNKNOWN {
			log.Printf("Received message with UNKNOWN type: %v", *msg.Type)
		} else {
			log.Printf("Received message with actually unknown type: %v", *msg.Type)
		}
	}
}

func (s *SignalWebsocket) SendRequest(ctx context.Context, request *signalpb.WebSocketRequestMessage, username *string, password *string) (<-chan *signalpb.WebSocketResponseMessage, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	if s.ws == nil {
		err := s.connect()
		if err != nil {
			return nil, err.Err
		}
	}
	request.Headers = append(request.Headers, "Content-Type: application/json")
	if username != nil && password != nil {
		basicAuth := base64.StdEncoding.EncodeToString([]byte(*username + ":" + *password))
		request.Headers = append(request.Headers, "authorization:Basic "+basicAuth)
	}
	msg_type := signalpb.WebSocketMessage_REQUEST
	message := &signalpb.WebSocketMessage{
		Type:    &msg_type,
		Request: request,
	}
	responseChannel := make(chan *signalpb.WebSocketResponseMessage, 1)
	s.currentRequestId++
	request.Id = &s.currentRequestId
	s.responseChannels[s.currentRequestId] = responseChannel
	err := wspb.Write(s.ctx, s.ws, message)
	if err != nil {
		close(responseChannel)
		return responseChannel, err
	}
	return responseChannel, nil
}

func (s *SignalWebsocket) Close() error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.ws != nil {
		err := s.ws.Close(websocket.StatusNormalClosure, "")
		if err != nil {
			return err
		}
		s.cancel()
		s.ctx = nil
		s.cancel = nil
		s.ws = nil
	}
	return nil
}
