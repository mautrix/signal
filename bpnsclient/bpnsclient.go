package bpnsclient

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"sync"
	"time"

	"github.com/google/uuid"
	"github.com/rs/zerolog"
)

var (
	ErrBPNSUnauthorized       = errors.New("imat unauthorized")
	ErrBPNSUnknownDevice      = errors.New("device not registered on bpns")
	ErrBPNSConflict           = errors.New("registration conflict on bpns")
	ErrBPNSUnexpectedResponse = errors.New("unexpected error from bpns")
)

const bpnsMinKeepalive = time.Second * 1

type BPNSClient struct {
	log      *zerolog.Logger
	url      string
	imaToken string
	cfg      DeviceConfig
	cancel   context.CancelFunc
	wg       sync.WaitGroup
}

type FCMConfig struct {
	Token string `json:"token"`
}

type SignalConfig struct {
	AciUUID  string `json:"aci_uuid"`
	DeviceID int    `json:"device_id"`
	Password string `json:"password"`
}

type DeviceConfig struct {
	FCM    FCMConfig    `json:"fcm"`
	Signal SignalConfig `json:"signal,omitempty"`
}

type JSONDurationMs time.Duration

func (t *JSONDurationMs) UnmarshalJSON(data []byte) error {
	var value int64

	if err := json.Unmarshal(data, &value); err != nil {
		return err
	}

	*t = JSONDurationMs(value * int64(time.Millisecond))
	return nil
}

type KeepaliveResponse struct {
	Rate JSONDurationMs `json:"rate_ms"`
}

func NewBPNSClient(log *zerolog.Logger, url, imaToken, pushToken string, signalACI uuid.UUID, signalPassword string, deviceID int) *BPNSClient {
	deviceConfig := DeviceConfig{
		FCM: FCMConfig{
			Token: pushToken,
		},
		Signal: SignalConfig{
			AciUUID:  signalACI.String(),
			Password: signalPassword,
			DeviceID: deviceID,
		},
	}

	return &BPNSClient{
		log:      log,
		url:      url,
		imaToken: imaToken,
		cfg:      deviceConfig,
	}
}

func (bpns *BPNSClient) request(ctx context.Context, method, endpoint string, body any) (*http.Response, error) {
	var bodyReader io.Reader

	if body != nil {
		data, err := json.Marshal(body)
		if err != nil {
			return nil, err
		}

		bodyReader = bytes.NewReader(data)
	}

	req, err := http.NewRequestWithContext(ctx, method, fmt.Sprintf("%s/v1/signal/%s", bpns.url, endpoint), bodyReader)
	if err != nil {
		return nil, err
	}

	req.Header.Set("Authorization", "Bearer "+bpns.imaToken)
	req.Header.Set("User-Agent", "signal")

	normalTransport := &http.Transport{
		DialContext:           (&net.Dialer{Timeout: 10 * time.Second}).DialContext,
		ForceAttemptHTTP2:     true,
		TLSHandshakeTimeout:   10 * time.Second,
		ResponseHeaderTimeout: 5 * time.Second,
	}
	normalClient := &http.Client{
		Timeout:   1 * time.Minute,
		Transport: normalTransport,
	}
	resp, err := normalClient.Do(req)
	if err != nil {
		bpns.log.Trace().Err(err).Stringer("url", req.URL).Str("method", method).Msg("bpns Request Error")
	} else {
		bpns.log.Trace().Stringer("url", req.URL).Str("method", method).Str("status", resp.Status).Msg("bpns Request")
	}

	return resp, err
}

func (bpns *BPNSClient) register(ctx context.Context) (time.Duration, error) {
	resp, err := bpns.request(ctx, http.MethodPut, "device", &bpns.cfg)
	if err != nil {
		return 0, err
	}

	switch resp.StatusCode {
	case http.StatusCreated:
		return decodeKeepaliveRate(resp)
	case http.StatusConflict:
		return 0, ErrBPNSConflict
	case http.StatusUnauthorized:
		return 0, ErrBPNSUnauthorized
	default:
		return 0, fmt.Errorf("%w: register returned unexpected status %d", ErrBPNSUnexpectedResponse, resp.StatusCode)
	}
}

func decodeKeepaliveRate(resp *http.Response) (rate time.Duration, err error) {
	if resp.Body == nil {
		return
	}

	var keepaliveResp KeepaliveResponse
	if err = json.NewDecoder(resp.Body).Decode(&keepaliveResp); err != nil {
		return
	}

	rate = time.Duration(keepaliveResp.Rate)
	return
}

func (bpns *BPNSClient) keepalive(ctx context.Context) (time.Duration, error) {
	resp, err := bpns.request(ctx, http.MethodPost, "keepalive", nil)
	if err != nil {
		return 0, err
	}

	switch resp.StatusCode {
	case http.StatusOK:
		return decodeKeepaliveRate(resp)
	case http.StatusNoContent:
		return 0, nil
	case http.StatusUnauthorized:
		return 0, ErrBPNSUnauthorized
	case http.StatusNotFound:
		return 0, ErrBPNSUnknownDevice
	default:
		return 0, fmt.Errorf("%w: keepalive returned unexpected status %d", ErrBPNSUnexpectedResponse, resp.StatusCode)
	}
}

func (bpns *BPNSClient) yield(ctx context.Context) error {
	resp, err := bpns.request(ctx, http.MethodPost, "yield", nil)
	if err != nil {
		return err
	}

	switch resp.StatusCode {
	case http.StatusNoContent:
		return nil
	case http.StatusUnauthorized:
		return ErrBPNSUnauthorized
	case http.StatusNotFound:
		return ErrBPNSUnknownDevice
	default:
		return fmt.Errorf("%w: yield returned unexpected status %d", ErrBPNSUnexpectedResponse, resp.StatusCode)
	}
}

func (bpns *BPNSClient) keepaliveOrRegister(ctx context.Context) (time.Duration, error) {
	rate, err := bpns.keepalive(ctx)

	if err == ErrBPNSUnknownDevice {
		rate, err = bpns.register(ctx)
	}

	return rate, err
}

func (bpns *BPNSClient) Start(ctx context.Context) {
	if bpns.cancel != nil {
		bpns.log.Debug().Msg("Start() called when already running")
		return
	}

	if bpns.url == "" {
		bpns.log.Warn().Msg("No URL set, bpns disabled")
		return
	}

	// we need to run once with start context to make bpns disconnect from remote network immediately
	rate, err := bpns.keepaliveOrRegister(ctx)
	if err != nil {
		bpns.log.Warn().Err(err).Msg("Unexpected bpns error during start")
		// first successful keepalive will reset the ticker
		rate = time.Second * 30
	} else if rate == 0 {
		bpns.log.Warn().Msg("Server requested we don't do keepalives, not starting loop")
		return
	} else if rate < bpnsMinKeepalive {
		bpns.log.Warn().Dur("rate_req", rate).Dur("rate_min", bpnsMinKeepalive).Msg("Server requested keepalive time less than allowed, using ours")
		rate = bpnsMinKeepalive
	}

	bpns.log.Info().Str("url", bpns.url).Dur("rate", rate).Msg("Starting bpns loop")

	ctx, bpns.cancel = context.WithCancel(context.Background())

	bpns.wg.Add(1)
	go func() {
		defer func() {
			bpns.wg.Done()
			bpns.log.Trace().Msg("Leaving bpns loop")
		}()

		ticker := time.NewTicker(rate)
		for {
			select {
			case <-ticker.C:
				newRate, err := bpns.keepaliveOrRegister(ctx)
				if errors.Is(err, context.Canceled) {
					return
				} else if err != nil {
					bpns.log.Warn().Err(err).Msg("Unexpected bpns error")
				} else if newRate == 0 {
					bpns.log.Warn().Msg("Keepalive returned zero rate, stopping loop")
					return
				} else if newRate > bpnsMinKeepalive && newRate != rate {
					bpns.log.Info().Dur("rate_new", newRate).Dur("rate_old", rate).Msg("Keepalive rate changed by bpns")
					rate = newRate
					ticker.Reset(rate)
				}
			case <-ctx.Done():
				return
			}
		}
	}()
}

func (bpns *BPNSClient) Stop(ctx context.Context) {
	if bpns.cancel == nil {
		return
	}

	bpns.log.Info().Msg("Stopping bpns loop")

	bpns.Close()

	// send yield before returning
	bpns.log.Debug().Msg("Sending final yield")
	err := bpns.yield(ctx)
	if err != nil {
		bpns.log.Err(err).Msg("Final yield failed")
	} else {
		bpns.log.Info().Msg("Yielded bpns connection")
	}
}

func (bpns *BPNSClient) Close() {
	if bpns.cancel == nil {
		return
	}

	bpns.cancel()
	bpns.cancel = nil
	bpns.wg.Wait()
}

func (bpns *BPNSClient) Deregister(ctx context.Context) error {
	_, err := bpns.request(ctx, http.MethodDelete, "device", &bpns.cfg)
	return err
}

func (bpns *BPNSClient) IsUsingSignalACI(aci uuid.UUID) bool {
	return uuid.MustParse(bpns.cfg.Signal.AciUUID) == aci
}

func (bpns *BPNSClient) IsUsingFCMPushToken(token string) bool {
	return bpns.cfg.FCM.Token == token
}
