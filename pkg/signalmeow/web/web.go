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
	"bytes"
	"crypto/tls"
	"crypto/x509"
	_ "embed"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"os"

	"github.com/rs/zerolog"
	"github.com/rs/zerolog/log"
)

const proxyUrlStr = "" // Set this to proxy requests
const caCertPath = ""  // Set this to trust a self-signed cert (ie. for mitmproxy)

const (
	UrlHost        = "chat.signal.org"
	StorageUrlHost = "storage.signal.org"
	CDNUrlHost     = "cdn.signal.org"
	CDN2UrlHost    = "cdn2.signal.org"
)

var CDNHosts = []string{
	CDNUrlHost,
	CDNUrlHost,
	CDN2UrlHost,
}

// logging
var zlog zerolog.Logger = zerolog.New(zerolog.ConsoleWriter{}).With().Timestamp().Logger()

func SetLogger(l zerolog.Logger) {
	zlog = l
}

//go:embed signal-root.crt.der
var signalRootCertBytes []byte
var signalTransport = &http.Transport{
	ForceAttemptHTTP2: true,
	TLSClientConfig: &tls.Config{
		RootCAs: x509.NewCertPool(),
	},
}
var signalHTTPClient = &http.Client{
	Transport: signalTransport,
}

func init() {
	cert, err := x509.ParseCertificate(signalRootCertBytes)
	if err != nil {
		panic(err)
	}
	signalTransport.TLSClientConfig.RootCAs.AddCert(cert)

	if proxyUrlStr != "" {
		proxyURL, err := url.Parse(proxyUrlStr)
		if err != nil {
			panic(err)
		}
		signalTransport.Proxy = http.ProxyURL(proxyURL)
	}
	if caCertPath != "" {
		caCert, err := os.ReadFile(caCertPath)
		if err != nil {
			panic(err)
		}
		signalTransport.TLSClientConfig.RootCAs.AppendCertsFromPEM(caCert)
	}
}

type ContentType string

const (
	ContentTypeJSON        ContentType = "application/json"
	ContentTypeProtobuf    ContentType = "application/x-protobuf"
	ContentTypeOctetStream ContentType = "application/octet-stream"
)

type HTTPReqOpt struct {
	Body        []byte
	Username    *string
	Password    *string
	ContentType ContentType
	Host        string
	Headers     map[string]string
	OverrideURL string // Override the full URL, if set ignores path and Host
}

var httpReqCounter = 0

func SendHTTPRequest(method string, path string, opt *HTTPReqOpt) (*http.Response, error) {
	// Set defaults
	if opt == nil {
		opt = &HTTPReqOpt{}
	}
	if opt.Host == "" {
		opt.Host = UrlHost
	}
	if len(path) > 0 && path[0] != '/' {
		path = "/" + path
	}
	urlStr := "https://" + opt.Host + path
	if opt.OverrideURL != "" {
		urlStr = opt.OverrideURL
	}

	req, err := http.NewRequest(method, urlStr, bytes.NewBuffer(opt.Body))
	if err != nil {
		zlog.Err(err).Msg("Error creating request")
		return nil, err
	}
	if opt.Headers != nil {
		for k, v := range opt.Headers {
			req.Header.Add(k, v)
		}
	}
	if opt.ContentType != "" {
		req.Header.Set("Content-Type", string(opt.ContentType))
	} else {
		req.Header.Set("Content-Type", string(ContentTypeJSON))
	}
	req.Header.Set("Content-Length", fmt.Sprintf("%d", len(opt.Body)))
	// TODO: figure out what user agent to use
	//req.Header.Set("User-Agent", "SignalBridge/0.1")
	//req.Header.Set("X-Signal-Agent", "SignalBridge/0.1")
	if opt.Username != nil && opt.Password != nil {
		req.SetBasicAuth(*opt.Username, *opt.Password)
	}

	httpReqCounter++
	zlog.Debug().Msgf("Sending HTTP request %v, %v url: %s", httpReqCounter, method, urlStr)
	resp, err := signalHTTPClient.Do(req)
	if err != nil {
		zlog.Err(err).Msg("Error sending request")
		return nil, err
	}
	zlog.Debug().Msgf("Received HTTP response %v, status: %v", httpReqCounter, resp.StatusCode)
	return resp, nil
}

// DecodeHTTPResponseBody checks status code, reads an http.Response's Body and decodes it into the provided interface.
func DecodeHTTPResponseBody(out interface{}, resp *http.Response) error {
	defer resp.Body.Close()

	// Check if status code indicates success
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		// Read the whole body and log it
		buf := new(bytes.Buffer)
		buf.ReadFrom(resp.Body)
		body := buf.String()
		log.Debug().Msgf("Response body: %v", body)
		return fmt.Errorf("Unexpected status code: %d %s", resp.StatusCode, resp.Status)
	}

	decoder := json.NewDecoder(resp.Body)
	if err := decoder.Decode(&out); err != nil {
		return fmt.Errorf("JSON decoding failed: %w", err)
	}

	return nil
}

// Download an attachment from the CDN
func GetAttachment(path string, cdnNumber uint32, opt *HTTPReqOpt) (*http.Response, error) {
	if opt == nil {
		opt = &HTTPReqOpt{}
	}
	if opt.Host == "" {
		if cdnNumber == 0 {
			// This is basically a fallback if cdnNumber is not set
			// but it also seems to be the right host if cdnNumber == 0
			opt.Host = CDNHosts[0]
		} else if cdnNumber > 0 && int(cdnNumber) <= len(CDNHosts) {
			// Pull CDN hosts from array (cdnNumber is 1-indexed, but we have a placeholder host at index 0)
			// (the 1-indexed is just an assumption, other clients seem to only explicitly handle cdnNumber == 0 and 2)
			opt.Host = CDNHosts[cdnNumber]
		} else {
			opt.Host = CDNHosts[0]
			log.Warn().Msgf("Invalid CDN index %v, using %s", cdnNumber, opt.Host)
		}
	}
	urlStr := "https://" + opt.Host + path
	req, err := http.NewRequest("GET", urlStr, nil)

	//const SERVICE_REFLECTOR_HOST = "europe-west1-signal-cdn-reflector.cloudfunctions.net"
	//req.Header.Add("Host", SERVICE_REFLECTOR_HOST)
	req.Header.Add("Content-Type", "application/octet-stream")

	httpReqCounter++
	zlog.Debug().Msgf("Sending Attachment HTTP request %v, url: %s", httpReqCounter, urlStr)
	resp, err := signalHTTPClient.Do(req)
	zlog.Debug().Msgf("Received Attachment HTTP response %v, status: %v", httpReqCounter, resp.StatusCode)

	return resp, err
}

// Upload an attachment to the CDN
//func PutAttachment(
