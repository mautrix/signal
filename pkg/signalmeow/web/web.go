package web

import (
	"bytes"
	"crypto/tls"
	"crypto/x509"
	"io/ioutil"
	"net/http"
	"net/url"

	"github.com/rs/zerolog"
)

const proxyUrlStr = "" // Set this to proxy requests
const caCertPath = ""  // Set this to trust a self-signed cert (ie. for mitmproxy)

const UrlHost = "chat.signal.org"
const StorageUrlHost = "storage.signal.org"

// logging
var zlog zerolog.Logger = zerolog.New(zerolog.ConsoleWriter{}).With().Timestamp().Logger()

func SetLogger(l zerolog.Logger) {
	zlog = l
}

func proxiedHTTPClient() *http.Client {
	var proxyURL *url.URL
	if proxyUrlStr != "" {
		var err error
		proxyURL, err = url.Parse(proxyUrlStr)
		if err != nil {
			zlog.Err(err).Msg("Error parsing proxy URL")
			panic(err)
		}
	}

	tlsConfig := &tls.Config{}
	if caCertPath != "" {
		var caCert []byte
		var err error
		caCert, err = ioutil.ReadFile(caCertPath)
		if err != nil {
			zlog.Err(err).Msg("Error reading CA certificate")
			panic(err)
		}
		caCertPool := x509.NewCertPool()
		caCertPool.AppendCertsFromPEM(caCert)

		tlsConfig.RootCAs = caCertPool
	}

	// TODO: embed Signal's self-signed cert, and turn off InsecureSkipVerify
	tlsConfig.InsecureSkipVerify = true

	transport := &http.Transport{}
	if proxyURL != nil {
		transport.Proxy = http.ProxyURL(proxyURL)
	}
	transport.TLSClientConfig = tlsConfig

	client := &http.Client{
		Transport: transport,
	}
	return client
}

type HTTPReqOpt struct {
	Body      []byte
	Username  *string
	Password  *string
	RequestPB bool
	Host      string
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

	urlStr := "https://" + opt.Host + path
	req, err := http.NewRequest(method, urlStr, bytes.NewBuffer(opt.Body))
	if err != nil {
		zlog.Err(err).Msg("Error creating request")
		return nil, err
	}
	if opt.RequestPB {
		req.Header.Set("Content-Type", "application/x-protobuf")
	} else {
		req.Header.Set("Content-Type", "application/json")
	}
	// TODO: figure out what user agent to use
	//req.Header.Set("User-Agent", "SignalBridge/0.1")
	//req.Header.Set("X-Signal-Agent", "SignalBridge/0.1")
	if opt.Username != nil && opt.Password != nil {
		req.SetBasicAuth(*opt.Username, *opt.Password)
	}

	httpReqCounter++
	zlog.Debug().Msgf("Sending HTTP request %v, path: %s", httpReqCounter, path)
	client := proxiedHTTPClient()
	resp, err := client.Do(req)
	zlog.Debug().Msgf("Received HTTP response %v, status: %v", httpReqCounter, resp.StatusCode)
	return resp, err
}
