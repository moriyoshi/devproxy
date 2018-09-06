/*
 * Copyright (c) 2016 Moriyoshi Koizumi
 * Copyright (c) 2012 Elazar Leibovich.
 * Copyright (c) 2012 The Go Authors.
 *
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are
 * met:
 *
 *    * Redistributions of source code must retain the above copyright
 * notice, this list of conditions and the following disclaimer.
 *    * Redistributions in binary form must reproduce the above
 * copyright notice, this list of conditions and the following disclaimer
 * in the documentation and/or other materials provided with the
 * distribution.
 *    * Neither the name of Elazar Leibovich. nor the names of its
 * contributors may be used to endorse or promote products derived from
 * this software without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
 * "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
 * LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR
 * A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT
 * OWNER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
 * SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT
 * LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
 * DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
 * THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
 * (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
 * OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 */
package main

import (
	"bufio"
	"crypto/tls"
	"encoding/base64"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/textproto"
	"net/url"
	"strings"
	"sync/atomic"
	"time"

	"github.com/Sirupsen/logrus"
	"github.com/moriyoshi/devproxy/httpx"
	"github.com/pkg/errors"
)

type ResponseFilter interface {
	Filter(*http.Response, *OurProxyCtx) (*http.Response, error)
}

type OurProxyHttpServer struct {
	Ctx              *DevProxy
	Logger           *logrus.Logger
	Tr               *httpx.Transport
	TLSConfigFactory TLSConfigFactory
	ResponseFilters  []ResponseFilter
	SessionSerial    int64
}

type OurProxyCtx struct {
	Proxy           *OurProxyHttpServer
	Logger          *logrus.Logger
	OrigReq         *http.Request
	Req             *http.Request
	OrigResp        *http.Response
	Resp            *http.Response
	Tr              *httpx.Transport
	ResponseFilters []ResponseFilter
	Error           error
	Session         int64
}

type ResponseWriter struct {
	conn                   net.Conn
	brw                    *bufio.ReadWriter
	header                 http.Header
	headerWritten          bool
	protoMajor, protoMinor int
}

func makeHttp10Response(header string, body string) string {
	return header + "\r\n" + fmt.Sprintf("Content-Length: %d\r\n", len(body)) + "Connection: close\r\n\r\n" + body
}

/* --- BEGIN pasted from src/net/http/header.go -- */

func isTokenBoundary(b byte) bool {
	return b == ' ' || b == ',' || b == '\t'
}

// hasToken reports whether token appears with v, ASCII
// case-insensitive, with space or comma boundaries.
// token must be all lowercase.
// v may contain mixed cased.
func hasToken(v, token string) bool {
	if len(token) > len(v) || token == "" {
		return false
	}
	if v == token {
		return true
	}
	for sp := 0; sp <= len(v)-len(token); sp++ {
		// Check that first character is good.
		// The token is ASCII, so checking only a single byte
		// is sufficient. We skip this potential starting
		// position if both the first byte and its potential
		// ASCII uppercase equivalent (b|0x20) don't match.
		// False positives ('^' => '~') are caught by EqualFold.
		if b := v[sp]; b != token[0] && b|0x20 != token[0] {
			continue
		}
		// Check that start pos is on a valid token boundary.
		if sp > 0 && !isTokenBoundary(v[sp-1]) {
			continue
		}
		// Check that end pos is on a valid token boundary.
		if endPos := sp + len(token); endPos != len(v) && !isTokenBoundary(v[endPos]) {
			continue
		}
		if strings.EqualFold(v[sp:sp+len(token)], token) {
			return true
		}
	}
	return false
}

/* --- END pasted from src/net/http/client.go -- */

func isWebSocketReq(req *http.Request) bool {
	connHdr := req.Header.Get("Connection")
	if hasToken(connHdr, "upgrade") {
		upgradeHdr := req.Header.Get("Upgrade")
		if strings.ToLower(upgradeHdr) == "websocket" {
			return true
		}
	}
	return false
}

func removeProxyHeaders(r *http.Request) {
	r.RequestURI = ""
	r.Header.Del("Proxy-Connection")
	r.Header.Del("Proxy-Authenticate")
	r.Header.Del("Proxy-Authorization")
}

func translateToWebsocketURL(u *url.URL) *url.URL {
	v := *u
	switch u.Scheme {
	case "http":
		v.Scheme = "ws"
	case "https":
		v.Scheme = "wss"
	default:
		return nil
	}
	return &v
}

var contentTypeKey = http.CanonicalHeaderKey("Content-Type")

var http10BadGatewayBytes = []byte(makeHttp10Response("HTTP/1.0 502 Bad Gateway", "<html><body><h1>Bad Gateway</h1></body></html>"))
var http10OkBytes = []byte("HTTP/1.0 200 OK\r\n\r\n")

func NewResponseWriter(conn net.Conn, protoMajor, protoMinor int) *ResponseWriter {
	return &ResponseWriter{
		conn:   conn,
		header: make(http.Header),
		brw: bufio.NewReadWriter(
			bufio.NewReader(conn),
			bufio.NewWriter(conn),
		),
		protoMajor: protoMajor,
		protoMinor: protoMinor,
	}
}

func (rw *ResponseWriter) Header() http.Header {
	return rw.header
}

func (rw *ResponseWriter) Write(b []byte) (int, error) {
	if !rw.headerWritten {
		rw.WriteHeader(http.StatusOK)
	}
	return rw.Write(b)
}

func (rw *ResponseWriter) WriteHeader(statusCode int) {
	if rw.writeHeader(statusCode) != nil {
		return
	}
	rw.headerWritten = true
}

func (rw *ResponseWriter) writeHeader(statusCode int) error {
	statusText := http.StatusText(statusCode)
	if statusText == "" {
		statusText = fmt.Sprintf("status code %d", statusCode)
	}
	_, err := fmt.Fprintf(rw.brw, "HTTP/%d.%d %03d %s\r\n", rw.protoMajor, rw.protoMinor, statusCode, statusText)
	if err != nil {
		return errors.Wrapf(err, "failed to send HTTP status header")
	}
	err = rw.header.Write(rw.brw)
	if err != nil {
		return errors.Wrapf(err, "failed to send HTTP headers")
	}
	_, err = rw.brw.WriteString("\r\n")
	if err != nil {
		return errors.Wrapf(err, "failed to send HTTP header epilogue")
	}
	return nil
}

func (rw *ResponseWriter) Hijack() (net.Conn, *bufio.ReadWriter, error) {
	return rw.conn, rw.brw, nil
}

func (proxyCtx *OurProxyCtx) NewTLSConfig(r *http.Request) (*tls.Config, error) {
	return proxyCtx.Proxy.TLSConfigFactory(r.URL.Host, proxyCtx)
}

func (proxyCtx *OurProxyCtx) FilterRequest(r *http.Request) (req *http.Request, resp *http.Response) {
	for _, perHostConfig := range proxyCtx.Proxy.Ctx.Config.Hosts {
		if proxyCtx.Proxy.Ctx.checkIfRequestMatchesToUrl(perHostConfig.Host, false, r, proxyCtx) {
			return FilterRequest(perHostConfig, r, proxyCtx)
		}
	}
	return r, nil
}

func (proxyCtx *OurProxyCtx) FilterResponse(resp *http.Response) *http.Response {
	proxyCtx.Logger.Debugf("applying %d response filters", len(proxyCtx.ResponseFilters))
	for _, f := range proxyCtx.ResponseFilters {
		newResp, err := f.Filter(resp, proxyCtx)
		if err != nil {
			proxyCtx.Logger.Errorf("failed to run the response filter: %s", err.Error())
			return proxyCtx.OrigResp
		}
		proxyCtx.Resp = newResp
		resp = newResp
	}
	return resp
}

func (proxy *OurProxyHttpServer) HandleNonProxyRequest(w http.ResponseWriter, r *http.Request) {
	http.Error(w, "This is a proxy server. Does not respond to non-proxy requests.", 400)
}

/* --- BEGIN pasted from src/net/http/client.go -- */
// cancelTimerBody is an io.ReadCloser that wraps rc with two features:
// 1) on Read EOF or Close, the timer t is Stopped,
// 2) On Read failure, if reqWasCanceled is true, the error is wrapped and
//    marked as net.Error that hit its timeout.
type cancelTimerBody struct {
	t        *time.Timer
	rc       io.ReadCloser
	canceled *int32
}

func (b *cancelTimerBody) Read(p []byte) (n int, err error) {
	n, err = b.rc.Read(p)
	if err == io.EOF {
		b.t.Stop()
	} else if err != nil && atomic.LoadInt32(b.canceled) != 0 {
		return n, errors.Wrapf(err, "timeout exceeded")
	}
	return
}

func (b *cancelTimerBody) Close() error {
	err := b.rc.Close()
	b.t.Stop()
	return err
}

/* --- END pasted from src/net/http/client.go -- */

func (proxyCtx *OurProxyCtx) DoRequest(req *http.Request, respW http.ResponseWriter, timeout time.Duration) (*http.Response, error) {
	defer func() {
		if req.Body != nil {
			req.Body.Close()
		}
	}()

	if isWebSocketReq(req) {
		proxyCtx.Logger.Debugf("Handling WebSocket Handshake: %v", req.URL)
		cm, err := proxyCtx.Tr.ConnectMethodForRequest(&httpx.TransportRequest{req, nil})
		if err != nil {
			return nil, errors.Wrapf(err, "failed to create a ConnectMethod struct")
		}
		obConn, _, err := proxyCtx.Tr.DoDial(cm)
		if err != nil {
			return nil, errors.Wrapf(err, "failed to dial to remote server")
		}
		err = req.Write(obConn)
		if err != nil {
			obConn.Close()
			return nil, err
		}
		hijacker, ok := respW.(http.Hijacker)
		if !ok {
			obConn.Close()
			return nil, errors.Errorf("responseWriter does not implement http.Hijacker")
		}
		ibConn, brw, err := hijacker.Hijack()
		if err != nil {
			obConn.Close()
			return nil, err
		}
		err = brw.Flush()
		if err != nil {
			ibConn.Close()
			obConn.Close()
			return nil, err
		}
		if brw.Reader.Buffered() > 0 {
			ibConn.Close()
			obConn.Close()
			return nil, errors.Errorf("client sent data before handshake is complete")
		}
		proxyCtx.Logger.Debugf("Established bidi tunnel between %v and %v", obConn.RemoteAddr(), ibConn.RemoteAddr())
		proxyCtx.Proxy.Ctx.bidiTunnel(obConn, ibConn)
		proxyCtx.Logger.Debugf("Discarded bidi tunnel between %v and %v", obConn.RemoteAddr(), ibConn.RemoteAddr())
		return nil, nil
	} else {
		timer := (*time.Timer)(nil)
		canceled := int32(0)

		if timeout > 0 {
			timer = time.AfterFunc(timeout, func() {
				atomic.StoreInt32(&canceled, 1)
				proxyCtx.Tr.CancelRequest(req)
			})
		}

		resp, err := proxyCtx.Tr.RoundTrip(req)
		if err != nil {
			if atomic.LoadInt32(&canceled) != 0 {
				return nil, errors.Wrapf(err, "timeout exceeded")
			}
			return nil, errors.Wrapf(err, "failed to do the roundtrip")
		}

		if timer != nil {
			resp.Body = &cancelTimerBody{
				t:        timer,
				rc:       resp.Body,
				canceled: &canceled,
			}
		}
		return resp, nil
	}
}

func (proxyCtx *OurProxyCtx) HandleConnect(r *http.Request, proxyClient net.Conn) {
	var targetHostPort string
	{
		pair := splitHostPort(r.URL.Host)
		if pair.Port == "" {
			pair.Port = "443" // this may be a bad assumption
		}
		targetHostPort = pair.String()
	}

	for _, perHostConfig := range proxyCtx.Proxy.Ctx.Config.Hosts {
		if proxyCtx.Proxy.Ctx.checkIfTunnelRequestMatchesToUrl(perHostConfig.Host, r, proxyCtx) {
			tlsConfig, err := proxyCtx.NewTLSConfig(r)
			if err != nil {
				proxyCtx.Logger.Errorf("failed to create tls.Config (%s)", err.Error())
				if _, err := proxyClient.Write(http10BadGatewayBytes); err != nil {
					proxyCtx.Logger.Errorf("failed to send response to client (%s)", err.Error())
				}
				return
			}

			_, err = proxyClient.Write(http10OkBytes)
			if err != nil {
				proxyCtx.Logger.Errorf("failed to send response to client (%s)", err.Error())
				return
			}
			clientTlsConn := tls.Server(proxyClient, tlsConfig)
			err = clientTlsConn.Handshake()
			if err != nil {
				proxyCtx.Logger.Errorf("TLS handshake with the client failed (%s)", err.Error())
				return
			}
			defer func() {
				if err := clientTlsConn.Close(); err != nil {
					proxyCtx.Logger.Warnf("failed to close connection (%s)", err.Error())
				}
			}()

			clientBufReader := bufio.NewReader(clientTlsConn)
			req, err := http.ReadRequest(clientBufReader)
			if err != nil {
				proxyCtx.Logger.Errorf("failed to read request from the target (%s)", err.Error())
				if _, err := clientTlsConn.Write(http10BadGatewayBytes); err != nil {
					proxyCtx.Logger.Errorf("failed to send response to client (%s)", err.Error())
				}
				return
			}

			nestedProxyCtx := new(OurProxyCtx)
			*nestedProxyCtx = *proxyCtx
			nestedProxyCtx.OrigReq = req
			nestedProxyCtx.Req = req

			req.URL.Scheme = "https"
			req.URL.Host = targetHostPort
			req.RequestURI = req.URL.String()
			req, resp := FilterRequest(perHostConfig, req, nestedProxyCtx)
			nestedProxyCtx.Req = req

			if resp == nil {
				removeProxyHeaders(req)
				respW := NewResponseWriter(clientTlsConn, req.ProtoMajor, req.ProtoMinor)
				resp, err = nestedProxyCtx.DoRequest(req, respW, 0)
				if err != nil {
					nestedProxyCtx.Logger.Errorf("failed to read response from the target (%s)", err.Error())
					if _, err := clientTlsConn.Write(http10BadGatewayBytes); err != nil {
						nestedProxyCtx.Logger.Errorf("failed to send response to client (%s)", err.Error())
					}
					return
				}
			}
			nestedProxyCtx.OrigResp = resp
			resp = nestedProxyCtx.FilterResponse(resp)
			resp.ContentLength = -1
			if resp.Header != nil {
				resp.Header.Del("Content-Length")
			}
			err = resp.Write(clientTlsConn)
			if err != nil {
				nestedProxyCtx.Logger.Errorf("failed to send response to the client (%s)", err.Error())
			}
			return
		}
	}

	proxyCtx.Logger.Debugf("Connecting to %s", targetHostPort)
	targetConn, err := proxyCtx.Proxy.ConnectDial(targetHostPort)
	if err != nil {
		proxyCtx.Logger.Errorf("failed to connect to %s (%s)", targetHostPort, err.Error())
		if _, err := proxyClient.Write(http10BadGatewayBytes); err != nil {
			proxyCtx.Logger.Errorf("failed to send response to client (%s)", err.Error())
		}
		return
	}
	defer func() {
		if err := targetConn.Close(); err != nil {
			proxyCtx.Logger.Warnf("failed to close connection (%s)", err.Error())
		}
	}()
	_, err = proxyClient.Write(http10OkBytes)
	if err != nil {
		proxyCtx.Logger.Errorf("failed to send response to client (%s)", err.Error())
		return
	}
	proxyCtx.Proxy.Ctx.bidiTunnel(proxyClient, targetConn)
}

func (proxyCtx *OurProxyCtx) SendToClient(w http.ResponseWriter, resp *http.Response) {
	dest := w.Header()
	for headerName, headerValues := range resp.Header {
		dest[headerName] = headerValues
	}
	w.WriteHeader(resp.StatusCode)
	nr, err := io.Copy(w, resp.Body)
	if err := resp.Body.Close(); err != nil {
		proxyCtx.Logger.Warnf("Can't close response body %v", err)
	}
	proxyCtx.Logger.Debugf("Copied %v bytes to client error=%v", nr, err)
}

func (proxy *OurProxyHttpServer) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	proxyCtx := &OurProxyCtx{
		Proxy:           proxy,
		Logger:          proxy.Logger,
		OrigReq:         r,
		Req:             r,
		OrigResp:        nil,
		Resp:            nil,
		Session:         atomic.AddInt64(&proxy.SessionSerial, 1),
		Tr:              proxy.Tr,
		ResponseFilters: proxy.ResponseFilters,
	}
	if r.Method == "CONNECT" {
		hij, ok := w.(http.Hijacker)
		if !ok {
			proxy.Logger.Error("Connection hijacking is not supported")
			http.Error(w, "CONNECT not supported", 400)
			return
		}
		proxyClient, _, err := hij.Hijack()
		if err != nil {
			proxy.Logger.Errorf("Failed to hijack the connection (%s)", err.Error())
			http.Error(w, "CONNECT not supported", 400)
		}
		proxyCtx.HandleConnect(r, proxyClient)
	} else {
		var err error
		proxy.Logger.Debugf("Got request %v %v %v %v", r.URL.Path, r.Host, r.Method, r.URL.String())
		if !r.URL.IsAbs() {
			proxy.HandleNonProxyRequest(w, r)
			return
		}
		r, resp := proxyCtx.FilterRequest(r)
		proxyCtx.Req = r
		if resp == nil {
			removeProxyHeaders(r)
			resp, err = proxyCtx.DoRequest(r, w, 0)
			if err != nil {
				proxyCtx.Logger.Errorf("Error occurred during handling request: %v", err)
				proxyCtx.Error = err
				resp = proxyCtx.FilterResponse(nil)
				if resp == nil {
					http.Error(w, err.Error(), 500)
					return
				}
			}
			if resp != nil {
				proxyCtx.Logger.Debugf("Received response %v", resp.Status)
			}
		}
		proxyCtx.OrigResp = resp
		if resp != nil {
			resp = proxyCtx.FilterResponse(resp)
			resp.ContentLength = -1
			if resp.Header != nil {
				resp.Header.Del("Content-Length")
			}
			proxyCtx.Logger.Debugf("Copying response to client %v [%d]", resp.Status, resp.StatusCode)
			proxyCtx.SendToClient(w, resp)
		} else {
			proxyCtx.Logger.Debugf("No response is available")
		}
	}
}

func buildFakeHTTPSRequestFromHostPortPair(addr string) *http.Request {
	return &http.Request{
		URL: &url.URL{
			Scheme:   "https",
			Opaque:   "",
			User:     nil,
			Host:     addr,
			Path:     "",
			RawPath:  "",
			RawQuery: "",
			Fragment: "",
		},
	}
}

func (proxy *OurProxyHttpServer) doDial(addr string) (net.Conn, error) {
	if proxy.Tr.Dial != nil {
		return proxy.Tr.Dial("tcp", addr)
	}
	return net.Dial("tcp", addr)
}

func (proxy *OurProxyHttpServer) doDialTLS(addr HostPortPair, tlsConfigTemplate *tls.Config) (net.Conn, error) {
	if tlsConfigTemplate == nil {
		if proxy.Tr.DialTLS != nil {
			return proxy.Tr.DialTLS("tcp", addr.String())
		}
		tlsConfigTemplate = proxy.Tr.TLSClientConfig
	}
	conn, err := net.Dial("tcp", addr.String())
	if err != nil {
		return nil, errors.Wrapf(err, "failed to connect to %v", addr)
	}
	tlsConfig := new(tls.Config)
	*tlsConfig = *tlsConfigTemplate
	tlsConfig.ServerName = addr.Host
	return tls.Client(conn, tlsConfig), nil
}

func buildProxyRequestFromProxyURL(proxyUrl *url.URL, addr string) *http.Request {
	retval := &http.Request{
		Method: "CONNECT",
		URL:    &url.URL{Opaque: addr},
		Host:   addr,
		Header: http.Header{},
	}
	if proxyUrl.User != nil {
		retval.Header.Set(
			"Proxy-Authorization",
			fmt.Sprintf(
				"Basic %s",
				base64.StdEncoding.EncodeToString([]byte(proxyUrl.User.String())), // UTF-8
			),
		)
	}
	return retval
}

func (proxy *OurProxyHttpServer) ConnectDial(addr string) (net.Conn, error) {
	proxyUrl, proxyTlsConfig, err := proxy.Tr.Proxy2(buildFakeHTTPSRequestFromHostPortPair(addr))
	if err != nil {
		return nil, errors.Wrapf(err, "failed to connect to %s", addr)
	}
	if proxyUrl != nil {
		proxyHostPortPair, err := toHostPortPair(proxyUrl)
		if err != nil {
			return nil, errors.Wrapf(err, "failed to parse %v as a proxy URL", proxyUrl)
		}
		proxyRequest := buildProxyRequestFromProxyURL(proxyUrl, addr)
		var conn net.Conn
		if proxyUrl.Scheme == "https" {
			conn, err = proxy.doDialTLS(proxyHostPortPair, proxyTlsConfig)
			if err != nil {
				return nil, errors.Wrapf(err, "failed to establish TLS connection to %v", proxyUrl)
			}
		} else {
			conn, err = proxy.doDial(proxyHostPortPair.String())
			if err != nil {
				return nil, errors.Wrapf(err, "failed to connect to %v", proxyHostPortPair)
			}
		}
		somethingWentWrong := true // always be prepared to something bad
		defer func() {
			if somethingWentWrong {
				conn.Close()
			}
		}()
		proxyRequest.Write(conn)
		br := bufio.NewReader(conn)
		resp, err := http.ReadResponse(br, proxyRequest)
		if err != nil {
			return nil, errors.Wrapf(err, "failed to read response")
		}
		if resp.StatusCode != 200 {
			return nil, errors.Errorf("proxy server %s returned error status (%d) for tunneling request to %s", proxyUrl.String(), resp.StatusCode, addr)
		}
		somethingWentWrong = false // we are safe
		return conn, nil
	} else {
		return proxy.doDial(addr)
	}
}

func CloneHeader(orig http.Header) http.Header {
	newHeader := make(http.Header)
	for headerName, headerValues := range orig {
		header := make([]string, len(headerValues))
		for i, headerValue := range headerValues {
			header[i] = headerValue
		}
		newHeader[headerName] = header
	}
	return newHeader
}

func CloneRequest(r *http.Request) *http.Request {
	newRequest := new(http.Request)
	*newRequest = *r
	newRequest.URL = new(url.URL)
	*newRequest.URL = *r.URL
	if r.Header != nil {
		newRequest.Header = CloneHeader(r.Header)
	}
	if r.Trailer != nil {
		newRequest.Trailer = CloneHeader(r.Trailer)
	}
	return newRequest
}

func FilterRequest(perHostConfig *PerHostConfig, r *http.Request, proxyCtx *OurProxyCtx) (*http.Request, *http.Response) {
	newUrlString := ""
	headerSets := (http.Header)(nil)
	for _, pattern := range perHostConfig.Patterns {
		submatchIndexes := pattern.Pattern.FindStringSubmatchIndex(r.URL.Path)
		if submatchIndexes != nil {
			proxyCtx.Logger.Debugf("%s matched to pattern %s", r.URL.Path, pattern.Pattern.String())
			newUrlString = string(pattern.Pattern.ExpandString(
				make([]byte, 0, len(pattern.Substitution)+len(r.URL.Path)),
				pattern.Substitution,
				r.URL.Path,
				submatchIndexes,
			))
			headerSets = make(http.Header)
			for headerName, headers := range pattern.Headers {
				newHeaders := []string(nil)
				if headers != nil {
					newHeaders = make([]string, len(headers))
					for i, header := range headers {
						newHeaders[i] = string(pattern.Pattern.ExpandString(
							make([]byte, 0, len(header)+len(r.URL.Path)),
							header,
							r.URL.Path,
							submatchIndexes,
						))
					}
				}
				headerSets[textproto.CanonicalMIMEHeaderKey(headerName)] = newHeaders
			}
			break
		}
	}
	if newUrlString != "" {
		newUrl, err := url.Parse(newUrlString)
		if err != nil {
			proxyCtx.Logger.Error(err)
		}
		newUrl.User = r.URL.User
		if newUrl.RawQuery == "" {
			newUrl.RawQuery = r.URL.RawQuery
		}
		newRequest := CloneRequest(r)
		newRequest.URL = newUrl
		for headerName, headers := range headerSets {
			if headers == nil {
				delete(newRequest.Header, headerName)
			} else {
				existingHeaders, ok := newRequest.Header[headerName]
				if ok {
					headers = append(existingHeaders, headers...)
				}
				newRequest.Header[headerName] = headers
			}
		}
		proxyCtx.Logger.Infof("%s %s => %s", r.Method, r.RequestURI, newRequest.URL.String())
		return newRequest, nil
	} else {
		proxyCtx.Logger.Infof("%s %s", r.Method, r.RequestURI)
		return r, nil
	}
}
