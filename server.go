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
	"context"
	"crypto/tls"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/textproto"
	"net/url"
	"strings"
	"sync/atomic"
	"time"

	"github.com/moriyoshi/devproxy/httpx"
	"github.com/pkg/errors"
	"github.com/sirupsen/logrus"
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

var proxyContextKey string = "devproxy:proxyCtx"

func makeHttp10Response(header string, body string) string {
	return header + "\r\n" + fmt.Sprintf("Content-Length: %d\r\n", len(body)) + "Connection: close\r\n\r\n" + body
}

func isWebSocketReq(req *http.Request) bool {
	connHdr := req.Header.Get("Connection")
	if httpx.HasToken(connHdr, "upgrade") {
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
		proxyCtx.Logger.Debugf("handling WebSocket handshake: %v", req.URL)
		cm, err := proxyCtx.Tr.ConnectMethodForRequest(&httpx.TransportRequest{Request: req, Extra: nil})
		if err != nil {
			return nil, errors.Wrapf(err, "failed to create a ConnectMethod struct")
		}
		obConn, _, _, _, err := proxyCtx.Tr.DoDial(req.Context(), cm)
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
		proxyCtx.Logger.Debugf("established bidi tunnel between %v and %v", obConn.RemoteAddr(), ibConn.RemoteAddr())
		proxyCtx.Proxy.Ctx.bidiTunnel(obConn, ibConn)
		proxyCtx.Logger.Debugf("discarded bidi tunnel between %v and %v", obConn.RemoteAddr(), ibConn.RemoteAddr())
		return nil, nil
	} else {
		timer := (*time.Timer)(nil)
		canceled := int32(0)

		if timeout > 0 {
			timer = time.AfterFunc(timeout, func() {
				atomic.StoreInt32(&canceled, 1)
				proxyCtx.Tr.CancelRequest(req, fmt.Errorf("timeout exceeded"))
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
	defer proxyClient.Close()
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
			req = req.WithContext(
				context.WithValue(
					r.Context(),
					proxyContextKey,
					nestedProxyCtx,
				),
			)
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
			if resp != nil {
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
			}
			return
		}
	}

	proxyCtx.Logger.Debugf("Connecting to %s", targetHostPort)
	targetConn, err := proxyCtx.Proxy.ConnectDial(r.Context(), targetHostPort)
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
	r = r.WithContext(
		context.WithValue(
			r.Context(),
			proxyContextKey,
			proxyCtx,
		),
	)
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
			return
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

func (proxy *OurProxyHttpServer) doDial(ctx context.Context, addr string) (net.Conn, error) {
	if proxy.Tr.DialContext != nil {
		return proxy.Tr.DialContext(ctx, "tcp", addr)
	}
	return (&net.Dialer{}).DialContext(ctx, "tcp", addr)
}

func (proxy *OurProxyHttpServer) doDialTLS(ctx context.Context, addr HostPortPair, tlsConfigTemplate *tls.Config) (net.Conn, error) {
	if tlsConfigTemplate == nil {
		if proxy.Tr.DialTLS != nil {
			return proxy.Tr.DialTLS(ctx, "tcp", addr.String())
		}
		tlsConfigTemplate = proxy.Tr.TLSClientConfig
	}
	conn, err := net.Dial("tcp", addr.String())
	if err != nil {
		return nil, errors.Wrapf(err, "failed to connect to %v", addr)
	}
	tlsConfig := tlsConfigTemplate.Clone()
	tlsConfig.ServerName = addr.Host
	return tls.Client(conn, tlsConfig), nil
}

func (proxy *OurProxyHttpServer) ConnectDial(netCtx context.Context, addr string) (net.Conn, error) {
	cm, err := proxy.Tr.ConnectMethodForRequest(&httpx.TransportRequest{Request: buildFakeHTTPSRequestFromHostPortPair(addr), Extra: nil})
	cm.TargetScheme = "http" // we won't SSL-terminate the connection; packets will be passed through
	if err != nil {
		return nil, errors.Wrapf(err, "failed to connect to %s", addr)
	}
	conn, _, _, _, err := proxy.Tr.DoDial(netCtx, cm)
	if err != nil {
		return nil, errors.Wrapf(err, "failed to connect to %s", addr)
	}
	return conn, err
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
		newRequest := r.Clone(r.Context())
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
