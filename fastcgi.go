/*
 * Copyright (c) 2016 Moriyoshi Koizumi
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
	"bytes"
	"github.com/moriyoshi/devproxy/fcgiclient"
	"github.com/sirupsen/logrus"
	"io"
	"io/ioutil"
	"math"
	"net"
	"net/http"
	"net/textproto"
	"strconv"

	"github.com/pkg/errors"
)

type fastCGIRoundTripper struct {
	Logger *logrus.Logger
	reqId  uint16
}

func pop(h http.Header, k string) string {
	v, ok := h[k]
	if !ok {
		return ""
	}
	delete(h, k)
	return v[0]
}

func (rt *fastCGIRoundTripper) RoundTrip(req *http.Request) (*http.Response, error) {
	env := map[string][]byte{
		"REQUEST_METHOD":  []byte(req.Method),
		"REQUEST_URI":     []byte(req.URL.Path),
		"HTTP_HOST":       []byte(req.Host),
		"HTTP_COOKIE":     []byte(req.Header.Get("Cookie")),
		"HTTP_REFERER":    []byte(req.Header.Get("Referer")),
		"HTTP_USER_AGENT": []byte(req.Header.Get("User-Agent")),
		"SCRIPT_FILENAME": []byte(pop(req.Header, "X-Cgi-Script-Filename")),
		"SCRIPT_NAME":     []byte(pop(req.Header, "X-Cgi-Script-Name")),
		"PATH_INFO":       []byte(pop(req.Header, "X-Cgi-Path-Info")),
		"PATH_TRANSLATED": []byte(pop(req.Header, "X-Cgi-Path-Translated")),
		"SERVER_PROTOCOL": []byte(req.Proto),
		"REMOTE_ADDR":     []byte(req.Header.Get("X-Forwarded-For")),
		"CONTENT_TYPE":    []byte(req.Header.Get("Content-Type")),
		"QUERY_STRING":    []byte(req.URL.RawQuery),
	}
	if req.Header.Get("X-Forwarded-Proto") == "https" {
		env["HTTPS"] = []byte("on")
	}
	pair := splitHostPort(req.URL.Host)
	unix := len(pair.Host) > 0 && pair.Host[0] == '/'
	if !unix && pair.Port == "" {
		pair.Port = "9000"
	}
	var proto string
	if unix {
		proto = "unix"
	} else {
		proto = "tcp"
	}
	conn, err := net.Dial(proto, pair.String())
	if err != nil {
		return nil, err
	}
	defer conn.Close()
	fcgi, err := fcgiclient.New(conn)
	if err != nil {
		return nil, err
	}
	var reqBody []byte
	if req.Body != nil {
		if req.ContentLength == 0 {
			reqBody, err = ioutil.ReadAll(req.Body)
		} else {
			if req.ContentLength > math.MaxInt32 {
				return nil, errors.Errorf("Request body too long (%d bytes)", req.ContentLength)
			}
			reqBody = make([]byte, int(req.ContentLength))
			_, err = io.ReadAtLeast(req.Body, reqBody, int(req.ContentLength))
		}
		if err != nil {
			return nil, err
		}
		env["CONTENT_LENGTH"] = []byte(strconv.Itoa(len(reqBody)))
	}
	respBytes, errBytes, err := fcgi.Request(env, reqBody, rt.reqId)
	rt.reqId += 1
	if err != nil {
		return nil, err
	}
	if errBytes != nil {
		return nil, errors.Errorf("Upstream returned error: %s", string(errBytes))
	}
	headers, err := textproto.NewReader(bufio.NewReader(bytes.NewReader(respBytes))).ReadMIMEHeader()
	if err != nil {
		return nil, err
	}
	status := headers.Get("Status")
	if status == "" {
		status = "200 OK"
	}
	_respBytes := make([]byte, 0, 9+len(status)+2+len(respBytes))
	_respBytes = append(_respBytes, 'H', 'T', 'T', 'P', '/', '1', '.', '1', ' ')
	_respBytes = append(_respBytes, []byte(status)...)
	_respBytes = append(_respBytes, '\r', '\n')
	_respBytes = append(_respBytes, respBytes...)
	return http.ReadResponse(bufio.NewReader(bytes.NewReader(_respBytes)), req)
}
