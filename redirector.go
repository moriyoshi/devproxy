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
	"bytes"
	"fmt"
	"io/ioutil"
	"net/http"
	"strconv"
	"strings"

	"github.com/sirupsen/logrus"
)

var redirStatusCodes = map[int]string{
	301: "Moved Permanently",
	302: "Found",
	303: "See Other",
	307: "Temporary Redirect",
	308: "Permanent edirect",
}

type redirector struct {
	Logger *logrus.Logger
}

var emptyReadCloser = ioutil.NopCloser(&bytes.Reader{})

func (redir *redirector) RoundTrip(req *http.Request) (*http.Response, error) {
	redirStatusCode := 302
	statusText := ""
	var location string

	if req.URL.Host == "" {
		components := strings.Split(req.URL.Opaque, ":")
		if len(components) < 1 {
			return nil, fmt.Errorf("invalid URL: %v", req.URL)
		}
		if components[0] != "http" && components[0] != "https" {
			var err error
			redirStatusCode, err = strconv.Atoi(components[0])
			if err != nil {
				return nil, fmt.Errorf("invalid URL: %v", req.URL)
			}
			var ok bool
			statusText, ok = redirStatusCodes[redirStatusCode]
			if !ok {
				return nil, fmt.Errorf("invalid status code %d in URL %v", redirStatusCode, req.URL)
			}
			components = components[1:]
		} else {
			redirStatusCode = 302
		}
		if len(components) < 1 {
			return nil, fmt.Errorf("invalid URL: %v", req.URL)
		}
		location = strings.Join(components, ":")
		if req.URL.RawQuery != "" {
			location += "&" + req.URL.RawQuery
		}
		if req.URL.Fragment != "" {
			location += "#" + req.URL.Fragment
		}
	} else {
		proxyCtx := req.Context().Value(proxyContextKey).(*OurProxyCtx)
		redirStatusCode = 302
		_location := req.URL
		_location.Scheme = proxyCtx.OrigReq.URL.Scheme
		location = _location.String()
	}
	if statusText == "" {
		statusText = redirStatusCodes[redirStatusCode]
	}
	return &http.Response{
		Status:     fmt.Sprintf("%d %s", redirStatusCode, statusText),
		StatusCode: redirStatusCode,
		Proto:      req.Proto,
		ProtoMajor: req.ProtoMajor,
		ProtoMinor: req.ProtoMinor,
		Header: http.Header{
			"Location": []string{location},
		},
		Trailer:       http.Header{},
		ContentLength: 0,
		Body:          emptyReadCloser,
		Close:         true,
		Request:       req,
		TLS:           req.TLS,
	}, nil
}
