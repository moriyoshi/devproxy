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
	"fmt"
	"net"
	"net/url"
)

type HostPortPair struct {
	Host string
	Port string
}

func defaultPortForScheme(scheme string) string {
	if scheme == "https" {
		return "443"
	} else if scheme == "http" {
		return "80"
	} else {
		return ""
	}
}

func splitHostPort(hostPortPairStr string) (pair HostPortPair) {
	var err error
	pair.Host, pair.Port, err = net.SplitHostPort(hostPortPairStr)
	if err != nil {
		pair = HostPortPair{Host: hostPortPairStr, Port: ""}
	}
	return
}

func toHostPortPair(url_ *url.URL) (HostPortPair, error) {
	pair := splitHostPort(url_.Host)
	if pair.Port == "" {
		defaultPort := defaultPortForScheme(url_.Scheme)
		if defaultPort == "" {
			return HostPortPair{}, fmt.Errorf("Unsupported URL scheme: %s", url_.Scheme)
		}
		pair.Port = defaultPort
	}
	return pair, nil
}

func toHostPortPairs(url_ *url.URL) []HostPortPair {
	retval := make([]HostPortPair, 0)
	pair := splitHostPort(url_.Host)
	if pair.Port == "" {
		defaultPort := defaultPortForScheme(url_.Scheme)
		if defaultPort != "" {
			retval = append(retval, HostPortPair{
				Host: pair.Host,
				Port: defaultPort,
			})
		}
	}
	retval = append(retval, pair)
	return retval
}

func (pair HostPortPair) String() string {
	if pair.Port != "" {
		return pair.Host + ":" + pair.Port
	} else {
		return pair.Host
	}
}