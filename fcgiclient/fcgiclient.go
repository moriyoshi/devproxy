/*
 * Copyright (c) 2016 Moriyoshi Koizumi
 * Copyright (c) 2012 Junqing Tan <ivan@mysqlab.net>
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

package fcgiclient

import (
	"bufio"
	"encoding/binary"
	"errors"
	"io"
	"net"
)

const FCGI_LISTENSOCK_FILENO uint8 = 0
const FCGI_HEADER_LEN uint8 = 8
const VERSION_1 uint8 = 1
const FCGI_NULL_REQUEST_ID uint8 = 0
const FCGI_KEEP_CONN uint8 = 1

const (
	FCGI_BEGIN_REQUEST uint8 = iota + 1
	FCGI_ABORT_REQUEST
	FCGI_END_REQUEST
	FCGI_PARAMS
	FCGI_STDIN
	FCGI_STDOUT
	FCGI_STDERR
	FCGI_DATA
	FCGI_GET_VALUES
	FCGI_GET_VALUES_RESULT
	FCGI_UNKNOWN_TYPE
	FCGI_MAXTYPE = FCGI_UNKNOWN_TYPE
)

const (
	FCGI_RESPONDER uint8 = iota + 1
	FCGI_AUTHORIZER
	FCGI_FILTER
)

const (
	FCGI_REQUEST_COMPLETE uint8 = iota
	FCGI_CANT_MPX_CONN
	FCGI_OVERLOADED
	FCGI_UNKNOWN_ROLE
)

const (
	FCGI_MAX_CONNS  string = "MAX_CONNS"
	FCGI_MAX_REQS   string = "MAX_REQS"
	FCGI_MPXS_CONNS string = "MPXS_CONNS"
)

const (
	maxWrite = 65535 // maximum record body
	maxPad   = 255
)

var nullByteSlice []byte = []byte{}

type header struct {
	Version       uint8
	Type          uint8
	Id            uint16
	ContentLength uint16
	PaddingLength uint8
	Reserved      uint8
}

// for padding so we don't have to allocate all the time
// not synchronized because we don't care what the contents are
var pad [maxPad]byte

func (h *header) init(recType uint8, reqId uint16, contentLength int) {
	h.Version = 1
	h.Type = recType
	h.Id = reqId
	h.ContentLength = uint16(contentLength)
	h.PaddingLength = uint8(-contentLength & 7)
}

type record struct {
	h   header
	buf [maxWrite + maxPad]byte
}

func (rec *record) read(r io.Reader) (err error) {
	if err = binary.Read(r, binary.BigEndian, &rec.h); err != nil {
		return err
	}
	if rec.h.Version != 1 {
		return errors.New("fcgi: invalid header version")
	}
	n := int(rec.h.ContentLength) + int(rec.h.PaddingLength)
	if _, err = io.ReadFull(r, rec.buf[:n]); err != nil {
		return err
	}
	return nil
}

func (r *record) content() []byte {
	return r.buf[:r.h.ContentLength]
}

type FCGIClient struct {
	conn      net.Conn
	r         io.Reader
	w         io.Writer // *bufio.Writer
	h         header
	keepAlive bool
}

func New(conn net.Conn) (fcgi *FCGIClient, err error) {
	return &FCGIClient{
		conn:      conn,
		r:         conn, // bufio.NewReader(conn),
		w:         conn, // bufio.NewWriterSize(conn, maxWrite),
		keepAlive: false,
	}, nil
}

func (this *FCGIClient) writeRecord(recType uint8, reqId uint16, content []byte) (err error) {
	this.h.init(recType, reqId, len(content))
	if err := binary.Write(this.w, binary.BigEndian, this.h); err != nil {
		return err
	}
	if _, err := this.w.Write(content); err != nil {
		return err
	}
	if _, err := this.w.Write(pad[:this.h.PaddingLength]); err != nil {
		return err
	}
	return err
}

func (this *FCGIClient) writeBeginRequest(reqId uint16, role uint16, flags uint8) error {
	b := [8]byte{byte(role >> 8), byte(role), flags}
	return this.writeRecord(FCGI_BEGIN_REQUEST, reqId, b[:])
}

func (this *FCGIClient) writeEndRequest(reqId uint16, appStatus int, protocolStatus uint8) error {
	b := make([]byte, 8)
	binary.BigEndian.PutUint32(b, uint32(appStatus))
	b[4] = protocolStatus
	return this.writeRecord(FCGI_END_REQUEST, reqId, b)
}

func (this *FCGIClient) writePairs(recType uint8, reqId uint16, pairs map[string][]byte) error {
	b := make([]byte, 0, 32)
	for k, v := range pairs {
		if len(b)+8+len(k)+len(v) > maxWrite {
			// if the record is going to be larger than maxWrite, split the record
			this.writeRecord(recType, reqId, b)
			b = make([]byte, 0, 32)
		}
		b, _ = encodeSize(b, uint32(len(k)))
		b, _ = encodeSize(b, uint32(len(v)))
		b = append(b, []byte(k)...)
		b = append(b, v...)
	}
	if len(b) > 0 {
		this.writeRecord(recType, reqId, b)
	}
	this.writeRecord(recType, reqId, nullByteSlice)
	return nil
}

func grow(b []byte, s int, adjustLen bool) []byte {
	if s < cap(b)-len(b) {
		g := cap(b) >> 1
		if s < 16 || g == 0 {
			g = 16
		}
		nc := cap(b) + g
		nb := make([]byte, len(b), nc)
		copy(nb, b)
		b = nb
	}
	if adjustLen {
		b = b[0 : len(b)+s]
	}
	return b
}

func encodeSize(b []byte, size uint32) ([]byte, int) {
	if size > 127 {
		size |= 1 << 31
		b = grow(b, 4, true)
		binary.BigEndian.PutUint32(b[len(b)-4:], size)
		return b, 4
	}
	b = grow(b, 1, true)
	b[len(b)-1] = byte(size)
	return b, 1
}

func (this *FCGIClient) Request(env map[string][]byte, req []byte, reqId uint16) (stdout []byte, stderr []byte, err error) {
	err = this.writeBeginRequest(reqId, uint16(FCGI_RESPONDER), 0)
	if err != nil {
		return
	}
	err = this.writePairs(FCGI_PARAMS, reqId, env)
	if err != nil {
		return
	}
	if req == nil {
		req = nullByteSlice
	}
	err = this.writeRecord(FCGI_STDIN, reqId, req)
	if err != nil {
		return
	}
	if _w, ok := this.w.(*bufio.Writer); ok {
		err = _w.Flush()
		if err != nil {
			return
		}
	}

	noMoreStdout := false
	noMoreStderr := false
outer:
	for {
		rec := &record{}
		err = rec.read(this.r)
		if err != nil {
			return
		}
		switch rec.h.Type {
		case FCGI_STDOUT:
			if noMoreStdout {
				return nil, nil, errors.New("Invalid response")
			}
			c := rec.content()
			if len(c) == 0 {
				noMoreStdout = true
				if stdout == nil {
					stdout = c
				}
			} else {
				if stdout == nil {
					stdout = c
				} else {
					stdout = append(stdout, c...)
				}
			}
		case FCGI_STDERR:
			if noMoreStderr {
				return nil, nil, errors.New("Invalid response")
			}
			c := rec.content()
			if len(c) == 0 {
				noMoreStderr = true
				if stderr == nil {
					stderr = c
				}
			} else {
				if stderr == nil {
					stderr = c
				} else {
					stderr = append(stderr, c...)
				}
			}
		case FCGI_END_REQUEST:
			break outer
		}
	}
	return
}
