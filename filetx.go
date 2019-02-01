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
	"io"
	"mime"
	"net/http"
	"os"
	"path/filepath"

	"github.com/moriyoshi/mimetypes"
	_ "github.com/moriyoshi/mimetypes/loaders"
	"github.com/moriyoshi/simplefiletx"
)

var httpMetaKeys = []string{"Content-Type"}

const defaultMimeType = "application/octet-stream"

type MyOpener struct {
	MimeTypes mimetypes.MediaTypeRegistry
}

type MyReaderWithStat struct {
	inner  simplefiletx.ReaderWithStat
	name   string
	opener *MyOpener
}

func (opener *MyOpener) Open(name string) (io.ReadCloser, error) {
	f, err := os.Open(name)
	if err != nil {
		return nil, err
	}

	return &MyReaderWithStat{f, name, opener}, nil
}

func (rws *MyReaderWithStat) Read(b []byte) (int, error) {
	return rws.inner.Read(b)
}

func (rws *MyReaderWithStat) Close() error {
	return rws.inner.Close()
}

func (rws *MyReaderWithStat) Stat() (os.FileInfo, error) {
	return rws.inner.Stat()
}

func (rws *MyReaderWithStat) GetHTTPMetadataKeys() ([]string, error) {
	return httpMetaKeys, nil
}

func (rws *MyReaderWithStat) GetHTTPMetadata(k string) ([]string, error) {
	if k == "Content-Type" {
		ext := filepath.Ext(rws.name)
		var mimeType string
		if rws.opener.MimeTypes != nil {
			mimeType = rws.opener.MimeTypes.TypeByExtension(ext)
		} else {
			mimeType = mime.TypeByExtension(ext)
		}
		if mimeType == "" {
			mimeType = defaultMimeType
		}
		return []string{mimeType}, nil
	}
	return nil, fmt.Errorf("no such key: %s", k)
}

func NewFileTransport(config FileTransportConfig) http.RoundTripper {
	return &simplefiletx.SimpleFileTransport{
		BaseDir: config.RootDirectory,
		Opener:  &MyOpener{config.MimeTypes},
	}
}
