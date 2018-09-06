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
	"io"
	"io/ioutil"
	"math"
	"mime"
	"net/http"
	"unsafe"

	"github.com/pkg/errors"
)

type FilterRepositoryType struct {
	ResponseFilters map[string]ResponseFilterFactory
}

var FilterRepository = FilterRepositoryType{
	ResponseFilters: make(map[string]ResponseFilterFactory),
}

func (repo *FilterRepositoryType) AddResponseFilter(name string, f ResponseFilterFactory) {
	repo.ResponseFilters[name] = f
}

func init() {
	FilterRepository.AddResponseFilter("label", NewLabelFilter)
}

type LabelFilter struct {
	HTMLMediaTypes []string
	LabelHTML      []byte
	InsertBefore   []byte
}

var defaultHTMLMediaTypes = []string{
	"text/html",
	"application/xhtml+xml",
}

func NewLabelFilter(ctx *ConfigReaderContext, configMap map[interface{}]interface{}) (ResponseFilter, error) {
	htmlMediaTypes := defaultHTMLMediaTypes

	__htmlMediaTypes, ok := configMap["html_media_types"]
	if ok {
		_htmlMediaTypes, ok := __htmlMediaTypes.([]interface{})
		if !ok {
			return nil, errors.Errorf("invalid value for html_media_types")
		}
		htmlMediaTypes = make([]string, 0)
		for _, _htmlMediaType := range _htmlMediaTypes {
			htmlMediaType, ok := _htmlMediaType.(string)
			if !ok {
				return nil, errors.Errorf("invalid value for html_media_types")
			}
			htmlMediaTypes = append(htmlMediaTypes, htmlMediaType)
		}
	}

	labelHTML := `<div style="position:fixed;left:0;top:0;width:100%;background-color:#ff0">DEVPROXY</div>`
	_labelHTML, ok := configMap["html"]
	if ok {
		labelHTML, ok = _labelHTML.(string)
		if !ok {
			return nil, errors.Errorf("invalid value for insert_before")
		}
	}

	insertBefore := `</body>`
	_insertBefore, ok := configMap["insert_before"]
	if ok {
		insertBefore, ok = _insertBefore.(string)
		if !ok {
			return nil, errors.Errorf("invalid value for insert_before")
		}
	}

	return &LabelFilter{
		HTMLMediaTypes: htmlMediaTypes,
		LabelHTML:      []byte(labelHTML),
		InsertBefore:   []byte(insertBefore),
	}, nil
}

func (ctx *LabelFilter) Filter(resp *http.Response, proxyCtx *OurProxyCtx) (*http.Response, error) {
	if resp == nil {
		return resp, nil
	}

	if proxyCtx.OrigReq == proxyCtx.Req {
		return resp, nil
	}

	contentType, ok := resp.Header[contentTypeKey]
	if !ok || len(contentType) == 0 {
		return resp, nil
	}
	mimeType, params, err := mime.ParseMediaType(contentType[0])
	if err != nil {
		proxyCtx.Logger.Warnf("invalid Content-Type header: %s", contentType[0])
		return resp, nil
	}
	applicable := false
	for _, v := range ctx.HTMLMediaTypes {
		if v == mimeType {
			applicable = true
			break
		}
	}
	if !applicable {
		return resp, nil
	}
	charset, ok := params["charset"]
	if !ok {
		charset = "UTF-8"
	}
	if charset == "UTF-16" {
		return resp, nil
	}
	if unsafe.Sizeof(resp.ContentLength) != unsafe.Sizeof(int(0)) {
		if resp.ContentLength > math.MaxInt32 {
			return nil, errors.Errorf("failed to read response body (%d expected)", resp.ContentLength)
		}
	}
	contentLength := int(resp.ContentLength)
	body := []byte{}
	defer resp.Body.Close()
	if contentLength >= 0 {
		body = make([]byte, contentLength)
		n, err := io.ReadFull(resp.Body, body)
		if err != nil || (err == io.EOF && n < contentLength) {
			return nil, errors.Wrapf(err, "failed to read response body (%d bytes read, %d bytes expected)", n, contentLength)
		}
	} else {
		err := error(nil)
		body, err = ioutil.ReadAll(resp.Body)
		if err != nil {
			return nil, errors.Wrapf(err, "failed to read response body")
		}
	}
	p := bytes.LastIndex(body, ctx.InsertBefore)
	if p > 0 {
		newBody := make([]byte, 0, len(body)+len(ctx.LabelHTML))
		newBody = append(newBody, body[0:p]...)
		newBody = append(newBody, ctx.LabelHTML...)
		newBody = append(newBody, body[p:]...)
		body = newBody
	}
	newResp := new(http.Response)
	*newResp = *resp
	newResp.Body = ioutil.NopCloser(bytes.NewBuffer(body))
	return newResp, nil
}
