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
	"bytes"
	"crypto"
	"crypto/ecdsa"
	crand "crypto/rand"
	"crypto/rsa"
	"crypto/sha1"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/binary"
	"encoding/pem"
	"flag"
	"fmt"
	"github.com/Sirupsen/logrus"
	"github.com/cloudfoundry-incubator/candiedyaml"
	"io"
	"io/ioutil"
	"log"
	"math"
	"math/big"
	"mime"
	"net"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"time"
	"unsafe"
	"sync"
	"sync/atomic"
)

type Pattern struct {
	Pattern      *regexp.Regexp
	Substitution string
}

type PerHostConfig struct {
	Host	 *url.URL
	Patterns []Pattern
}

type MITMConfig struct {
	ServerTLSConfigTemplate   tls.Config
	ClientTLSConfigTemplate   tls.Config
	SigningCertificateKeyPair struct {
		Certificate *x509.Certificate
		PrivateKey  crypto.PrivateKey
	}
}

type ProxyConfig struct {
	HTTPProxy     *url.URL
	HTTPSProxy    *url.URL
	IncludedHosts []HostPortPair
	ExcludedHosts []HostPortPair
}

type Config struct {
	Hosts map[string]*PerHostConfig
	Proxy ProxyConfig
	MITM  MITMConfig
}

type HostPortPair struct {
	Host string
	Port string
}

type TLSConfigFactory func(hostPortPairStr string, proxyCtx *OurProxyCtx) (*tls.Config, error)

var contentTypeKey = http.CanonicalHeaderKey("Content-Type")
var http10BadGatewayBytes = []byte(makeHttp10Response("HTTP/1.0 502 Bad Gateway", "<html><body><h1>Bad Gateway</h1></body></html>"))
var http10OkBytes = []byte("HTTP/1.0 200 OK\r\n\r\n")

var unixTimeEpoch = time.Unix(0, 0)


func makeHttp10Response(header string, body string) string {
	return header + fmt.Sprintf("Content-Length: %d\r\n", len(body)) + "Connection: close\r\n\r\n" + body;
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
		pair = HostPortPair{Host:hostPortPairStr, Port: ""}
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

type ConfigReaderContext struct {
	Filename string
	Warn     func(string)
}

func (ctx *ConfigReaderContext) extractPerHostConfigs(configMap map[string]interface{}) (map[string]*PerHostConfig, error) {
	__hosts, ok := configMap["hosts"]
	if !ok {
		return nil, fmt.Errorf("%s: no hosts entry", ctx.Filename)
	}
	_hosts, ok := __hosts.(map[interface{}]interface{})
	if !ok {
		return nil, fmt.Errorf("%s: invalid structure under hosts", ctx.Filename)
	}
	perHostConfigs := make(map[string]*PerHostConfig)
	for __url, __patterns := range _hosts {
		_url, ok := __url.(string)
		if !ok {
			return nil, fmt.Errorf("%s: invalid structure under hosts", ctx.Filename)
		}
		url, err := url.Parse(_url)
		if err != nil {
			return nil, fmt.Errorf("%s: invalid value for URL (%s) under hosts/%s", ctx.Filename)
		}
		if url.Path != "" {
			return nil, fmt.Errorf("%s: path many not be present: %s", ctx.Filename, _url)
		}
		_patterns, ok := __patterns.([]interface{})
		if !ok {
			return nil, fmt.Errorf("%s: invalid structure under hosts/%s", ctx.Filename, _url)
		}
		patterns := make([]Pattern, 0)
		for _, ___pattern := range _patterns {
			__pattern, ok := ___pattern.(map[interface{}]interface{})
			if !ok {
				return nil, fmt.Errorf("%s: invalid structure under hosts/%s", ctx.Filename, _url)
			}
			if len(__pattern) != 1 {
				return nil, fmt.Errorf("%s: invalid structure under hosts/%s", ctx.Filename, _url)
			}
			for _pattern, _substitution := range __pattern {
				pattern, ok := _pattern.(string)
				if !ok {
					return nil, fmt.Errorf("%s: invalid structure under hosts/%s", ctx.Filename, _url)
				}
				substitution, ok := _substitution.(string)
				if !ok {
					return nil, fmt.Errorf("%s: invalid structure under hosts/%s", ctx.Filename, _url)
				}
				patternRegexp, err := regexp.Compile(pattern)
				if err != nil {
					return nil, fmt.Errorf("%s: invalid regexp %s for %s configuration", ctx.Filename, pattern, _url)
				}
				patterns = append(patterns, Pattern{Pattern: patternRegexp, Substitution: substitution})
			}
		}
		perHostConfigs[_url] = &PerHostConfig{Host: url, Patterns: patterns}
	}
	return perHostConfigs, nil
}

func getenv(name string) string {
	v := os.Getenv(strings.ToUpper(name))
	if v != "" {
		return v
	}
	return os.Getenv(strings.ToLower(name))
}

func convertUnparsedHostsIntoPairs(unparsedHosts []string) ([]HostPortPair, error) {
	retval := make([]HostPortPair, 0, len(unparsedHosts))
	for _, unparsedHost := range unparsedHosts {
		host, port, err := net.SplitHostPort(unparsedHost)
		if err != nil {
			host = unparsedHost
			port = ""
		}
		retval = append(retval, HostPortPair{Host: host, Port: port})
	}
	return retval, nil
}

func convertToStringList(src []interface{}) ([]string, bool) {
	retval := make([]string, len(src))
	for i, v := range src {
		var ok bool
		retval[i], ok = v.(string)
		if !ok {
			return nil, false
		}
	}
	return retval, true
}

func parseUrlOrHostPortPair(urlOrHostPortPair string) (retval *url.URL, err error) {
	retval, err = url.Parse(urlOrHostPortPair)
	if err != nil {
		// possibly a host-port pair
		retval, err = url.Parse("http://" + urlOrHostPortPair)
		if err != nil {
			return
		}
	}
	return
}

func (ctx *ConfigReaderContext) extractProxyConfig(configMap map[string]interface{}) (retval ProxyConfig, err error) {
	__proxy, ok := configMap["proxy"]
	if ok {
		_proxy, ok := __proxy.(map[interface{}]interface{})
		if !ok {
			err = fmt.Errorf("%s: invalid structure under proxy", ctx.Filename)
			return
		}
		_httpProxy, ok := _proxy["http"]
		if ok {
			httpProxy, ok := _httpProxy.(string)
			if !ok {
				err = fmt.Errorf("%s: invalid value for proxy/http_proxy", ctx.Filename)
				return
			}
			var httpProxyUrl *url.URL
			httpProxyUrl, err = parseUrlOrHostPortPair(httpProxy)
			if err != nil {
				err = fmt.Errorf("%s: invalid value for proxy/http_proxy (%s)", ctx.Filename, err.Error())
				return
			}
			retval.HTTPProxy = httpProxyUrl
		}
		_httpsProxy, ok := _proxy["https"]
		if ok {
			httpsProxy, ok := _httpsProxy.(string)
			if !ok {
				err = fmt.Errorf("%s: invalid value for proxy/http_proxy", ctx.Filename)
				return
			}
			var httpsProxyUrl *url.URL
			httpsProxyUrl, err = parseUrlOrHostPortPair(httpsProxy)
			if err != nil {
				err = fmt.Errorf("%s: invalid value for proxy/http_proxy (%s)", ctx.Filename, err.Error())
				return
			}
			retval.HTTPSProxy = httpsProxyUrl
		}
		__includedHosts, ok := _proxy["included"]
		if ok {
			_includedHosts, ok := __includedHosts.([]interface{})
			if !ok {
				err = fmt.Errorf("%s: invalid value for proxy/included", ctx.Filename)
				return
			}
			includedHosts, ok := convertToStringList(_includedHosts)
			if !ok {
				err = fmt.Errorf("%s: invalid value for proxy/included", ctx.Filename)
				return
			}
			retval.IncludedHosts, err = convertUnparsedHostsIntoPairs(includedHosts)
			if err != nil {
				err = fmt.Errorf("invalid host-port pair contained in NO_PROXY (%s)", err.Error())
				return
			}
		}
		__excludedHosts, ok := _proxy["excluded"]
		if ok {
			_excludedHosts, ok := __excludedHosts.([]interface{})
			if !ok {
				err = fmt.Errorf("%s: invalid value for proxy/excluded", ctx.Filename)
				return
			}
			excludedHosts, ok := convertToStringList(_excludedHosts)
			if !ok {
				err = fmt.Errorf("%s: invalid value for proxy/excluded", ctx.Filename)
				return
			}
			retval.ExcludedHosts, err = convertUnparsedHostsIntoPairs(excludedHosts)
			if err != nil {
				err = fmt.Errorf("invalid host-port pair contained in NO_PROXY (%s)", err.Error())
				return
			}
		}
	}
	envUsed := false
	if retval.HTTPProxy == nil {
		httpProxy := getenv("http_proxy")
		if httpProxy != "" {
			retval.HTTPProxy, err = parseUrlOrHostPortPair(httpProxy)
			if err != nil {
				err = fmt.Errorf("invalid value for HTTP_PROXY (%s)", err.Error())
				return
			}
			envUsed = true
		}
	}
	if retval.HTTPSProxy == nil {
		httpsProxy := getenv("https_proxy")
		if httpsProxy != "" {
			retval.HTTPSProxy, err = parseUrlOrHostPortPair(httpsProxy)
			if err != nil {
				err = fmt.Errorf("invalid value for HTTPS_PROXY (%s)", err.Error())
				return
			}
			envUsed = true
		}
	}
	if envUsed && retval.ExcludedHosts == nil {
		noProxy := strings.Split(getenv("no_proxy"), ",")
		if len(noProxy) == 1 && noProxy[0] == "*" {
			retval.HTTPProxy = nil
			retval.HTTPSProxy = nil
			return
		}
		retval.ExcludedHosts, err = convertUnparsedHostsIntoPairs(noProxy)
		if err != nil {
			err = fmt.Errorf("invalid host-port pair contained in NO_PROXY (%s)", err.Error())
			return
		}
	}
	return
}

var clientAuthTypeValues = map[string]tls.ClientAuthType{
	"none":                       tls.NoClientCert,
	"NoClientCert":               tls.NoClientCert,
	"request":                    tls.RequestClientCert,
	"RequestClientCert":          tls.RequestClientCert,
	"require_any":                tls.RequestClientCert,
	"RequireAnyClientCert":       tls.RequireAnyClientCert,
	"verify_if_given":            tls.RequestClientCert,
	"VerifyClientCertIfGiven":    tls.VerifyClientCertIfGiven,
	"always_verify":              tls.RequestClientCert,
	"RequireAndVerifyClientCert": tls.RequireAndVerifyClientCert,
}

var cipherSuiteValues = map[string]uint16{
	"TLS_RSA_WITH_RC4_128_SHA":      tls.TLS_RSA_WITH_RC4_128_SHA,
	"RSA_WITH_RC4_128_SHA":          tls.TLS_RSA_WITH_RC4_128_SHA,
	"TLS_RSA_WITH_3DES_EDE_CBC_SHA": tls.TLS_RSA_WITH_3DES_EDE_CBC_SHA,
	"RSA_WITH_3DES_EDE_CBC_SHA":     tls.TLS_RSA_WITH_3DES_EDE_CBC_SHA,
	"TLS_RSA_WITH_AES_128_CBC_SHA":  tls.TLS_RSA_WITH_AES_128_CBC_SHA,
	"RSA_WITH_AES_128_CBC_SHA":      tls.TLS_RSA_WITH_AES_128_CBC_SHA,
	"TLS_RSA_WITH_AES_256_CBC_SHA":  tls.TLS_RSA_WITH_AES_256_CBC_SHA,
	"RSA_WITH_AES_256_CBC_SHA":      tls.TLS_RSA_WITH_AES_256_CBC_SHA,
	// "TLS_RSA_WITH_AES_128_GCM_SHA256":         tls.TLS_RSA_WITH_AES_128_GCM_SHA256,
	// "RSA_WITH_AES_128_GCM_SHA256":             tls.TLS_RSA_WITH_AES_128_GCM_SHA256,
	// "TLS_RSA_WITH_AES_256_GCM_SHA384":         tls.TLS_RSA_WITH_AES_256_GCM_SHA384,
	// "RSA_WITH_AES_256_GCM_SHA384":             tls.TLS_RSA_WITH_AES_256_GCM_SHA384,
	"TLS_ECDHE_ECDSA_WITH_RC4_128_SHA":        tls.TLS_ECDHE_ECDSA_WITH_RC4_128_SHA,
	"ECDHE_ECDSA_WITH_RC4_128_SHA":            tls.TLS_ECDHE_ECDSA_WITH_RC4_128_SHA,
	"TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA":    tls.TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA,
	"ECDHE_ECDSA_WITH_AES_128_CBC_SHA":        tls.TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA,
	"TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA":    tls.TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA,
	"ECDHE_ECDSA_WITH_AES_256_CBC_SHA":        tls.TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA,
	"TLS_ECDHE_RSA_WITH_RC4_128_SHA":          tls.TLS_ECDHE_RSA_WITH_RC4_128_SHA,
	"ECDHE_RSA_WITH_RC4_128_SHA":              tls.TLS_ECDHE_RSA_WITH_RC4_128_SHA,
	"TLS_ECDHE_RSA_WITH_3DES_EDE_CBC_SHA":     tls.TLS_ECDHE_RSA_WITH_3DES_EDE_CBC_SHA,
	"ECDHE_RSA_WITH_3DES_EDE_CBC_SHA":         tls.TLS_ECDHE_RSA_WITH_3DES_EDE_CBC_SHA,
	"TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA":      tls.TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA,
	"ECDHE_RSA_WITH_AES_128_CBC_SHA":          tls.TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA,
	"TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA":      tls.TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA,
	"ECDHE_RSA_WITH_AES_256_CBC_SHA":          tls.TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA,
	"TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256":   tls.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
	"ECDHE_RSA_WITH_AES_128_GCM_SHA256":       tls.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
	"TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256": tls.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
	"ECDHE_ECDSA_WITH_AES_128_GCM_SHA256":     tls.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
	"TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384":   tls.TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
	"ECDHE_RSA_WITH_AES_256_GCM_SHA384":       tls.TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
	"TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384": tls.TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,
	"ECDHE_ECDSA_WITH_AES_256_GCM_SHA384":     tls.TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,
}

var tlsVersionValues = map[string]uint16{
	"SSL30":  tls.VersionSSL30,
	"SSL3.0": tls.VersionSSL30,
	"TLS10":  tls.VersionTLS10,
	"TLS1.0": tls.VersionTLS10,
	"TLS11":  tls.VersionTLS11,
	"TLS1.1": tls.VersionTLS11,
	"TLS12":  tls.VersionTLS12,
	"TLS1.2": tls.VersionTLS12,
}

func (ctx *ConfigReaderContext) extractCertPool(certPoolConfig interface{}, path string) (*x509.CertPool, error) {
	pool := x509.NewCertPool()
	fileOrDirectory, ok := certPoolConfig.(string)
	if ok {
		var f *os.File
		f, err := os.Open(fileOrDirectory)
		if err != nil && !os.IsNotExist(err) {
			return nil, fmt.Errorf("%s: failed to open %s", ctx.Filename, fileOrDirectory)
		}
		if err == nil {
			var traverse func(f *os.File) error
			traverse = func(f *os.File) error {
				st, err := f.Stat()
				if err != nil {
					return fmt.Errorf("%s: failed to open %s (%s)", ctx.Filename, f.Name(), err.Error())
				}
				if st.IsDir() {
					children, err := f.Readdir(-1)
					if err != nil {
						return fmt.Errorf("%s: failed to read directory entry under %s (%s)", ctx.Filename, f.Name(), err.Error())
					}
					for _, child := range children {
						cp := filepath.Join(f.Name(), child.Name())
						cf, err := os.Open(cp)
						if err != nil {
							return fmt.Errorf("%s: failed to open %s (%s)", ctx.Filename, cp, err.Error())
						}
						err = traverse(cf)
						if err != nil {
							return err
						}
					}
				} else {
					pems, err := ioutil.ReadAll(f)
					if err != nil {
						return fmt.Errorf("%s: failed to read certificates from %s (%s)", ctx.Filename, f.Name(), err.Error())
					}
					if !pool.AppendCertsFromPEM(pems) {
						ctx.Warn(fmt.Sprintf("failed to parse some certificates in %s", f.Name()))
					}
				}
				return nil
			}
			err = traverse(f)
			if err != nil {
				return nil, err
			}
		} else {
			if strings.HasPrefix(fileOrDirectory, "----- BEGIN") {
				if !pool.AppendCertsFromPEM([]byte(fileOrDirectory)) {
					ctx.Warn("failed to parse some certificates")
				}
			} else {
				return nil, fmt.Errorf("%s: %s does not exist", ctx.Filename, fileOrDirectory)
			}
		}
		return pool, nil
	}
	_certList, ok := certPoolConfig.([]interface{})
	if ok {
		for _, _certs := range _certList {
			certs, ok := _certs.(string)
			if !ok {
				return nil, fmt.Errorf("%s: every item under %s must be a string", ctx.Filename, path)
			}
			if !pool.AppendCertsFromPEM([]byte(certs)) {
				ctx.Warn("failed to parse some certificates")
			}
		}
		return pool, nil
	}
	_certMap, ok := certPoolConfig.(map[interface{}]interface{})
	if ok {
		for _name, _certs := range _certMap {
			name := _name.(string)
			certs, ok := _certs.(string)
			if !ok {
				return nil, fmt.Errorf("%s: value for %s/%s must be a string", ctx.Filename, path, name)
			}
			if !pool.AppendCertsFromPEM([]byte(certs)) {
				ctx.Warn("failed to parse some certificates")
			}
		}
		return pool, nil
	}
	return nil, fmt.Errorf("%s: invalid structure under %s", ctx.Filename, path)
}

func countLines(s []byte) int {
	l := 0
	for adv, i := 0, 0; i < len(s); i += adv {
		adv, _, _ = bufio.ScanLines(s[i:], true)
		l++
	}
	return l
}

func parsePemBlocks(pemBytes []byte, warnFunc func(msg string)) ([][]byte, crypto.PrivateKey, error) {
	certs := make([][]byte, 0)
	key := crypto.PrivateKey(nil)
	lines := 0
	offset := 0
	for newPemBytes := []byte(nil); ; offset, lines, pemBytes = offset+len(pemBytes)-len(newPemBytes), lines+countLines(pemBytes[0:len(pemBytes)-len(newPemBytes)]), newPemBytes {
		var pemBlock *pem.Block
		pemBlock, newPemBytes = pem.Decode(pemBytes)
		if pemBlock == nil {
			break
		}
		if pemBlock.Type == "CERTIFICATE" || strings.HasSuffix(pemBlock.Type, " CERTIFICATE") {
			certs = append(certs, pemBlock.Bytes)
			continue
		} else if pemBlock.Type == "PRIVATE KEY" || strings.HasSuffix(pemBlock.Type, " PRIVATE KEY") {
			if key != nil {
				return nil, nil, fmt.Errorf("duplicate private keys exist")
			}
			{
				_key, err := x509.ParsePKCS1PrivateKey(pemBlock.Bytes)
				if err == nil {
					key = _key
					continue
				}
			}
			{
				_key, err := x509.ParsePKCS8PrivateKey(pemBlock.Bytes)
				if err == nil {
					key = _key
					continue
				}
			}
			{
				_key, err := x509.ParseECPrivateKey(pemBlock.Bytes)
				if err == nil {
					key = _key
					continue
				}
			}
		}
		warnFunc(fmt.Sprintf("Unknown PEM structure: type=%s at line %d", pemBlock.Type, lines+1))
	}
	return certs, key, nil
}

func checkIfKeysArePaired(a crypto.PublicKey, b crypto.PrivateKey) bool {
	switch _a := a.(type) {
	case *rsa.PublicKey:
		_b, ok := b.(*rsa.PrivateKey)
		if !ok {
			return false
		}
		return _a.N.Cmp(_b.N) == 0
	case *ecdsa.PublicKey:
		_b, ok := b.(*ecdsa.PrivateKey)
		if !ok {
			return false
		}
		return _a.X.Cmp(_b.X) == 0 && _a.Y.Cmp(_b.Y) == 0
	}
	return false
}

func (ctx *ConfigReaderContext) extractCertPrivateKeyPairs(certConfigMap map[interface{}]interface{}, path string) (tlsCert tls.Certificate, x509Cert *x509.Certificate, err error) {
	certs := [][]byte(nil)
	key := crypto.PrivateKey(nil)

	_filenamePemOrList, ok := certConfigMap["cert"]
	if !ok {
		err = fmt.Errorf("%s: missing item \"cert\" under %s", ctx.Filename, path)
		return
	}
	filenameOrPem, ok := _filenamePemOrList.(string)
	if ok {
		var f *os.File
		f, err = os.Open(filenameOrPem)
		if err != nil && !os.IsNotExist(err) {
			err = fmt.Errorf("%s: could not open %s (%s)", ctx.Filename, filenameOrPem, err.Error())
			return
		}
		if err == nil {
			var pemBytes []byte
			pemBytes, err = ioutil.ReadAll(f)
			if err != nil {
				err = fmt.Errorf("%s: could not read data from %s (%s)", ctx.Filename, filenameOrPem, err.Error())
				return
			}
			certs, key, err = parsePemBlocks(pemBytes, ctx.Warn)
			if err != nil {
				err = fmt.Errorf("%s: failed to parse certificates or private keys (%s)", ctx.Filename, err.Error())
				return
			}
		} else {
			certs, key, err = parsePemBlocks([]byte(filenameOrPem), ctx.Warn)
			if err != nil {
				err = fmt.Errorf("%s: failed to parse certificates or private keys (%s)", ctx.Filename, err.Error())
				return
			}
		}
	} else {
		certs = make([][]byte, 0, 1)
		list, ok := _filenamePemOrList.([]interface{})
		if !ok {
			err = fmt.Errorf("%s: %s/cert must be a string or a list of PEM-formatted certificates / private key", ctx.Filename, path)
			return
		}
		for _, _pem := range list {
			pem, ok := _pem.(string)
			if !ok {
				err = fmt.Errorf("%s: every item under %s/cert must be a PEM-formatted certificates / private key", ctx.Filename, path)
				return
			}
			var _certs [][]byte
			var _key crypto.PrivateKey
			_certs, _key, err = parsePemBlocks([]byte(pem), ctx.Warn)
			if err != nil {
				err = fmt.Errorf("%s: failed to parse certificates or private keys (%s)", ctx.Filename, err.Error())
				return
			}
			if _key != nil {
				if key != nil {
					err = fmt.Errorf("duplicate private keys exist")
					return
				}
			}
			certs = append(certs, _certs...)
			key = _key
		}
	}
	if len(certs) == 0 {
		err = fmt.Errorf("%s: no certificates exist in %s/cert", ctx.Filename, path)
		return
	}

	_filenamePemOrList, ok = certConfigMap["key"]
	if ok {
		if key != nil {
			err = fmt.Errorf("%s: private keys exist both in %s/cert and %s/key", ctx.Filename, path, path)
			return
		}
		filenameOrPem, ok := _filenamePemOrList.(string)
		if ok {
			var f *os.File
			var _certs [][]byte
			f, err = os.Open(filenameOrPem)
			if err != nil && !os.IsNotExist(err) {
				err = fmt.Errorf("%s: could not open %s (%s)", ctx.Filename, filenameOrPem, err.Error())
				return
			}
			if err == nil {
				var pemBytes []byte
				pemBytes, err = ioutil.ReadAll(f)
				if err != nil {
					err = fmt.Errorf("%s: could not read data from %s (%s)", ctx.Filename, filenameOrPem, err.Error())
					return
				}
				_certs, key, err = parsePemBlocks(pemBytes, ctx.Warn)
				if err != nil {
					err = fmt.Errorf("%s: failed to parse certificates or private keys (%s)", ctx.Filename, err.Error())
					return
				}
			} else {
				_certs, key, err = parsePemBlocks([]byte(filenameOrPem), ctx.Warn)
				if err != nil {
					err = fmt.Errorf("%s: failed to parse certificates or private keys (%s)", ctx.Filename, err.Error())
					return
				}
			}
			if len(_certs) != 0 {
				err = fmt.Errorf("%s: no certificates are allowed in %s/key", ctx.Filename, path)
				return
			}
		} else {
			var _certs [][]byte
			_certs, key, err = parsePemBlocks([]byte(filenameOrPem), ctx.Warn)
			if err != nil {
				err = fmt.Errorf("%s: failed to parse certificates or private keys (%s)", ctx.Filename, err.Error())
				return
			}
			if len(_certs) != 0 {
				err = fmt.Errorf("%s: no certificates are allowed in %s/key", ctx.Filename, path)
				return
			}
		}
	}
	if key == nil {
		err = fmt.Errorf("%s: no key found in %s/cert and %s/key", ctx.Filename, path, path)
		return
	}

	x509Cert, err = x509.ParseCertificate(certs[0])
	if err != nil {
		err = fmt.Errorf("%s: failed to parse certificate", ctx.Filename, err.Error())
	}
	if !checkIfKeysArePaired(x509Cert.PublicKey, key) {
		err = fmt.Errorf("%s: certificate does not correspond to private key", ctx.Filename)
	}

	tlsCert.Certificate = certs
	tlsCert.PrivateKey = key
	return
}

func (ctx *ConfigReaderContext) extractTLSConfig(tlsConfigMap map[interface{}]interface{}, path string, client bool) (retval tls.Config, err error) {
	_cipherSuites, ok := tlsConfigMap["ciphers"]
	if ok {
		cipherSuites, ok := _cipherSuites.([]interface{})
		if !ok {
			err = fmt.Errorf("%s: invalid value for %s/ciphers", ctx.Filename, path)
			return
		}
		retval.CipherSuites = make([]uint16, 0, len(cipherSuites))
		for _, __cipherSuite := range cipherSuites {
			var cipherSuite uint16
			_cipherSuite, ok := __cipherSuite.(string)
			if ok {
				_cipherSuite = strings.ToUpper(_cipherSuite)
				cipherSuite, ok = cipherSuiteValues[_cipherSuite]
			}
			if !ok {
				err = fmt.Errorf("%s: invalid value for %s/ciphers", ctx.Filename, path)
				return
			}
			retval.CipherSuites = append(retval.CipherSuites, cipherSuite)
		}
	}

	__minVersion, ok := tlsConfigMap["min_version"]
	if ok {
		var minVersion uint16
		_minVersion, ok := __minVersion.(string)
		if ok {
			_minVersion = strings.ToUpper(_minVersion)
			minVersion, ok = tlsVersionValues[_minVersion]
		}
		if !ok {
			err = fmt.Errorf("%s: invalid value for %s/min_version", ctx.Filename, path)
			return
		}
		retval.MinVersion = minVersion
	}

	__maxVersion, ok := tlsConfigMap["max_version"]
	if ok {
		var maxVersion uint16
		_maxVersion, ok := __maxVersion.(string)
		if ok {
			_maxVersion = strings.ToUpper(_maxVersion)
			maxVersion, ok = tlsVersionValues[_maxVersion]
		}
		if !ok {
			err = fmt.Errorf("%s: invalid value for %s/max_version", ctx.Filename, path)
			return
		}
		retval.MaxVersion = maxVersion
	}

	__certs, ok := tlsConfigMap["certs"]
	if ok {
		_certs, ok := __certs.([]interface{})
		if !ok {
			err = fmt.Errorf("%s: invalid value for %s/certs", ctx.Filename, path)
			return
		}
		certs := make([]tls.Certificate, 0)
		for i, __cert := range _certs {
			_cert, ok := __cert.(map[interface{}]interface{})
			if !ok {
				err = fmt.Errorf("%s: invalid structure under %s/certs/@%d", ctx.Filename, path, i)
				return
			}
			var cert tls.Certificate
			cert, _, err = ctx.extractCertPrivateKeyPairs(_cert, fmt.Sprintf("%s/certs/@%d", path, i))
			if err != nil {
				return
			}
			certs = append(certs, cert)
		}
		retval.Certificates = certs
		retval.BuildNameToCertificate()
	}

	if !client {
		clientAuth := tls.NoClientCert
		__clientAuth, ok := tlsConfigMap["client_auth"]
		if ok {
			_clientAuth, ok := __clientAuth.(map[interface{}]interface{})
			if !ok {
				err = fmt.Errorf("%s: invalid value for %s/client_auth", ctx.Filename, path)
				return
			}
			_type, ok := _clientAuth["type"]
			if !ok {
				err = fmt.Errorf("%s: missing setting \"type\" under %s/client_auth", ctx.Filename, path)
				return
			}
			type_, ok := (_type).(string)
			if !ok {
				err = fmt.Errorf("%s: invalid value for %s/client_auth/type", ctx.Filename, path)
				return
			}
			clientAuth, ok = clientAuthTypeValues[type_]
			if clientAuth != tls.NoClientCert {
				_clientCA, ok := _clientAuth["ca_certs"]
				if ok {
					retval.ClientCAs, err = ctx.extractCertPool(_clientCA, path+"/client_auth/ca_certs")
					if err != nil {
						return
					}
				}
			}
		}
		retval.ClientAuth = clientAuth
	} else {
		_verify, ok := tlsConfigMap["verify"]
		if ok {
			verify, ok := _verify.(bool)
			if !ok {
				err = fmt.Errorf("%s: invalid value for %s/verify", ctx.Filename, path)
				return
			}
			retval.InsecureSkipVerify = verify
		}
		_preferServerCiphers, ok := tlsConfigMap["prefer_server_ciphers"]
		if ok {
			preferServerCiphers, ok := _preferServerCiphers.(bool)
			if !ok {
				err = fmt.Errorf("%s: invalid value for %s/preferServerCiphers", ctx.Filename, path)
				return
			}
			retval.PreferServerCipherSuites = preferServerCiphers
		}
		_certs, ok := tlsConfigMap["ca_certs"]
		if ok {
			retval.RootCAs, err = ctx.extractCertPool(_certs, path+"/ca_certs")
			if err != nil {
				return
			}
		}
	}
	return
}

func (ctx *ConfigReaderContext) extractMITMConfig(configMap map[string]interface{}) (retval MITMConfig, err error) {
	__tls, ok := configMap["tls"]
	if ok {
		_tls, ok := __tls.(map[interface{}]interface{})
		if !ok {
			err = fmt.Errorf("%s: invalid structure under tls", ctx.Filename)
			return
		}
		__client, ok := _tls["client"]
		if ok {
			_client, ok := __client.(map[interface{}]interface{})
			if !ok {
				err = fmt.Errorf("%s: invalid structure under tls/client", ctx.Filename)
				return
			}
			retval.ClientTLSConfigTemplate, err = ctx.extractTLSConfig(_client, "tls/client", true)
			if err != nil {
				return
			}
		}
		__server, ok := _tls["server"]
		if ok {
			_server, ok := __server.(map[interface{}]interface{})
			if !ok {
				err = fmt.Errorf("%s: invalid structure under tls/server", ctx.Filename)
				return
			}
			retval.ClientTLSConfigTemplate, err = ctx.extractTLSConfig(_server, "tls/server", false)
			if err != nil {
				return
			}
		}
		__ca, ok := _tls["ca"]
		if !ok {
			err = fmt.Errorf("%s: item \"ca\" must exist under tls", ctx.Filename)
			return
		}
		_ca, ok := __ca.(map[interface{}]interface{})
		if !ok {
			err = fmt.Errorf("%s: invalid structure under tls/ca", ctx.Filename)
			return
		}
		var tlsCert tls.Certificate
		tlsCert, retval.SigningCertificateKeyPair.Certificate, err = ctx.extractCertPrivateKeyPairs(_ca, "tls/ca")
		if err != nil {
			return
		}
		retval.SigningCertificateKeyPair.PrivateKey = tlsCert.PrivateKey
	}
	return
}

func loadConfig(yamlFile string, progname string) (*Config, error) {
	f, err := os.Open(yamlFile)
	if err != nil {
		return nil, fmt.Errorf("failed to load %s (%s)", yamlFile, err.Error())
	}
	configMap := make(map[string]interface{})
	err = candiedyaml.NewDecoder(f).Decode(&configMap)
	if err != nil {
		return nil, fmt.Errorf("failed to load %s (%s)", yamlFile, err.Error())
	}
	ctx := &ConfigReaderContext{
		Filename: yamlFile,
		Warn: func(msg string) {
			fmt.Fprintf(os.Stderr, "%s: %s\n", progname, msg)
		},
	}
	perHostConfigs, err := ctx.extractPerHostConfigs(configMap)
	if err != nil {
		return nil, err
	}
	proxy, err := ctx.extractProxyConfig(configMap)
	if err != nil {
		return nil, err
	}
	mitm, err := ctx.extractMITMConfig(configMap)
	if err != nil {
		return nil, err
	}
	return &Config{
		Hosts: perHostConfigs,
		Proxy: proxy,
		MITM:  mitm,
	}, nil
}

type OurContext struct {
	Verbose          bool
	Logger           *logrus.Logger
	LogWriter        io.WriteCloser
	StdLogger        *log.Logger
	Config           *Config
	HTMLMediaTypes   []string
	DefaultCharset   string
	LabelHTML        []byte
	InsertBefore     []byte
	CryptoRandReader io.Reader
	Now              func() time.Time
	certCache        map[string]*tls.Certificate
}

func (ctx *OurContext) proxyIsApplicable(req *http.Request) bool {
	pcfg := ctx.Config.Proxy
	if len(pcfg.IncludedHosts) > 0 {
		pairs := toHostPortPairs(req.URL)
		for _, a := range pcfg.IncludedHosts {
			for _, b := range pairs {
				if a == b {
					return true
				}
			}
		}
		return false
	} else if len(pcfg.ExcludedHosts) > 0 {
		pairs := toHostPortPairs(req.URL)
		for _, a := range pcfg.ExcludedHosts {
			for _, b := range pairs {
				if a == b {
					return false
				}
			}
		}
		return true
	} else {
		return true
	}
}

func (ctx *OurContext) getProxyUrlForRequest(req *http.Request) (*url.URL, error) {
	if !ctx.proxyIsApplicable(req) {
		ctx.Logger.Debugf("No outbound proxy is applicable for %s", req.URL.String())
		return nil, nil
	}
	if req.URL.Scheme == "https" {
		if ctx.Config.Proxy.HTTPSProxy != nil {
			return ctx.Config.Proxy.HTTPSProxy, nil
		}
	}
	// falls back to http
	if req.URL.Scheme == "https" || req.URL.Scheme == "http" {
		if ctx.Config.Proxy.HTTPProxy != nil {
			return ctx.Config.Proxy.HTTPProxy, nil
		}
	}
	return nil, nil
}

func (ctx *OurContext) newTLSConfigFactory() TLSConfigFactory {
	if ctx.Config.MITM.SigningCertificateKeyPair.Certificate == nil {
		return nil
	}
	return func(hostPortPairStr string, proxyCtx *OurProxyCtx) (*tls.Config, error) {
		pair := splitHostPort(hostPortPairStr)
		config := ctx.Config.MITM.ServerTLSConfigTemplate
		ctx.Logger.Infof("Generate temporary certificate for %s", pair.Host)
		cert, err := ctx.generateCertificate([]string{pair.Host})
		if err != nil {
			ctx.Logger.Warnf("Cannot sign host certificate with provided CA: %s", err)
			return nil, err
		}
		config.Certificates = append(config.Certificates, *cert)
		return &config, nil
	}
}

func (ctx *OurContext) newProxyURLBuilder() func(*http.Request) (*url.URL, error) {
	return func(req *http.Request) (*url.URL, error) {
		return ctx.getProxyUrlForRequest(req)
	}
}

func (ctx *OurContext) newHttpTransport() *http.Transport {
	return &http.Transport{
		TLSClientConfig: &ctx.Config.MITM.ClientTLSConfigTemplate,
		Proxy:           ctx.newProxyURLBuilder(),
	}
}

func (ctx *OurContext) generateCertificate(hosts []string) (*tls.Certificate, error) {
	sortedHosts := make([]string, len(hosts))
	copy(sortedHosts, hosts)
	sort.Strings(sortedHosts)
	key := strings.Join(sortedHosts, ";")
	if cert, ok := ctx.certCache[key]; ok {
		return cert, nil
	}
	ca := ctx.Config.MITM.SigningCertificateKeyPair
	ctx.Logger.Debugf("CA: CN=%s", ca.Certificate.Subject.CommonName)
	start := time.Date(ctx.Now().Year(), 1, 1, 0, 0, 0, 0, time.UTC)
	end := time.Date(ctx.Now().Year() + 1, 1, 1, 0, 0, 0, 0, time.UTC)

	h := sha1.New()
	h.Write([]byte(key))
	binary.Write(h, binary.BigEndian, start)
	binary.Write(h, binary.BigEndian, end)
	hash := h.Sum(nil)
	serial := big.Int{}
	serial.SetBytes(hash)
	ctx.Logger.Debugf("Generated serial=%v", serial)

	template := x509.Certificate{
		SignatureAlgorithm: ca.Certificate.SignatureAlgorithm,
		SerialNumber:       &serial,
		Issuer:             ca.Certificate.Subject,
		Subject: pkix.Name{
			Organization: []string{"GoProxy untrusted MITM proxy"},
			CommonName:   hosts[0],
		},
		NotBefore:             start,
		NotAfter:              end,
		KeyUsage:              x509.KeyUsageKeyEncipherment | x509.KeyUsageDataEncipherment | x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
		IsCA:           false,
		MaxPathLen:     0,
		MaxPathLenZero: true,
		DNSNames:       hosts,
	}
	derBytes, err := x509.CreateCertificate(ctx.CryptoRandReader, &template, ca.Certificate, ca.Certificate.PublicKey, ca.PrivateKey)
	if err != nil {
		return nil, err
	}
	cert := &tls.Certificate{
		Certificate: [][]byte{derBytes, ca.Certificate.Raw},
		PrivateKey:  ca.PrivateKey,
	}
	ctx.certCache[key] = cert
	return cert, nil
}

func (ctx *OurContext) checkIfRequestMatchesToUrl(url_ *url.URL, secureOnly bool, req *http.Request, _ *OurProxyCtx) bool {
	if req.Method == "CONNECT" {
		return false
	}
	if secureOnly && url_.Scheme != "https" {
		return false
	}
	if req.URL.Scheme != url_.Scheme {
		return false
	}
	reqPairs := toHostPortPairs(req.URL)
	givenPairs := toHostPortPairs(url_)
	for _, a := range reqPairs {
		for _, b := range givenPairs {
			if a.Host == b.Host && a.Port == b.Port {
				return true
			}
		}
	}
	return false
}

func (ctx *OurContext) checkIfTunnelRequestMatchesToUrl(url_ *url.URL, req *http.Request, _ *OurProxyCtx) bool {
	if req.Method != "CONNECT" || req.URL.Scheme != "" {
		return false
	}
	if url_.Scheme != "https" {
		return false
	}
	a := splitHostPort(req.Host)
	if a.Port == "" {
		ctx.Logger.Warnf("invalid request")
		return false
	}
	for _, b := range toHostPortPairs(url_) {
		if a.Host == b.Host && a.Port == b.Port {
			return true
		}
	}
	return false
}

/* copy and pasted from github.com/elazarl/goproxy */
func (proxy *OurProxyHttpServer) ConnectDial(network, addr string) (c net.Conn, err error) {
	if proxy.Tr.Dial != nil {
		return proxy.Tr.Dial(network, addr)
	}
	return net.Dial(network, addr)
}

type OurProxyHttpServer struct {
	Ctx *OurContext
	Logger *logrus.Logger
	Tr *http.Transport
	TLSConfigFactory TLSConfigFactory
	SessionSerial int64
}

type OurProxyCtx struct {
	Proxy *OurProxyHttpServer
	Logger *logrus.Logger
	OrigReq *http.Request
	Req *http.Request
	OrigResp *http.Response
	Resp *http.Response
	Tr *http.Transport
	Error error
	Session int64
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

func (perHostConfig *PerHostConfig) FilterRequest(r *http.Request, proxyCtx *OurProxyCtx) (*http.Request, *http.Response) {
	newUrlString := ""
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
			break
		}
	}
	if newUrlString != "" {
		newUrl, err := url.Parse(newUrlString)
		if err != nil {
			proxyCtx.Logger.Error(err)
		}
		newUrl.User = r.URL.User
		newRequest := CloneRequest(r)
		newRequest.URL = newUrl
		proxyCtx.Logger.Infof("%s %s => %s", r.Method, r.RequestURI, newRequest.URL.String())
		return newRequest, nil
	} else {
		proxyCtx.Logger.Infof("%s %s", r.Method, r.RequestURI)
		return r, nil
	}
}

func (proxyCtx *OurProxyCtx) NewTLSConfig(r *http.Request) (*tls.Config, error) {
	return proxyCtx.Proxy.TLSConfigFactory(r.URL.Host, proxyCtx)
}

func (proxyCtx *OurProxyCtx) FilterRequest(r *http.Request) (req *http.Request, resp *http.Response) {
	for _, perHostConfig := range proxyCtx.Proxy.Ctx.Config.Hosts {
		if proxyCtx.Proxy.Ctx.checkIfRequestMatchesToUrl(perHostConfig.Host, false, r, proxyCtx) {
			return perHostConfig.FilterRequest(r, proxyCtx)
		}
	}
	return r, nil
}

func (proxyCtx *OurProxyCtx) FilterResponse(resp *http.Response) *http.Response {
	if proxyCtx.OrigReq != proxyCtx.Req {
		if resp == nil {
			return resp
		}
		contentType, ok := resp.Header[contentTypeKey]
		if !ok || len(contentType) == 0 {
			return resp
		}
		mimeType, params, err := mime.ParseMediaType(contentType[0])
		if err != nil {
			proxyCtx.Logger.Warnf("invalid Content-Type header: %s", contentType[0])
			return resp
		}
		applicable := false
		for _, v := range proxyCtx.Proxy.Ctx.HTMLMediaTypes {
			if v == mimeType {
				applicable = true
				break
			}
		}
		if !applicable {
			return resp
		}
		charset, ok := params["charset"]
		if !ok {
			charset = "UTF-8"
		}
		if charset == "UTF-16" {
			return resp
		}
		if unsafe.Sizeof(resp.ContentLength) != unsafe.Sizeof(int(0)) {
			if resp.ContentLength > math.MaxInt32 {
				proxyCtx.Logger.Errorf("failed to read response body (%d expected)", resp.ContentLength)
			}
		}
		contentLength := int(resp.ContentLength)
		body := []byte{}
		defer resp.Body.Close()
		if contentLength >= 0 {
			body = make([]byte, contentLength)
			n, err := io.ReadFull(resp.Body, body)
			if err != nil || (err == io.EOF && n < contentLength) {
				proxyCtx.Logger.Errorf("failed to read response body (%d bytes read, %d bytes expected): %s", n, contentLength, err.Error())
			}
		} else {
			err := error(nil)
			body, err = ioutil.ReadAll(resp.Body)
			if err != nil {
				proxyCtx.Logger.Errorf("failed to read response body: %s", err.Error())
			}
		}
		p := bytes.LastIndex(body, proxyCtx.Proxy.Ctx.InsertBefore)
		if p > 0 {
			newBody := make([]byte, 0, len(body)+len(proxyCtx.Proxy.Ctx.LabelHTML))
			newBody = append(newBody, body[0:p]...)
			newBody = append(newBody, proxyCtx.Proxy.Ctx.LabelHTML...)
			newBody = append(newBody, body[p:]...)
			body = newBody
		}
		newResp := new(http.Response)
		*newResp = *resp
		newResp.Body = ioutil.NopCloser(bytes.NewBuffer(body))
		return newResp
	} else {
		return resp
	}
}

func (proxy *OurProxyHttpServer) HandleNonProxyRequest(w http.ResponseWriter, r *http.Request) {
	http.Error(w, "This is a proxy server. Does not respond to non-proxy requests.", 400)
}

func (ctx *OurContext) unidiTunnel(wg *sync.WaitGroup, connA net.Conn, connB net.Conn) {
	defer wg.Done()
	n, err := io.Copy(connA, connB)
	msg := fmt.Sprintf("%d bytes transferred from %s to %s", n, connA, connB)
	if err != nil && err != io.EOF {
		ctx.Logger.Errorf("%s; %s", err.Error(), msg)
	} else {
		ctx.Logger.Debug(msg)
	}
}

func (ctx *OurContext) bidiTunnel(connA net.Conn, connB net.Conn) {
	wg := &sync.WaitGroup {}
	wg.Add(1)
	go ctx.unidiTunnel(wg, connA, connB)
	wg.Add(1)
	go ctx.unidiTunnel(wg, connB, connA)
	wg.Wait()
}

/* --- BEGIN pasted from src/net/http/client.go -- */
// cancelTimerBody is an io.ReadCloser that wraps rc with two features:
// 1) on Read EOF or Close, the timer t is Stopped,
// 2) On Read failure, if reqWasCanceled is true, the error is wrapped and
//    marked as net.Error that hit its timeout.
type cancelTimerBody struct {
	t              *time.Timer
	rc             io.ReadCloser
	canceled       *int32
}

func (b *cancelTimerBody) Read(p []byte) (n int, err error) {
	n, err = b.rc.Read(p)
	if err == io.EOF {
		b.t.Stop()
	} else if err != nil && atomic.LoadInt32(b.canceled) != 0 {
		return n, fmt.Errorf("%s: timeout exceeded", err.Error())
	}
	return
}

func (b *cancelTimerBody) Close() error {
	err := b.rc.Close()
	b.t.Stop()
	return err
}
/* --- END pasted from src/net/http/client.go -- */

func (proxyCtx *OurProxyCtx) DoRequest(req *http.Request, timeout time.Duration) (*http.Response, error) {
	defer func () { if (req.Body != nil) { req.Body.Close() } }()

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
			return nil, fmt.Errorf("%s: timeout exceeded", err.Error())
		}
		return nil, err
	}

	if timer != nil {
		resp.Body = &cancelTimerBody{
			t:              timer,
			rc:             resp.Body,
			canceled:       &canceled,
		}
	}
	return resp, nil
}

func (proxyCtx *OurProxyCtx) HandleConnect(r *http.Request, proxyClient net.Conn) {
	connClosers := []func() error { proxyClient.Close }
	defer func() {
		i := len(connClosers)
		for {
			i--
			if i < 0 {
				break
			}
			connCloser := connClosers[i]
			err := connCloser()
			if err != nil {
				proxyCtx.Logger.Warnf("failed to close connection (%s)", err.Error())
			}
		}
	}()

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
			connClosers[0] = clientTlsConn.Close

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
			req, resp := perHostConfig.FilterRequest(req, nestedProxyCtx)
			nestedProxyCtx.Req = req

			if resp == nil {
				removeProxyHeaders(req)
				resp, err = nestedProxyCtx.DoRequest(req, 0)
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
	targetConn, err := proxyCtx.Proxy.ConnectDial("tcp", targetHostPort)
	if err != nil {
		proxyCtx.Logger.Errorf("failed to connect to %s (%s)", targetHostPort, err.Error())
		if _, err := proxyClient.Write(http10BadGatewayBytes); err != nil {
			proxyCtx.Logger.Errorf("failed to send response to client (%s)", err.Error())
		}
		return
	}
	connClosers = append(connClosers, targetConn.Close)
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

func removeProxyHeaders(r *http.Request) {
	r.RequestURI = ""
	r.Header.Del("Accept-Encoding")
	r.Header.Del("Proxy-Connection")
	r.Header.Del("Proxy-Authenticate")
	r.Header.Del("Proxy-Authorization")
	r.Header.Del("Connection")
}


func (proxy *OurProxyHttpServer) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	proxyCtx := &OurProxyCtx{
		Proxy: proxy,
		Logger: proxy.Logger,
		OrigReq: r,
		Req: r,
		OrigResp: nil,
		Resp: nil,
		Session: atomic.AddInt64(&proxy.SessionSerial, 1),
		Tr: proxy.Tr,
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
			resp, err = proxyCtx.DoRequest(r, 0)
			if err != nil {
				proxyCtx.Error = err
				resp = proxyCtx.FilterResponse(nil)
				if resp == nil {
					proxyCtx.Logger.Errorf("error read response %v %v:", r.URL.Host, err.Error())
					http.Error(w, err.Error(), 500)
					return
				}
			}
			proxyCtx.Logger.Debugf("Received response %v", resp.Status)
		}
		proxyCtx.OrigResp = resp
		resp = proxyCtx.FilterResponse(resp)
		resp.ContentLength = -1
		if resp.Header != nil {
			resp.Header.Del("Content-Length")
		}
		proxyCtx.Logger.Debugf("Copying response to client %v [%d]", resp.Status, resp.StatusCode)
		proxyCtx.SendToClient(w, resp)
	}
}


func (ctx *OurContext) newProxyHttpServer() *OurProxyHttpServer {
	return &OurProxyHttpServer{
		Ctx: ctx,
		Logger: ctx.Logger,
		Tr: ctx.newHttpTransport(),
		TLSConfigFactory: ctx.newTLSConfigFactory(),
		SessionSerial: 0,
	}
}

func (ctx *OurContext) Dispose() {
	ctx.LogWriter.Close()
}

func main() {
	var listenOn string
	var verbose bool
	progname := os.Args[0]
	flag.StringVar(&listenOn, "l", ":8080", "\"addr:port\" on which the server listens")
	flag.BoolVar(&verbose, "v", false, "verbose output")
	flag.Parse()
	args := flag.Args()
	if len(args) < 1 {
		fmt.Fprintf(os.Stderr, "usage: %s -l [LISTEN] -v config\n", progname)
		flag.PrintDefaults()
		os.Exit(255)
	}
	config, err := loadConfig(args[0], progname)
	if err != nil {
		fmt.Fprintf(os.Stderr, "%s: %s\n", progname, err.Error())
		os.Exit(1)
	}
	if len(config.Hosts) == 0 {
		fmt.Fprintf(os.Stderr, "%s: warning: no patterns defined\n", progname)
	}
	logger := &logrus.Logger{
		Out: os.Stderr,
		Formatter: &logrus.TextFormatter{
			ForceColors:      false,
			DisableColors:    false,
			DisableTimestamp: false,
			FullTimestamp:    true,
			TimestampFormat:  time.RFC3339Nano,
			DisableSorting:   false,
		},
		Level: logrus.InfoLevel,
	}
	if verbose {
		logger.Level = logrus.DebugLevel
	}
	logWriter := logger.Writer()
	ctx := OurContext{
		Verbose:        verbose,
		Logger:         logger,
		LogWriter:      logWriter,
		StdLogger:      log.New(logWriter, "", 0),
		Config:         config,
		DefaultCharset: "UTF-8",
		HTMLMediaTypes: []string{
			"text/html",
			"application/xhtml+xml",
		},
		InsertBefore:     []byte(`</body>`),
		LabelHTML:        []byte(`<div style="position:fixed;left:0;top:0;width:100%;background-color:#ff0">DEVELOPMENT</div>`),
		CryptoRandReader: crand.Reader,
		Now:              time.Now,
		certCache:        make(map[string]*tls.Certificate, 0),
	}
	defer ctx.Dispose()
	proxy := ctx.newProxyHttpServer()
	logger.Infof("Listening on %s...", listenOn)
	logger.Fatal(http.ListenAndServe(listenOn, proxy))
}
