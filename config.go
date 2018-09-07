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
	"crypto"
	"crypto/ecdsa"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"io/ioutil"
	"net"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"time"

	"github.com/cloudfoundry-incubator/candiedyaml"
	"github.com/pkg/errors"
)

type ResponseFilterFactory func(*ConfigReaderContext, map[interface{}]interface{}) (ResponseFilter, error)

type Pattern struct {
	Pattern      *regexp.Regexp
	Substitution string
	Headers      http.Header
}

type PerHostConfig struct {
	Host     *url.URL
	Patterns []Pattern
}

type MITMConfig struct {
	ServerTLSConfigTemplate   *tls.Config
	ClientTLSConfigTemplate   *tls.Config
	SigningCertificateKeyPair struct {
		Certificate *x509.Certificate
		PrivateKey  crypto.PrivateKey
	}
	CacheDirectory string
	DisableCache   bool
}

type ProxyConfig struct {
	HTTPProxy     *url.URL
	HTTPSProxy    *url.URL
	IncludedHosts []HostPortPair
	ExcludedHosts []HostPortPair
	TLSConfig     *tls.Config
}

type Config struct {
	Hosts           map[string]*PerHostConfig
	Proxy           ProxyConfig
	MITM            MITMConfig
	ResponseFilters []ResponseFilter
	NowGetter       func() (time.Time, error)
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

type ConfigReaderContext struct {
	Filename string
	Warn     func(string)
}

func (ctx *ConfigReaderContext) extractPerHostConfigs(configMap map[string]interface{}) (map[string]*PerHostConfig, error) {
	__hosts, ok := configMap["hosts"]
	if !ok {
		return make(map[string]*PerHostConfig), nil
	}
	_hosts, ok := __hosts.(map[interface{}]interface{})
	if !ok {
		return nil, errors.Errorf("%s: invalid structure under hosts", ctx.Filename)
	}
	perHostConfigs := make(map[string]*PerHostConfig)
	for __url, __patterns := range _hosts {
		_url, ok := __url.(string)
		if !ok {
			return nil, errors.Errorf("%s: invalid structure under hosts", ctx.Filename)
		}
		url, err := url.Parse(_url)
		if err != nil {
			return nil, errors.Wrapf(err, "%s: invalid value for URL (%s) under hosts", ctx.Filename, _url)
		}
		if url.Path != "" {
			return nil, errors.Errorf("%s: path may not be present: %s", ctx.Filename, _url)
		}
		_patterns, ok := __patterns.([]interface{})
		if !ok {
			return nil, errors.Errorf("%s: invalid structure under hosts/%s", ctx.Filename, _url)
		}
		patterns := make([]Pattern, 0)
		for _, ___pattern := range _patterns {
			__pattern, ok := ___pattern.(map[interface{}]interface{})
			if !ok {
				return nil, errors.Errorf("%s: invalid structure under hosts/%s", ctx.Filename, _url)
			}
			headers := make(http.Header)
			patternOccurred := false
			for _pattern, _substitution := range __pattern {
				pattern, ok := _pattern.(string)
				if !ok {
					return nil, errors.Errorf("%s: invalid structure under hosts/%s", ctx.Filename, _url)
				}
				if pattern == "headers" {
					__headers, ok := _substitution.(map[interface{}]interface{})
					if !ok {
						return nil, errors.Errorf("%s: invalid structure under hosts/%s/%s", ctx.Filename, _url, pattern)
					}
					for _headerName, __values := range __headers {
						headerName, ok := _headerName.(string)
						if !ok {
							return nil, errors.Errorf("%s: invalid structure under hosts/%s/%s", ctx.Filename, _url, pattern)
						}
						values := ([]string)(nil)
						if __values != nil {
							_values, ok := __values.([]interface{})
							if ok {
								values = make([]string, len(_values))
								for i, _header := range _values {
									header, ok := _header.(string)
									if !ok {
										return nil, errors.Errorf("%s: invalid structure under hosts/%s/%s/%s", ctx.Filename, _url, pattern, headerName)
									}
									values[i] = header
								}
							} else {
								value, ok := __values.(string)
								if !ok {
									return nil, errors.Errorf("%s: invalid structure under hosts/%s/%s/%s", ctx.Filename, _url, pattern, headerName)
								}
								values = []string{value}
							}
						}
						headers[headerName] = values
					}
				} else {
					if patternOccurred {
						return nil, errors.Errorf("%s: invalid structure under hosts/%s", ctx.Filename, _url)
					}
					substitution, ok := _substitution.(string)
					if !ok {
						return nil, errors.Errorf("%s: invalid structure under hosts/%s", ctx.Filename, _url)
					}
					patternRegexp, err := regexp.Compile(pattern)
					if err != nil {
						return nil, errors.Errorf("%s: invalid regexp %s for %s configuration", ctx.Filename, pattern, _url)
					}
					patterns = append(patterns, Pattern{Pattern: patternRegexp, Substitution: substitution, Headers: headers})
					patternOccurred = true
				}
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
			err = errors.Errorf("%s: invalid structure under proxy", ctx.Filename)
			return
		}
		_httpProxy, ok := _proxy["http"]
		if ok {
			httpProxy, ok := _httpProxy.(string)
			if !ok {
				err = errors.Errorf("%s: invalid value for proxy/http_proxy", ctx.Filename)
				return
			}
			var httpProxyUrl *url.URL
			httpProxyUrl, err = parseUrlOrHostPortPair(httpProxy)
			if err != nil {
				err = errors.Wrapf(err, "%s: invalid value for proxy/http_proxy", ctx.Filename)
				return
			}
			retval.HTTPProxy = httpProxyUrl
		}
		_httpsProxy, ok := _proxy["https"]
		if ok {
			httpsProxy, ok := _httpsProxy.(string)
			if !ok {
				err = errors.Errorf("%s: invalid value for proxy/http_proxy", ctx.Filename)
				return
			}
			var httpsProxyUrl *url.URL
			httpsProxyUrl, err = parseUrlOrHostPortPair(httpsProxy)
			if err != nil {
				err = errors.Wrapf(err, "%s: invalid value for proxy/http_proxy", ctx.Filename)
				return
			}
			retval.HTTPSProxy = httpsProxyUrl
		}
		__includedHosts, ok := _proxy["included"]
		if ok {
			_includedHosts, ok := __includedHosts.([]interface{})
			if !ok {
				err = errors.Errorf("%s: invalid value for proxy/included", ctx.Filename)
				return
			}
			includedHosts, ok := convertToStringList(_includedHosts)
			if !ok {
				err = errors.Errorf("%s: invalid value for proxy/included", ctx.Filename)
				return
			}
			retval.IncludedHosts, err = convertUnparsedHostsIntoPairs(includedHosts)
			if err != nil {
				err = errors.Wrapf(err, "invalid host-port pair contained in NO_PROXY")
				return
			}
		}
		__excludedHosts, ok := _proxy["excluded"]
		if ok {
			_excludedHosts, ok := __excludedHosts.([]interface{})
			if !ok {
				err = errors.Errorf("%s: invalid value for proxy/excluded", ctx.Filename)
				return
			}
			excludedHosts, ok := convertToStringList(_excludedHosts)
			if !ok {
				err = errors.Errorf("%s: invalid value for proxy/excluded", ctx.Filename)
				return
			}
			retval.ExcludedHosts, err = convertUnparsedHostsIntoPairs(excludedHosts)
			if err != nil {
				err = errors.Wrapf(err, "invalid host-port pair contained in NO_PROXY")
				return
			}
		}
		__tlsConfig, ok := _proxy["tls"]
		if ok {
			_tlsConfig, ok := __tlsConfig.(map[interface{}]interface{})
			if !ok {
				err = errors.Errorf("%s: invalid value for proxy/tls", ctx.Filename)
				return
			}
			retval.TLSConfig, err = ctx.extractTLSConfig(_tlsConfig, "proxy/tls", true)
			if err != nil {
				return
			}
		} else {
			retval.TLSConfig = new(tls.Config)
		}
	}
	envUsed := false
	if retval.HTTPProxy == nil {
		httpProxy := getenv("http_proxy")
		if httpProxy != "" {
			retval.HTTPProxy, err = parseUrlOrHostPortPair(httpProxy)
			if err != nil {
				err = errors.Wrapf(err, "invalid value for HTTP_PROXY")
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
				err = errors.Wrapf(err, "invalid value for HTTPS_PROXY")
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
			err = errors.Wrapf(err, "invalid host-port pair contained in NO_PROXY")
			return
		}
	}
	return
}

func (ctx *ConfigReaderContext) extractCertPool(certPoolConfig interface{}, path string) (*x509.CertPool, error) {
	pool := x509.NewCertPool()
	fileOrDirectory, ok := certPoolConfig.(string)
	if ok {
		var f *os.File
		f, err := os.Open(fileOrDirectory)
		if err != nil && !os.IsNotExist(err) {
			return nil, errors.Errorf("%s: failed to open %s", ctx.Filename, fileOrDirectory)
		}
		if err == nil {
			var traverse func(f *os.File) error
			traverse = func(f *os.File) error {
				st, err := f.Stat()
				if err != nil {
					return errors.Wrapf(err, "%s: failed to open %s", ctx.Filename, f.Name())
				}
				if st.IsDir() {
					children, err := f.Readdir(-1)
					if err != nil {
						return errors.Wrapf(err, "%s: failed to read directory entry under %s", ctx.Filename, f.Name())
					}
					for _, child := range children {
						cp := filepath.Join(f.Name(), child.Name())
						cf, err := os.Open(cp)
						if err != nil {
							return errors.Wrapf(err, "%s: failed to open %s", ctx.Filename, cp)
						}
						err = traverse(cf)
						if err != nil {
							return err
						}
					}
				} else {
					pems, err := ioutil.ReadAll(f)
					if err != nil {
						return errors.Wrapf(err, "%s: failed to read certificates from %s", ctx.Filename, f.Name())
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
				return nil, errors.Errorf("%s: %s does not exist", ctx.Filename, fileOrDirectory)
			}
		}
		return pool, nil
	}
	_certList, ok := certPoolConfig.([]interface{})
	if ok {
		for _, _certs := range _certList {
			certs, ok := _certs.(string)
			if !ok {
				return nil, errors.Errorf("%s: every item under %s must be a string", ctx.Filename, path)
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
				return nil, errors.Errorf("%s: value for %s/%s must be a string", ctx.Filename, path, name)
			}
			if !pool.AppendCertsFromPEM([]byte(certs)) {
				ctx.Warn("failed to parse some certificates")
			}
		}
		return pool, nil
	}
	return nil, errors.Errorf("%s: invalid structure under %s", ctx.Filename, path)
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
				return nil, nil, errors.Errorf("duplicate private keys exist")
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
		err = errors.Errorf("%s: missing item \"cert\" under %s", ctx.Filename, path)
		return
	}
	filenameOrPem, ok := _filenamePemOrList.(string)
	if ok {
		var f *os.File
		f, err = os.Open(filenameOrPem)
		if err != nil && !os.IsNotExist(err) {
			err = errors.Wrapf(err, "%s: could not open %s", ctx.Filename, filenameOrPem)
			return
		}
		if err == nil {
			var pemBytes []byte
			pemBytes, err = ioutil.ReadAll(f)
			if err != nil {
				err = errors.Wrapf(err, "%s: could not read data from %s", ctx.Filename, filenameOrPem)
				return
			}
			certs, key, err = parsePemBlocks(pemBytes, ctx.Warn)
			if err != nil {
				err = errors.Wrapf(err, "%s: failed to parse certificates or private keys", ctx.Filename)
				return
			}
		} else {
			certs, key, err = parsePemBlocks([]byte(filenameOrPem), ctx.Warn)
			if err != nil {
				err = errors.Wrapf(err, "%s: failed to parse certificates or private keys", ctx.Filename)
				return
			}
		}
	} else {
		certs = make([][]byte, 0, 1)
		list, ok := _filenamePemOrList.([]interface{})
		if !ok {
			err = errors.Errorf("%s: %s/cert must be a string or a list of PEM-formatted certificates / private key", ctx.Filename, path)
			return
		}
		for _, _pem := range list {
			pem, ok := _pem.(string)
			if !ok {
				err = errors.Errorf("%s: every item under %s/cert must be a PEM-formatted certificates / private key", ctx.Filename, path)
				return
			}
			var _certs [][]byte
			var _key crypto.PrivateKey
			_certs, _key, err = parsePemBlocks([]byte(pem), ctx.Warn)
			if err != nil {
				err = errors.Wrapf(err, "%s: failed to parse certificates or private keys", ctx.Filename)
				return
			}
			if _key != nil {
				if key != nil {
					err = errors.Errorf("duplicate private keys exist")
					return
				}
			}
			certs = append(certs, _certs...)
			key = _key
		}
	}
	if len(certs) == 0 {
		err = errors.Errorf("%s: no certificates exist in %s/cert", ctx.Filename, path)
		return
	}

	_filenamePemOrList, ok = certConfigMap["key"]
	if ok {
		if key != nil {
			err = errors.Errorf("%s: private keys exist both in %s/cert and %s/key", ctx.Filename, path, path)
			return
		}
		filenameOrPem, ok := _filenamePemOrList.(string)
		if ok {
			var f *os.File
			var _certs [][]byte
			f, err = os.Open(filenameOrPem)
			if err != nil && !os.IsNotExist(err) {
				err = errors.Wrapf(err, "%s: could not open %s", ctx.Filename, filenameOrPem)
				return
			}
			if err == nil {
				var pemBytes []byte
				pemBytes, err = ioutil.ReadAll(f)
				if err != nil {
					err = errors.Wrapf(err, "%s: could not read data from %s", ctx.Filename, filenameOrPem)
					return
				}
				_certs, key, err = parsePemBlocks(pemBytes, ctx.Warn)
				if err != nil {
					err = errors.Wrapf(err, "%s: failed to parse certificates or private keys", ctx.Filename)
					return
				}
			} else {
				_certs, key, err = parsePemBlocks([]byte(filenameOrPem), ctx.Warn)
				if err != nil {
					err = errors.Wrapf(err, "%s: failed to parse certificates or private keys", ctx.Filename)
					return
				}
			}
			if len(_certs) != 0 {
				err = errors.Errorf("%s: no certificates are allowed in %s/key", ctx.Filename, path)
				return
			}
		} else {
			var _certs [][]byte
			_certs, key, err = parsePemBlocks([]byte(filenameOrPem), ctx.Warn)
			if err != nil {
				err = errors.Wrapf(err, "%s: failed to parse certificates or private keys", ctx.Filename)
				return
			}
			if len(_certs) != 0 {
				err = errors.Errorf("%s: no certificates are allowed in %s/key", ctx.Filename, path)
				return
			}
		}
	}
	if key == nil {
		err = errors.Errorf("%s: no key found in %s/cert and %s/key", ctx.Filename, path, path)
		return
	}

	x509Cert, err = x509.ParseCertificate(certs[0])
	if err != nil {
		err = errors.Wrapf(err, "%s: failed to parse certificate", ctx.Filename)
	}
	if !checkIfKeysArePaired(x509Cert.PublicKey, key) {
		err = errors.Errorf("%s: certificate does not correspond to private key", ctx.Filename)
	}

	tlsCert.Certificate = certs
	tlsCert.PrivateKey = key
	return
}

func (ctx *ConfigReaderContext) extractTLSConfig(tlsConfigMap map[interface{}]interface{}, path string, client bool) (retval *tls.Config, err error) {
	retval = new(tls.Config)
	_cipherSuites, ok := tlsConfigMap["ciphers"]
	if ok {
		cipherSuites, ok := _cipherSuites.([]interface{})
		if !ok {
			err = errors.Errorf("%s: invalid value for %s/ciphers", ctx.Filename, path)
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
				err = errors.Errorf("%s: invalid value for %s/ciphers", ctx.Filename, path)
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
			err = errors.Errorf("%s: invalid value for %s/min_version", ctx.Filename, path)
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
			err = errors.Errorf("%s: invalid value for %s/max_version", ctx.Filename, path)
			return
		}
		retval.MaxVersion = maxVersion
	}

	__certs, ok := tlsConfigMap["certs"]
	if ok {
		_certs, ok := __certs.([]interface{})
		if !ok {
			err = errors.Errorf("%s: invalid value for %s/certs", ctx.Filename, path)
			return
		}
		certs := make([]tls.Certificate, 0)
		for i, __cert := range _certs {
			_cert, ok := __cert.(map[interface{}]interface{})
			if !ok {
				err = errors.Errorf("%s: invalid structure under %s/certs/@%d", ctx.Filename, path, i)
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
				err = errors.Errorf("%s: invalid value for %s/client_auth", ctx.Filename, path)
				return
			}
			_type, ok := _clientAuth["type"]
			if !ok {
				err = errors.Errorf("%s: missing setting \"type\" under %s/client_auth", ctx.Filename, path)
				return
			}
			type_, ok := (_type).(string)
			if !ok {
				err = errors.Errorf("%s: invalid value for %s/client_auth/type", ctx.Filename, path)
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
				err = errors.Errorf("%s: invalid value for %s/verify", ctx.Filename, path)
				return
			}
			retval.InsecureSkipVerify = verify
		}
		_preferServerCiphers, ok := tlsConfigMap["prefer_server_ciphers"]
		if ok {
			preferServerCiphers, ok := _preferServerCiphers.(bool)
			if !ok {
				err = errors.Errorf("%s: invalid value for %s/preferServerCiphers", ctx.Filename, path)
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
			err = errors.Errorf("%s: invalid structure under tls", ctx.Filename)
			return
		}
		__client, ok := _tls["client"]
		if ok {
			_client, ok := __client.(map[interface{}]interface{})
			if !ok {
				err = errors.Errorf("%s: invalid structure under tls/client", ctx.Filename)
				return
			}
			retval.ClientTLSConfigTemplate, err = ctx.extractTLSConfig(_client, "tls/client", true)
			if err != nil {
				return
			}
		} else {
			retval.ClientTLSConfigTemplate = new(tls.Config)
		}
		__server, ok := _tls["server"]
		if ok {
			_server, ok := __server.(map[interface{}]interface{})
			if !ok {
				err = errors.Errorf("%s: invalid structure under tls/server", ctx.Filename)
				return
			}
			retval.ServerTLSConfigTemplate, err = ctx.extractTLSConfig(_server, "tls/server", false)
			if err != nil {
				return
			}
		} else {
			retval.ServerTLSConfigTemplate = new(tls.Config)
		}
		__ca, ok := _tls["ca"]
		if !ok {
			err = errors.Errorf("%s: item \"ca\" must exist under tls", ctx.Filename)
			return
		}
		_ca, ok := __ca.(map[interface{}]interface{})
		if !ok {
			err = errors.Errorf("%s: invalid structure under tls/ca", ctx.Filename)
			return
		}
		var tlsCert tls.Certificate
		tlsCert, retval.SigningCertificateKeyPair.Certificate, err = ctx.extractCertPrivateKeyPairs(_ca, "tls/ca")
		if err != nil {
			return
		}
		retval.SigningCertificateKeyPair.PrivateKey = tlsCert.PrivateKey
		__cache_directory, ok := _tls["cache_directory"]
		if ok {
			_cache_directory, ok := __cache_directory.(string)
			if !ok {
				err = errors.Errorf("%s: invalid structure under tls; cache_directory must be a string", ctx.Filename)
				return
			}
			retval.CacheDirectory = _cache_directory
		}
		__disable_cache, ok := _tls["disable_cache"]
		if ok {
			_disable_cache, ok := __disable_cache.(bool)
			if !ok {
				err = errors.Errorf("%s: invalid structure under tls; disable_cache must be a boolean", ctx.Filename)
				return
			}
			retval.DisableCache = _disable_cache
		}
	}
	return
}

func (ctx *ConfigReaderContext) extractResponseFilters(configMap map[string]interface{}) (retval []ResponseFilter, err error) {
	retval = make([]ResponseFilter, 0, 16)

	__responseFilterConfigs, ok := configMap["response_filters"]
	if !ok {
		return
	}
	_responseFilterConfigs, ok := __responseFilterConfigs.([]interface{})
	if !ok {
		err = errors.Errorf("%s: invalid structure under response_filters", ctx.Filename)
		return
	}

	for i, _responseFilterConfig := range _responseFilterConfigs {
		responseFilterConfig, ok := _responseFilterConfig.(map[interface{}]interface{})
		if !ok {
			err = errors.Errorf("%s: invalid structure under response_filters/@%d", ctx.Filename, i)
			return
		}
		_type, ok := responseFilterConfig["type"]
		if !ok {
			err = errors.Errorf("%s: missing response_filters/@%d/type", ctx.Filename, i)
			return
		}

		type_, ok := _type.(string)
		if !ok {
			err = errors.Errorf("%s: invalid value for response_filters/@%d/type", ctx.Filename, i)
			return
		}

		f, ok := FilterRepository.ResponseFilters[type_]
		if !ok {
			err = errors.Errorf("%s: unknown filter \"%s\"", ctx.Filename, type_)
			return
		}

		var responseFilter ResponseFilter
		responseFilter, err = f(ctx, responseFilterConfig)
		if err != nil {
			err = errors.Wrapf(err, "%s: failed to instantiate response filter \"%s\"", ctx.Filename, type_)
			return
		}

		retval = append(retval, responseFilter)
	}
	return
}

func defaultNow() (time.Time, error) {
	return time.Now(), nil
}

func loadConfig(yamlFile string, progname string) (*Config, error) {
	f, err := os.Open(yamlFile)
	if err != nil {
		return nil, errors.Wrapf(err, "failed to load %s", yamlFile)
	}
	configMap := make(map[string]interface{})
	err = candiedyaml.NewDecoder(f).Decode(&configMap)
	if err != nil {
		return nil, errors.Wrapf(err, "failed to load %s", yamlFile)
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
	responseFilters, err := ctx.extractResponseFilters(configMap)
	if err != nil {
		return nil, err
	}
	return &Config{
		Hosts:           perHostConfigs,
		Proxy:           proxy,
		MITM:            mitm,
		ResponseFilters: responseFilters,
		NowGetter:       defaultNow,
	}, nil
}
