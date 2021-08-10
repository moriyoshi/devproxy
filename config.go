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

	"github.com/moriyoshi/mimetypes"
	"github.com/pkg/errors"
	"gopkg.in/yaml.v2"
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

type PreparedCertificate struct {
	Pattern        *regexp.Regexp
	TLSCertificate *tls.Certificate
	Certificate    *x509.Certificate
}

type MITMConfig struct {
	ServerTLSConfigTemplate   *tls.Config
	ClientTLSConfigTemplate   *tls.Config
	SigningCertificateKeyPair struct {
		Certificate *x509.Certificate
		PrivateKey  crypto.PrivateKey
	}
	Prepared       []PreparedCertificate
	CacheDirectory string
	DisableCache   bool
	ValidityPeriod int
}

type ProxyConfig struct {
	HTTPProxy     *url.URL
	HTTPSProxy    *url.URL
	IncludedHosts []HostPortPair
	ExcludedHosts []HostPortPair
	TLSConfig     *tls.Config
}

type FileTransportConfig struct {
	RootDirectory string
	MimeTypes     mimetypes.MediaTypeRegistry
}

type Config struct {
	Hosts           map[string]*PerHostConfig
	Proxy           ProxyConfig
	MITM            MITMConfig
	ResponseFilters []ResponseFilter
	FileTransport   FileTransportConfig
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
	"TLS13":  tls.VersionTLS13,
	"TLS1.3": tls.VersionTLS13,
}

type ConfigReaderContext struct {
	filename string
	warn     func(string)
}

func (ctx *ConfigReaderContext) extractPerHostConfigs(deref dereference) (perHostConfigs map[string]*PerHostConfig, err error) {
	perHostConfigs = make(map[string]*PerHostConfig)
	err = deref.multi(
		"hosts", func(urlStr string, hostMap dereference) error {
			url, err := url.Parse(urlStr)
			if err != nil {
				return errors.Wrapf(err, "invalid value for URL (%s)", urlStr)
			}
			if url.Path != "" {
				return errors.Errorf("path may not be present: %s", urlStr)
			}
			patterns := make([]Pattern, 0)
			err = hostMap.iterateHomogeneousValuedSlice(yamlMapType, func(_ int, kv dereference) error {
				headers := make(http.Header)
				patternOccurred := false
				return kv.iterateHomogeneousValuedMap(emptyInterfaceType, func(pattern string, substitutionOrAuxAttrs dereference) error {
					if pattern == "headers" {
						err := substitutionOrAuxAttrs.iterateHomogeneousValuedMap(emptyInterfaceType, func(headerName string, values dereference) error {
							if values.value == nil {
								return errors.Errorf("element must be non-null")
							}
							var resultingValues []string
							switch values := values.value.(type) {
							case []interface{}:
								resultingValues = make([]string, len(values))
								for i, _header := range values {
									header, ok := _header.(string)
									if !ok {
										return errors.Errorf("unexpected element; expecting a string, got %T", _header)
									}
									values[i] = header
								}
							case string:
								resultingValues = []string{values}
							default:
								return errors.Errorf("expecting string or array of string, got %T", values)
							}
							headers[headerName] = resultingValues
							return nil
						})
						if err != nil {
							return err
						}
					} else {
						if patternOccurred {
							return errors.Errorf("Pattern already specfieid")
						}
						substitution, err := substitutionOrAuxAttrs.stringValue()
						if err != nil {
							return err
						}
						patternRegexp, err := regexp.Compile(pattern)
						if err != nil {
							return errors.Errorf("invalid regexp %s for %s configuration", pattern, urlStr)
						}
						patterns = append(patterns, Pattern{Pattern: patternRegexp, Substitution: substitution, Headers: headers})
						patternOccurred = true
					}
					return nil
				})
			})
			if err != nil {
				return err
			}
			perHostConfigs[urlStr] = &PerHostConfig{Host: url, Patterns: patterns}
			return nil
		},
	)
	return
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

func (ctx *ConfigReaderContext) extractProxyConfig(deref dereference) (retval ProxyConfig, err error) {
	err = deref.multi(
		"proxy", func(deref dereference) error {
			return deref.multi(
				"http", func(httpProxy string) error {
					var httpProxyUrl *url.URL
					httpProxyUrl, err = parseUrlOrHostPortPair(httpProxy)
					if err != nil {
						return errors.Wrapf(err, "invalid value for proxy/http_proxy")
					}
					retval.HTTPProxy = httpProxyUrl
					return nil
				},
				"https", func(httpsProxy string) error {
					var httpsProxyUrl *url.URL
					httpsProxyUrl, err = parseUrlOrHostPortPair(httpsProxy)
					if err != nil {
						return errors.Wrapf(err, "invalid value for proxy/http_proxy")
					}
					retval.HTTPSProxy = httpsProxyUrl
					return nil
				},
				"included", func(includedHosts []string) error {
					retval.IncludedHosts, err = convertUnparsedHostsIntoPairs(includedHosts)
					if err != nil {
						return errors.Wrapf(err, "invalid host-port pair contained in NO_PROXY")
					}
					return nil
				},
				"excluded", func(excludedHosts []string) error {
					retval.ExcludedHosts, err = convertUnparsedHostsIntoPairs(excludedHosts)
					if err != nil {
						return errors.Wrapf(err, "invalid host-port pair contained in NO_PROXY")
					}
					return nil
				},
				"tls", func(deref dereference) error {
					var err error
					retval.TLSConfig, err = ctx.extractTLSConfig(deref, true)
					return err
				},
			)
		},
	)

	if err != nil {
		return
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

func (ctx *ConfigReaderContext) extractCertPool(deref dereference) (*x509.CertPool, error) {
	pool := x509.NewCertPool()
	switch fileDirectoryOrPemBundle := deref.value.(type) {
	case string:
		var f *os.File
		f, err := os.Open(fileDirectoryOrPemBundle)
		if err != nil && !os.IsNotExist(err) {
			return nil, errors.Errorf("failed to open %s", fileDirectoryOrPemBundle)
		}
		if err == nil {
			defer f.Close()

			var traverse func(f *os.File) error
			traverse = func(f *os.File) error {
				st, err := f.Stat()
				if err != nil {
					return errors.Wrapf(err, "failed to open %s", f.Name())
				}
				if st.IsDir() {
					children, err := f.Readdir(-1)
					if err != nil {
						return errors.Wrapf(err, "failed to read directory entry under %s", f.Name())
					}
					for _, child := range children {
						cp := filepath.Join(f.Name(), child.Name())
						cf, err := os.Open(cp)
						if err != nil {
							return errors.Wrapf(err, "failed to open %s", cp)
						}
						defer cf.Close()
						err = traverse(cf)
						if err != nil {
							return err
						}
					}
				} else {
					pems, err := ioutil.ReadAll(f)
					if err != nil {
						return errors.Wrapf(err, "failed to read certificates from %s", f.Name())
					}
					if !pool.AppendCertsFromPEM(pems) {
						ctx.warn(fmt.Sprintf("failed to parse some certificates in %s", f.Name()))
					}
				}
				return nil
			}
			err = traverse(f)
			if err != nil {
				return nil, err
			}
		} else {
			if strings.HasPrefix(fileDirectoryOrPemBundle, "----- BEGIN") {
				if !pool.AppendCertsFromPEM([]byte(fileDirectoryOrPemBundle)) {
					ctx.warn("failed to parse some certificates")
				}
			} else {
				return nil, errors.Errorf("%s does not exist", fileDirectoryOrPemBundle)
			}
		}
		return pool, nil
	case []interface{}:
		for _, _certs := range fileDirectoryOrPemBundle {
			certs, ok := _certs.(string)
			if !ok {
				return nil, errors.Errorf("every item must be a string")
			}
			if !pool.AppendCertsFromPEM([]byte(certs)) {
				ctx.warn("failed to parse some certificates")
			}
		}
		return pool, nil
	case map[interface{}]interface{}:
		for _name, _certs := range fileDirectoryOrPemBundle {
			name, ok := _name.(string)
			if !ok {
				return nil, errors.Errorf("every key must be a string")
			}
			certs, ok := _certs.(string)
			if !ok {
				return nil, errors.Errorf("value for item %s must be a string", name)
			}
			if !pool.AppendCertsFromPEM([]byte(certs)) {
				ctx.warn("failed to parse some certificates")
			}
		}
		return pool, nil
	default:
		return nil, errors.Errorf("expecting a string, mapping or array, got %T", fileDirectoryOrPemBundle)
	}
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

func (ctx *ConfigReaderContext) extractCertPrivateKeyPairs(deref dereference) (tlsCert tls.Certificate, x509Cert *x509.Certificate, err error) {
	var certs [][]byte
	var key crypto.PrivateKey

	err = deref.multi(
		required{"cert"}, func(filenamePemOrListDeref dereference) error {
			switch filenamePemOrList := filenamePemOrListDeref.value.(type) {
			case string:
				f, fErr := os.Open(filenamePemOrList)
				if fErr != nil {
					if !os.IsNotExist(fErr) {
						return errors.Wrapf(fErr, "could not open %s", filenamePemOrList)
					}
				}
				if fErr == nil {
					// file
					defer f.Close()
					pemBytes, err := ioutil.ReadAll(f)
					if err != nil {
						return errors.Wrapf(err, "could not read data from %s", filenamePemOrList)
					}
					certs, key, err = parsePemBlocks(pemBytes, ctx.warn)
					if err != nil {
						return errors.Wrapf(err, "failed to parse certificates or private keys")
					}
				} else {
					// PEM
					var err error
					certs, key, err = parsePemBlocks([]byte(filenamePemOrList), ctx.warn)
					if err != nil {
						return errors.Wrapf(err, "failed to parse certificates or private keys")
					}
				}
				if len(certs) == 0 {
					if fErr != nil {
						return fErr
					} else {
						return errors.Errorf("no certificates exist in the cert file: %s", filenamePemOrList)
					}
				}
			case []interface{}:
				for _, _pem := range filenamePemOrList {
					pem, ok := _pem.(string)
					if !ok {
						return errors.Errorf("every item must be a PEM-formatted certificates / private key")
					}
					_certs, _key, err := parsePemBlocks([]byte(pem), ctx.warn)
					if err != nil {
						return errors.Wrapf(err, "failed to parse certificates or private keys")
					}
					if _key != nil {
						if key != nil {
							return errors.Errorf("duplicate private keys exist")
						}
					}
					certs = append(certs, _certs...)
					key = _key
				}
				if len(certs) == 0 {
					return errors.Errorf("no certificates exist in cert")
				}
			default:
				return errors.Errorf("expecting a string or a list of PEM-formatted certificates / private key")
			}
			return nil
		},
		"key", func(filenameOrPemDeref dereference) error {
			if key != nil {
				return errors.Errorf("private keys exist both in cert/ and key/")
			}
			switch filenameOrPem := filenameOrPemDeref.value.(type) {
			case string:
				f, err := os.Open(filenameOrPem)
				if err != nil && !os.IsNotExist(err) {
					return errors.Wrapf(err, "could not open %s", filenameOrPem)
				}
				var _certs [][]byte
				if err == nil {
					defer f.Close()
					pemBytes, err := ioutil.ReadAll(f)
					if err != nil {
						return errors.Wrapf(err, "could not read data from %s", filenameOrPem)
					}
					_certs, key, err = parsePemBlocks(pemBytes, ctx.warn)
					if err != nil {
						return errors.Wrapf(err, "failed to parse certificates or private keys")
					}
				} else {
					_certs, key, err = parsePemBlocks([]byte(filenameOrPem), ctx.warn)
					if err != nil {
						return errors.Wrapf(err, "failed to parse certificates or private keys")
					}
				}
				if len(_certs) != 0 {
					return errors.Errorf("no certificates are allowed in key")
				}
			default:
				return errors.Errorf("key must be a string")
			}
			return nil
		},
	)
	if err != nil {
		return
	}

	if key == nil {
		err = errors.Errorf("no key found in cert and key")
		return
	}

	x509Cert, err = x509.ParseCertificate(certs[0])
	if err != nil {
		err = errors.Wrapf(err, "failed to parse certificate")
	}
	if !checkIfKeysArePaired(x509Cert.PublicKey, key) {
		err = errors.Errorf("certificate does not correspond to private key")
	}

	tlsCert.Certificate = certs
	tlsCert.PrivateKey = key
	return
}

func (ctx *ConfigReaderContext) extractTLSConfig(deref dereference, client bool) (retval *tls.Config, err error) {
	retval = new(tls.Config)
	err = deref.multi(
		"ciphers", func(cipherSuiteStrValues []string) error {
			cipherSuites := make([]uint16, 0, 5)
			for _, cipherSuiteStrValue := range cipherSuiteStrValues {
				cipherSuiteStrValue = strings.ToUpper(cipherSuiteStrValue)
				cipherSuite, ok := cipherSuiteValues[cipherSuiteStrValue]
				if !ok {
					return errors.Errorf("invalid cipher name: %s", cipherSuiteStrValue)
				}
				cipherSuites = append(cipherSuites, cipherSuite)
				return nil
			}
			if err != nil {
				return err
			}
			retval.CipherSuites = cipherSuites
			return nil
		},
		"min_version", func(minVersionStr string) error {
			var minVersion uint16
			minVersionStr = strings.ToUpper(minVersionStr)
			minVersion, ok := tlsVersionValues[minVersionStr]
			if !ok {
				return errors.Errorf("invalid version value: %s", minVersionStr)
			}
			retval.MinVersion = minVersion
			return nil
		},
		"max_version", func(maxVersionStr string) error {
			var maxVersion uint16
			maxVersionStr = strings.ToUpper(maxVersionStr)
			maxVersion, ok := tlsVersionValues[maxVersionStr]
			if !ok {
				return errors.Errorf("invalid version value: %s", maxVersionStr)
			}
			retval.MinVersion = maxVersion
			return nil
		},
		"certs", func(deref dereference) error {
			certs := make([]tls.Certificate, 0)
			err := deref.iterateHomogeneousValuedSlice(yamlMapType, func(_ int, deref dereference) error {
				var cert tls.Certificate
				cert, _, err = ctx.extractCertPrivateKeyPairs(deref)
				if err != nil {
					return err
				}
				certs = append(certs, cert)
				return nil
			})
			if err != nil {
				return err
			}
			retval.Certificates = certs
			return nil
		},
	)
	if err != nil {
		return
	}

	// fixup
	retval.BuildNameToCertificate()

	if !client {
		retval.ClientAuth = tls.NoClientCert
		err = deref.multi(
			"client_auth", func(typ string) error {
				clientAuth, ok := clientAuthTypeValues[typ]
				if !ok {
					return errors.Errorf("invalid auth type: %s", typ)
				}
				if clientAuth != tls.NoClientCert {
					err := deref.multi(
						"ca_certs", func(deref dereference) error {
							var err error
							retval.ClientCAs, err = ctx.extractCertPool(deref)
							return err
						},
					)
					if err != nil {
						return err
					}
				}
				retval.ClientAuth = clientAuth
				return nil
			},
		)
	} else {
		err = deref.multi(
			"verify", func(v bool) error {
				retval.InsecureSkipVerify = !v
				return nil
			},
			"prefer_server_ciphers", func(v bool) error {
				retval.PreferServerCipherSuites = v
				return nil
			},
			"ca_certs", func(deref dereference) error {
				var err error
				retval.RootCAs, err = ctx.extractCertPool(deref)
				return err
			},
		)
	}
	return
}

func (ctx *ConfigReaderContext) extractMITMConfig(deref dereference) (retval MITMConfig, err error) {
	retval.ServerTLSConfigTemplate = new(tls.Config)
	retval.ClientTLSConfigTemplate = new(tls.Config)
	retval.ValidityPeriod = 4500
	err = deref.multi(
		"tls", func(deref dereference) error {
			return deref.multi(
				"client", func(deref dereference) error {
					var err error
					retval.ClientTLSConfigTemplate, err = ctx.extractTLSConfig(deref, true)
					return err
				},
				"server", func(deref dereference) error {
					var err error
					retval.ServerTLSConfigTemplate, err = ctx.extractTLSConfig(deref, false)
					return err
				},
				"ca", func(deref dereference) error {
					var tlsCert tls.Certificate
					tlsCert, retval.SigningCertificateKeyPair.Certificate, err = ctx.extractCertPrivateKeyPairs(deref)
					if err != nil {
						return err
					}
					retval.SigningCertificateKeyPair.PrivateKey = tlsCert.PrivateKey
					return nil
				},
				"validity", func(validity int) error {
					if validity <= 0 {
						return errors.Errorf("invalid validity %d days", validity)
					}
					retval.ValidityPeriod = validity
					return nil
				},
				"prepared", func(_ int, deref dereference) error {
					visited := false
					return deref.iterateHomogeneousValuedMap(yamlMapType, func(hostPattern string, deref dereference) error {
						if visited {
							return errors.Errorf("extra item exists")
						}
						visited = true
						hostPatternRegexp, err := regexp.Compile(hostPattern)
						if err != nil {
							return errors.Errorf("invalid regexp %s", hostPattern)
						}
						tlsCert, cert, err := ctx.extractCertPrivateKeyPairs(deref)
						if err != nil {
							return err
						}
						retval.Prepared = append(retval.Prepared, PreparedCertificate{
							Pattern:        hostPatternRegexp,
							TLSCertificate: &tlsCert,
							Certificate:    cert,
						})
						return nil
					})
				},
				"cache_directory", func(cacheDirectory string) error {
					retval.CacheDirectory = cacheDirectory
					return nil
				},
				"disable_cache", func(disableCache bool) error {
					retval.DisableCache = disableCache
					return nil
				},
			)
		},
	)
	return
}

func (ctx *ConfigReaderContext) extractResponseFilters(deref dereference) (retval []ResponseFilter, err error) {
	retval = make([]ResponseFilter, 0, 16)
	err = deref.multi(
		"response_filters", func(i int, deref dereference) error {
			typ, err := deref.derefOne("type").stringValue()
			if err != nil {
				return err
			}
			f, ok := FilterRepository.ResponseFilters[typ]
			if !ok {
				return errors.Errorf("unknown filter \"%s\"", typ)
			}
			responseFilterConfig, err := deref.mapValue()
			if err != nil {
				return err
			}
			responseFilter, err := f(ctx, responseFilterConfig)
			if err != nil {
				return errors.Wrapf(err, "failed to instantiate response filter \"%s\"", typ)
			}
			retval = append(retval, responseFilter)
			return nil
		},
	)
	return
}

func (ctx *ConfigReaderContext) extractFileTransportConfig(deref dereference) (retval FileTransportConfig, err error) {
	err = deref.multi(
		"file_tx", func(deref dereference) error {
			root := "."
			mimeTypeFile := ""
			mimeTypeFileFormat := "apache"
			err := deref.multi(
				"root", func(v string) error {
					root = v
					return nil
				},
				"mime_type_file", func(v string) error {
					mimeTypeFile = v
					return nil
				},
				"mime_type_file_format", func(v string) error {
					mimeTypeFileFormat = v
					return nil
				},
			)
			if err != nil {
				return err
			}

			if !filepath.IsAbs(root) {
				var wd string
				wd, err = os.Getwd()
				if err != nil {
					return err
				}
				root = filepath.Clean(filepath.Join(wd, root))
			}

			retval.RootDirectory = root

			if mimeTypeFile != "" {
				retval.MimeTypes, err = mimetypes.Load(mimeTypeFile, mimeTypeFileFormat)
				if err != nil {
					return errors.Wrapf(err, "failed to load %s", mimeTypeFile)
				}
			}
			return nil
		},
	)
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
	defer f.Close()
	configRoot := dereference{value: make(map[interface{}]interface{})}
	err = yaml.NewDecoder(f).Decode(&configRoot.value)
	if err != nil {
		return nil, errors.Wrapf(err, "failed to load %s", yamlFile)
	}
	ctx := &ConfigReaderContext{
		filename: yamlFile,
		warn: func(msg string) {
			fmt.Fprintf(os.Stderr, "%s: %s\n", progname, msg)
		},
	}
	perHostConfigs, err := ctx.extractPerHostConfigs(configRoot)
	if err != nil {
		return nil, err
	}
	proxy, err := ctx.extractProxyConfig(configRoot)
	if err != nil {
		return nil, err
	}
	mitm, err := ctx.extractMITMConfig(configRoot)
	if err != nil {
		return nil, err
	}
	responseFilters, err := ctx.extractResponseFilters(configRoot)
	if err != nil {
		return nil, err
	}

	fileTransport, err := ctx.extractFileTransportConfig(configRoot)
	if err != nil {
		return nil, err
	}

	return &Config{
		Hosts:           perHostConfigs,
		Proxy:           proxy,
		MITM:            mitm,
		ResponseFilters: responseFilters,
		FileTransport:   fileTransport,
		NowGetter:       defaultNow,
	}, nil
}
