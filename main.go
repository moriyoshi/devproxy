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
	"github.com/elazarl/goproxy"
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
)

type Pattern struct {
	Pattern      *regexp.Regexp
	Substitution string
}

type PerHostConfig struct {
	Name     string
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

var contentTypeKey = http.CanonicalHeaderKey("Content-Type")

var unixTimeEpoch = time.Unix(0, 0)

func defaultPortForScheme(scheme string) string {
	if scheme == "https" {
		return "443"
	} else if scheme == "http" {
		return "80"
	} else {
		return ""
	}
}

func toHostPortPairs(req *http.Request) []HostPortPair {
	retval := make([]HostPortPair, 0)
	host, port, err := net.SplitHostPort(req.URL.Host)
	if err != nil {
		host = req.URL.Host
		port = ""
	}
	if port == "" {
		defaultPort := defaultPortForScheme(req.URL.Scheme)
		if defaultPort != "" {
			retval = append(retval, HostPortPair{
				Host: host,
				Port: defaultPort,
			})
		}
	}
	retval = append(retval, HostPortPair{
		Host: host,
		Port: port,
	})
	return retval
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
	for _name, __patterns := range _hosts {
		name, ok := _name.(string)
		if !ok {
			return nil, fmt.Errorf("%s: invalid structure under hosts", ctx.Filename)
		}
		_patterns, ok := __patterns.(map[interface{}]interface{})
		if !ok {
			return nil, fmt.Errorf("%s: invalid structure under hosts/%s", name, ctx.Filename)
		}
		patterns := make([]Pattern, 0)
		for _pattern, _substitution := range _patterns {
			pattern, ok := _pattern.(string)
			if !ok {
				return nil, fmt.Errorf("%s: invalid structure under hosts/%s", name, ctx.Filename)
			}
			substitution, ok := _substitution.(string)
			if !ok {
				return nil, fmt.Errorf("%s: invalid structure under hosts/%s", name, ctx.Filename)
			}
			patternRegexp, err := regexp.Compile(pattern)
			if err != nil {
				return nil, fmt.Errorf("invalid regexp %s for %s configuration in %s", _pattern, name, ctx.Filename)
			}
			patterns = append(patterns, Pattern{Pattern: patternRegexp, Substitution: substitution})
		}
		perHostConfigs[name] = &PerHostConfig{Name: name, Patterns: patterns}
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
		pairs := toHostPortPairs(req)
		for _, a := range pcfg.IncludedHosts {
			for _, b := range pairs {
				if a == b {
					return true
				}
			}
		}
		return false
	} else if len(pcfg.ExcludedHosts) > 0 {
		pairs := toHostPortPairs(req)
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

func (ctx *OurContext) newTLSConfigFactory() func(host string, ctx *goproxy.ProxyCtx) (*tls.Config, error) {
	return func(host string, proxyCtx *goproxy.ProxyCtx) (*tls.Config, error) {
		config := ctx.Config.MITM.ServerTLSConfigTemplate
		hostname, _, err := net.SplitHostPort(host)
		if err != nil {
			hostname = host
		}
		ctx.Logger.Infof("Generate temporary certificate for %s", hostname)
		cert, err := ctx.generateCertificate([]string{hostname})
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
	start := unixTimeEpoch
	end := start.Add(time.Duration(time.Hour * 24 * 90))

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

func (ctx *OurContext) reqHostIs(host HostPortPair) goproxy.ReqConditionFunc {
	return func(req *http.Request, _ *goproxy.ProxyCtx) bool {
		pairs := toHostPortPairs(req)
		for _, a := range pairs {
			if a == host {
				return true
			}
			if host.Port == "" && a.Host == host.Host {
				return true
			}
		}
		return false
	}
}

func buildHostPortPairFromHostName(name string) HostPortPair {
	host, port, err := net.SplitHostPort(name)
	if err == nil {
		return HostPortPair{host, port}
	} else {
		return HostPortPair{name, ""}
	}
}

func (ctx *OurContext) newProxyHttpServer() *goproxy.ProxyHttpServer {
	proxy := goproxy.NewProxyHttpServer()
	proxy.Tr = ctx.newHttpTransport()
	proxy.Verbose = ctx.Verbose
	proxy.NonproxyHandler = http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		http.Error(w, "This is a proxy server. Does not respond to non-proxy requests.", 400)
	})
	for _, perHostConfig := range ctx.Config.Hosts {
		func(perHostConfig *PerHostConfig) {
			predicate := ctx.reqHostIs(buildHostPortPairFromHostName(perHostConfig.Name))
			proxy.OnRequest(predicate).DoFunc(
				func(r *http.Request, proxyCtx *goproxy.ProxyCtx) (*http.Request, *http.Response) {
					newUrlString := ""
					for _, pattern := range perHostConfig.Patterns {
						submatchIndexes := pattern.Pattern.FindStringSubmatchIndex(r.URL.Path)
						if submatchIndexes != nil {
							ctx.Logger.Debugf("%s matched to pattern %s", r.URL.Path, pattern.Pattern.String())
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
							ctx.Logger.Error(err)
						}
						newUrl.User = r.URL.User
						newRequest := new(http.Request)
						*newRequest = *r
						newRequest.URL = newUrl
						newRequest.RequestURI = newUrl.RequestURI()
						ctx.Logger.Infof("%s %s => %s", r.Method, r.RequestURI, newRequest.URL.String())
						r = newRequest
					} else {
						ctx.Logger.Infof("%s %s", r.Method, r.RequestURI)
					}
					return r, nil
				})
			if ctx.Config.MITM.SigningCertificateKeyPair.Certificate != nil {
				proxy.OnRequest(predicate).HandleConnectFunc(
					func(host string, proxyCtx *goproxy.ProxyCtx) (*goproxy.ConnectAction, string) {
						return &goproxy.ConnectAction{
							Action:    goproxy.ConnectMitm,
							TLSConfig: ctx.newTLSConfigFactory(),
						}, host
					})
			}
		}(perHostConfig)
	}
	proxy.OnResponse().DoFunc(func(resp *http.Response, proxyCtx *goproxy.ProxyCtx) *http.Response {
		if proxyCtx.Req.Method == "GET" || proxyCtx.Req.Method == "POST" {
			if resp == nil {
				return resp
			}
			contentType, ok := resp.Header[contentTypeKey]
			if !ok || len(contentType) == 0 {
				return resp
			}
			mimeType, params, err := mime.ParseMediaType(contentType[0])
			if err != nil {
				ctx.Logger.Warnf("invalid Content-Type header: %s", contentType[0])
				return resp
			}
			applicable := false
			for _, v := range ctx.HTMLMediaTypes {
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
					ctx.Logger.Errorf("failed to read response body (%d expected)", resp.ContentLength)
				}
			}
			contentLength := int(resp.ContentLength)
			body := []byte{}
			defer resp.Body.Close()
			if contentLength >= 0 {
				body = make([]byte, contentLength)
				n, err := io.ReadFull(resp.Body, body)
				if err != nil || (err == io.EOF && n < contentLength) {
					ctx.Logger.Errorf("failed to read response body (%d bytes read, %d bytes expected): %s", n, contentLength, err.Error())
				}
			} else {
				err := error(nil)
				body, err = ioutil.ReadAll(resp.Body)
				if err != nil {
					ctx.Logger.Errorf("failed to read response body: %s", err.Error())
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
			return newResp
		} else {
			return resp
		}
	})
	return proxy
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
