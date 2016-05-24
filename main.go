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
	crand "crypto/rand"
	"crypto/sha1"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/binary"
	"flag"
	"fmt"
	"github.com/Sirupsen/logrus"
	"io"
	"log"
	"math/big"
	"net"
	"net/http"
	"net/url"
	"os"
	"sort"
	"strings"
	"sync"
	"time"
)

type TLSConfigFactory func(hostPortPairStr string, proxyCtx *OurProxyCtx) (*tls.Config, error)

type DevProxy struct {
	Logger           *logrus.Logger
	LogWriter        io.WriteCloser
	StdLogger        *log.Logger
	Config           *Config
	DefaultCharset   string
	CryptoRandReader io.Reader
	Now              func() time.Time
	certCache        map[string]*tls.Certificate
}

func (ctx *DevProxy) unidiTunnel(wg *sync.WaitGroup, connA net.Conn, connB net.Conn) {
	defer wg.Done()
	n, err := io.Copy(connA, connB)
	msg := fmt.Sprintf("%d bytes transferred from %s to %s", n, connA, connB)
	if err != nil && err != io.EOF {
		ctx.Logger.Errorf("%s; %s", err.Error(), msg)
	} else {
		ctx.Logger.Debug(msg)
	}
}

func (ctx *DevProxy) bidiTunnel(connA net.Conn, connB net.Conn) {
	wg := &sync.WaitGroup{}
	wg.Add(1)
	go ctx.unidiTunnel(wg, connA, connB)
	wg.Add(1)
	go ctx.unidiTunnel(wg, connB, connA)
	wg.Wait()
}

func (ctx *DevProxy) proxyIsApplicable(req *http.Request) bool {
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

func (ctx *DevProxy) getProxyUrlForRequest(req *http.Request) (*url.URL, error) {
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

func (ctx *DevProxy) newTLSConfigFactory() TLSConfigFactory {
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

func (ctx *DevProxy) newProxyURLBuilder() func(*http.Request) (*url.URL, error) {
	return func(req *http.Request) (*url.URL, error) {
		return ctx.getProxyUrlForRequest(req)
	}
}

func (ctx *DevProxy) newHttpTransport() *http.Transport {
	return &http.Transport{
		TLSClientConfig: &ctx.Config.MITM.ClientTLSConfigTemplate,
		Proxy:           ctx.newProxyURLBuilder(),
	}
}

func (ctx *DevProxy) generateCertificate(hosts []string) (*tls.Certificate, error) {
	sortedHosts := make([]string, len(hosts))
	copy(sortedHosts, hosts)
	sort.Strings(sortedHosts)
	key := strings.Join(sortedHosts, ";")
	if cert, ok := ctx.certCache[key]; ok {
		return cert, nil
	}
	ca := ctx.Config.MITM.SigningCertificateKeyPair
	ctx.Logger.Debugf("CA: CN=%s", ca.Certificate.Subject.CommonName)
	year := ctx.Now().Year()
	start := time.Date(year, 1, 1, 0, 0, 0, 0, time.UTC)
	end := time.Date(year+1, 1, 1, 0, 0, 0, 0, time.UTC)

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

func (ctx *DevProxy) checkIfRequestMatchesToUrl(url_ *url.URL, secureOnly bool, req *http.Request, _ *OurProxyCtx) bool {
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

func (ctx *DevProxy) checkIfTunnelRequestMatchesToUrl(url_ *url.URL, req *http.Request, _ *OurProxyCtx) bool {
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

func (ctx *DevProxy) newProxyHttpServer() *OurProxyHttpServer {
	return &OurProxyHttpServer{
		Ctx:              ctx,
		Logger:           ctx.Logger,
		Tr:               ctx.newHttpTransport(),
		TLSConfigFactory: ctx.newTLSConfigFactory(),
		ResponseFilters:  ctx.Config.ResponseFilters,
		SessionSerial:    0,
	}
}

func (ctx *DevProxy) Dispose() {
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
	ctx := DevProxy{
		Logger:           logger,
		LogWriter:        logWriter,
		StdLogger:        log.New(logWriter, "", 0),
		Config:           config,
		DefaultCharset:   "UTF-8",
		CryptoRandReader: crand.Reader,
		Now:              time.Now,
		certCache:        make(map[string]*tls.Certificate, 0),
	}
	defer ctx.Dispose()
	proxy := ctx.newProxyHttpServer()
	logger.Infof("Listening on %s...", listenOn)
	logger.Fatal(http.ListenAndServe(listenOn, proxy))
}
