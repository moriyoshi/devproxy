/*
 * Copyright (c) 2016 Moriyoshi Koizumi
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
	"crypto"
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"github.com/Sirupsen/logrus"
	"io/ioutil"
	"os"
	"path/filepath"
	"strings"
	"time"
)

type CertCache struct {
	CacheDir   string
	Logger     *logrus.Logger
	certs      map[string]*tls.Certificate
	issuerCert *x509.Certificate
	privateKey crypto.PrivateKey
}

const certificateFileName = "cert.pem"
const certificateBlockName = "CERTIFICATE"

func buildKeyString(hosts []string) string {
	key := strings.Join(hosts, ";")
	return key
}

func (c *CertCache) writeCertificate(key string, cert *tls.Certificate) (err error) {
	leadingDirs, ok := c.buildPathToCachedCert(key)
	if !ok {
		return
	}
	err = os.MkdirAll(leadingDirs, os.FileMode(0777))
	if err != nil {
		return
	}
	path := filepath.Join(leadingDirs, certificateFileName)
	w, err := os.OpenFile(path, os.O_CREATE|os.O_TRUNC|os.O_WRONLY, os.FileMode(0666))
	if err != nil {
		return
	}
	defer w.Close()
	err = pem.Encode(w, &pem.Block{Type: certificateBlockName, Bytes: cert.Certificate[0]})
	if err != nil {
		return
	}
	return nil
}

func (c *CertCache) buildPathToCachedCert(key string) (string, bool) {
	if c.CacheDir == "" {
		return "", false
	}
	return filepath.Join(c.CacheDir, key), true
}

func (c *CertCache) readAndValidateCertificate(key string, hosts []string, now time.Time) (*tls.Certificate, error) {
	leadingDirs, ok := c.buildPathToCachedCert(key)
	if !ok {
		return nil, nil
	}
	path := filepath.Join(leadingDirs, certificateFileName)
	pemBytes, err := ioutil.ReadFile(path)
	if err != nil {
		return nil, err
	}
	certDerBytes := []byte(nil)
	for {
		var pemBlock *pem.Block
		pemBlock, pemBytes = pem.Decode(pemBytes)
		if pemBlock == nil {
			break
		}
		if pemBlock.Type == certificateBlockName {
			certDerBytes = pemBlock.Bytes
			break
		}
	}
	if certDerBytes == nil {
		return nil, fmt.Errorf("No valid certificate contained in %s", path)
	}
	x509Cert, err := x509.ParseCertificate(certDerBytes)
	if err != nil {
		return nil, fmt.Errorf("Invalid certificate found in %s (%s)", path, err.Error())
	}
	x509Cert.RawIssuer = c.issuerCert.Raw
	err = x509Cert.CheckSignatureFrom(c.issuerCert)
	if err != nil {
		return nil, fmt.Errorf("Invalid certificate found in %s (%s)", path, err.Error())
	}
	if !now.Before(x509Cert.NotAfter) {
		return nil, fmt.Errorf("Ceritificate no longer valid (not after: %s, now: %s)", x509Cert.NotAfter.Format(time.RFC1123), now.Format(time.RFC1123))
	}

outer:
	for _, a := range hosts {
		for _, b := range x509Cert.DNSNames {
			if a == b {
				break outer
			}
		}
		return nil, fmt.Errorf("Certificate does not cover the host name %s", a)
	}

	return &tls.Certificate{
		Certificate: [][]byte{certDerBytes, c.issuerCert.Raw},
		PrivateKey:  c.privateKey,
	}, nil
}

func (c *CertCache) readCertificate(key string, hosts []string, now time.Time) (cert *tls.Certificate, err error) {
	cert, err = c.readAndValidateCertificate(
		key,
		hosts,
		now,
	)
	if err != nil {
		c.Logger.Warn(err.Error())
		err = nil
	}
	return
}

func (c *CertCache) Put(hosts []string, cert *tls.Certificate) error {
	key := buildKeyString(hosts)
	c.certs[key] = cert
	return c.writeCertificate(key, cert)
}

func (c *CertCache) Get(hosts []string, now time.Time) (cert *tls.Certificate, err error) {
	key := buildKeyString(hosts)
	cert, ok := c.certs[key]
	if !ok {
		c.Logger.Debug("Certificate not found in in-process cache")
		cert, err = c.readCertificate(key, hosts, now)
		if err != nil {
			return
		}
		if cert != nil {
			c.certs[key] = cert
		}
	}
	return
}

func NewCertCache(cacheDir string, logger *logrus.Logger, issuerCert *x509.Certificate, privateKey crypto.PrivateKey) *CertCache {
	return &CertCache{
		CacheDir:   cacheDir,
		Logger:     logger,
		certs:      make(map[string]*tls.Certificate),
		issuerCert: issuerCert,
		privateKey: privateKey,
	}
}
