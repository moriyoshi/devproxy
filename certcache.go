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
	"io/ioutil"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/pkg/errors"
	"github.com/sirupsen/logrus"
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
const privateKeyFileName = "key.pem"
const privateKeyBlockName = "PRIVATE KEY"

func buildKeyString(hosts []string) string {
	key := strings.Join(hosts, ";")
	return key
}

func (c *CertCache) writeCertificate(key string, cert *tls.Certificate) (err error) {
	leadingDir, ok := c.buildPathToCachedCert(key)
	if !ok {
		return
	}

	leadingDirTmp := leadingDir + "$tmp$"
	err = os.MkdirAll(leadingDirTmp, os.FileMode(0700))
	if err != nil {
		return
	}
	defer func() {
		if err != nil {
			os.RemoveAll(leadingDirTmp)
		}
	}()

	certFilePath := filepath.Join(leadingDirTmp, certificateFileName)
	privKeyFilePath := filepath.Join(leadingDirTmp, privateKeyFileName)

	err = func(certFilePath string) (err error) {
		w, err := os.OpenFile(certFilePath, os.O_CREATE|os.O_TRUNC|os.O_WRONLY, os.FileMode(0600))
		if err != nil {
			return
		}
		defer w.Close()

		for _, x509Cert := range cert.Certificate {
			err = pem.Encode(w, &pem.Block{Type: certificateBlockName, Bytes: x509Cert})
			if err != nil {
				return
			}
			_, err = w.Write([]byte{'\n'})
			if err != nil {
				return
			}
		}
		return
	}(certFilePath)
	if err != nil {
		return
	}

	err = func(privKeyFilePath string) (err error) {
		privKeyBytes, err := x509.MarshalPKCS8PrivateKey(cert.PrivateKey)
		if err != nil {
			return
		}

		w, err := os.OpenFile(privKeyFilePath, os.O_CREATE|os.O_TRUNC|os.O_WRONLY, os.FileMode(0666))
		if err != nil {
			return
		}
		defer w.Close()
		err = pem.Encode(w, &pem.Block{Type: privateKeyBlockName, Bytes: privKeyBytes})
		if err != nil {
			return
		}
		return
	}(privKeyFilePath)
	if err != nil {
		return
	}

	err = os.Rename(leadingDirTmp, leadingDir)
	return
}

func (c *CertCache) buildPathToCachedCert(key string) (string, bool) {
	if c.CacheDir == "" {
		return "", false
	}
	return filepath.Join(c.CacheDir, key), true
}

func (c *CertCache) readAndValidateCertificate(key string, hosts []string, now time.Time) (*tls.Certificate, error) {
	leadingDir, ok := c.buildPathToCachedCert(key)
	if !ok {
		return nil, nil
	}

	if _, err := os.Stat(leadingDir); os.IsNotExist(err) {
		return nil, nil
	}

	var x509Cert *x509.Certificate
	var certDerBytes [][]byte
	{
		certFilePath := filepath.Join(leadingDir, certificateFileName)
		pemBytes, err := ioutil.ReadFile(certFilePath)
		if err != nil {
			return nil, err
		}

		for {
			var pemBlock *pem.Block
			pemBlock, pemBytes = pem.Decode(pemBytes)
			if pemBlock == nil {
				break
			}
			if pemBlock.Type == certificateBlockName {
				certDerBytes = append(certDerBytes, pemBlock.Bytes)
			}
		}
		if len(certDerBytes) == 0 {
			return nil, errors.Errorf("no valid certificate contained in %s", certFilePath)
		}

		x509Cert, err = x509.ParseCertificate(certDerBytes[0])
		if err != nil {
			return nil, errors.Wrapf(err, "invalid certificate found in %s", certFilePath)
		}
		if len(certDerBytes) == 1 && c.issuerCert != nil {
			err = x509Cert.CheckSignatureFrom(c.issuerCert)
			if err != nil {
				return nil, errors.Wrapf(err, "invalid certificate found in %s", certFilePath)
			}
		}

		if !now.Before(x509Cert.NotAfter) {
			return nil, errors.Errorf("ceritificate no longer valid (not after: %s, now: %s)", x509Cert.NotAfter.Local().Format(time.RFC1123), now.Local().Format(time.RFC1123))
		}
	}

	var privKey crypto.PrivateKey
	{
		privKeyFilePath := filepath.Join(leadingDir, privateKeyFileName)
		pemBytes, err := ioutil.ReadFile(privKeyFilePath)
		if err != nil {
			if !os.IsNotExist(err) {
				return nil, err
			}
		}
		if err == nil {
			b, _ := pem.Decode(pemBytes)
			privKey, err = x509.ParsePKCS8PrivateKey(b.Bytes)
			if err != nil {
				return nil, errors.Wrapf(err, "failed to parse private key %s", privKeyFilePath)
			}
		} else {
			if c != nil {
				privKey = c.privateKey
			}
			err = nil
		}
	}

	if privKey == nil {
		return nil, errors.Errorf("no private key is available (cache is broken)")
	}

outer:
	for _, a := range hosts {
		dnsNameMatched := false
		for _, b := range x509Cert.DNSNames {
			if wildMatch(b, a) {
				dnsNameMatched = true
				break outer
			}
		}
		if !dnsNameMatched {
			dnsNameMatched = wildMatch(x509Cert.Subject.CommonName, a)
		}
		if !dnsNameMatched {
			return nil, errors.Errorf("certificate does not cover the host name %s", a)
		}
	}

	return &tls.Certificate{
		Certificate: certDerBytes,
		PrivateKey:  privKey,
	}, nil
}

func (c *CertCache) evict(key string) error {
	c.Logger.Debugf("evicting cache foe %s", key)
	leadingDir, ok := c.buildPathToCachedCert(key)
	if !ok {
		return nil
	}
	return os.RemoveAll(leadingDir)
}

func (c *CertCache) readCertificate(key string, hosts []string, now time.Time) (cert *tls.Certificate, err error) {
	cert, err = c.readAndValidateCertificate(
		key,
		hosts,
		now,
	)
	if err != nil {
		c.evict(key)
		c.Logger.Warn(err.Error())
		err = nil
	}
	return
}

func (c *CertCache) Put(hosts []string, cert *tls.Certificate) error {
	key := buildKeyString(hosts)
	c.certs[key] = cert
	err := c.writeCertificate(key, cert)
	if err != nil {
		c.Logger.Warn(err.Error())
		err = nil
	}
	return err
}

func (c *CertCache) Get(hosts []string, now time.Time) (cert *tls.Certificate, err error) {
	key := buildKeyString(hosts)
	cert, ok := c.certs[key]
	if !ok {
		c.Logger.Debug("certificate not found in in-process cache")
		cert, err = c.readCertificate(key, hosts, now)
		if err != nil {
			return
		}
		if cert != nil {
			c.certs[key] = cert
		} else {
			c.Logger.Debug("certificate not found in cache directory")
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
