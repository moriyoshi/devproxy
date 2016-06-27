# devproxy

## What is devproxy?

devproxy is intended to be an easily configurable forward HTTP proxy for web application development.

It has the following features:

* URL rewriting

  If the upstream HTTP server listens on `127.0.0.1:3000` and you want to get your browser to access to it by a request to `http://example.com`, the configuration should look as follows:

  ```
hosts:
    http://example.com:
        - ^(/*)$: http://127.0.0.1:3000$1
  ```

* Transparent TLS wrapping (simulation of an SSL/TLS-enabled environment)

  You can also make it possible to access to the upstream by hitting `https://example.com/` by adding the configuration like the following:

  ```
hosts:
    http://example.com:
        - ^(/*)$: http://127.0.0.1:3000$1
    https://example.com:
        - ^(/*)$: http://127.0.0.1:3000$1
  ```

  It is however necessary to set up the private PKI for issuing bogus server certificates and let your browser trust the PKI's root CA certificate.  **DO IT YOUR OWN RISK.**

  The CA for issuing bogus server certificates is configured as follows:

  ```
tls:
    ca:
        cert: testca.rsa.crt.pem
        key: testca.rsa.key.pem
hosts:
  ...
```

* Request header modification

  You can add / remove arbitrary request HTTP headers for the request being rewritten:

  ```
hosts:
    http://example.com:
        - ^(/*)$: http://127.0.0.1:3000$1
          headers:
              X-Forwarded-Proto: https
              Removed-Header: null
```

* Testing FastCGI-enabled upstream
  
  You can forward the request to a FastCGI-enabled upstream:

  ```
hosts:
    http://example.com:
        - ^(((?:/.*)*/[^/]+\.php)(/.*|$)): fastcgi://localhost$1
          headers:
              X-Cgi-Script-Filename: /var/www/document/root$2
              X-Cgi-Script-Name: $2
              X-Cgi-Path-Info: $3
```


## Installation

```
go get github.com/moriyoshi/devproxy
```

## Using devproxy

```
$GOPATH/bin/devproxy -l listen_addr configuration_file
# ex: $GOPATH/bin/devproxy -l 127.0.0.1:8080 config.yml
```

And Adjust your browser's proxy settings to what is exactly given to `-l` option.

## Setting up the private PKI

```
openssl genrsa 2048 > testca.rsa.key.pem
openssl req -new -key testca.rsa.key.pem -out testca.rsa.csr.pem
openssl x509 -req -in testca.rsa.csr.pem -signkey testca.rsa.key.pem -days 3650 -extfile x509.ini -extensions CA -out testca.rsa.crt.pem
```

x509.ini:
```
[CA]
basicConstraints=critical,CA:TRUE,pathlen:1
keyUsage=digitalSignature,keyCertSign,cRLSign
```

## Configuration file example

```
tls:
  client:
    verify: true
  ca:
    cert: testca.rsa.crt.pem
    key: testca.rsa.key.pem

hosts:
  http://api.example.com:
    - ^(/v1/.*)$: http://localhost:8000$1
    - ^(/v2/.*)$: http://localhost:8001$1
  http://example.com:
    - ^(/asset.*)$: http://localhost:8002$1
    - ^(/.*)$: http://localhost:8003$1
```
