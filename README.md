# devproxy

## What is devproxy?

devproxy is intended to be an easily configurable forward HTTP proxy for web application development.

It has the following features:

* URL rewriting

  If you want to get your browser to access to the upstream HTTP server listening on `127.0.0.1:3000` by a request to `http://example.com`, the configuration should look as follows:

  ```
  hosts:
    http://example.com:
      - ^(/.*)$: http://127.0.0.1:3000$1
  ```

  This can be done since the name resolution is done in devproxy, which is configured to map any request for http://example.com to http://127.0.0.1:3000.

* Transparent TLS termination / wrapping (simulation of an SSL/TLS-enabled environment)

  You can also make it possible to direct the request to `https://example.com/` to the upstream by adding the configuration like the following:

  ```
  hosts:
    http://example.com:
      - ^(/.*)$: http://127.0.0.1:3000$1
    https://example.com:
      - ^(/.*)$: http://127.0.0.1:3000$1
  ```

  Even though you don't have a valid certificate prepared for `example.com`, devproxy automatically generates it on the fly.  However, it is necessary to set up the private PKI for issuing bogus server certificates and let your browser trust the PKI's root CA certificate.  **DO IT ON YOUR OWN RISK.**
  
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
      - ^(/.*)$: http://127.0.0.1:3000$1
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

* Serving files on the filesystem
  
  You can also serve the local files by specifying `file:` scheme as an upstream:

  ```
  hosts:
    http://example.com:
      - ^(/.*)$: file:///some-document-root$1
  ```

  *WARNING*: this feature did such naive path translation that is easily exploitable for path traversals beyond the document root.  Never expose the server to public when it is used.

  ```
  file_tx:
    root: /var/empty
    mime_type_file: /usr/share/mime/globs
    mime_type_file_format: xdg-globs
  ```

  Toplevel `file_tx` section configures the file transport.

  * `root` (string, optional)

    Specifies the base directory for resolving a absolute path when a relative form of file URI yields from the match.

  * `mime_type_file` (string, optional)

    Specifies the path to the MIME-type-to-extension mapping file used to deduce a MIME type from the file's extension.
    
    devproxy will use Go's standard `mime.TypeForExtension()` function when unspecified.

  * `mime_type_file_format` (string, optional)

    Specifies the format for the MIME type file.  Accepted values are `apache` and `xdg-globs`.
   

* Proxy chaining

  You can direct outgoing requests to another proxy server.  This is useful in a restricted network environment.

  ```
  proxy:
    http: http://anoother-proxy-server:8080
    https: http://another-proxy-server:8080
  ```

  `excluded` directive can be used when you want to prevent requests for the specific hosts from being proxied.
   
  ```
  excluded: 
    - 127.0.0.1
    - localhost
    - intranet.example.com
  ```
  
  Or inversely, in case of whitelisting:

  ```
  included:
    - intranet.example.com
    - foobar.example.com
  ```
  
  TLS proxy can also be specified.
  
  ```
  proxy:
    http: https://anoother-proxy-server:8443
    https: https://another-proxy-server:8443
    tls:
      ca_certs: cabundle.crt.pem
      certs:
        - cert: client_crt.pem # this can be either the filename of a PEM-formatted certificate or a PEM string itself.
          key: client_key.pem # this can be either the filename of a PEM-formatted private key or a PEM string itself.
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
openssl x509 -req -in testca.rsa.csr.pem -signkey testca.rsa.key.pem -days 3650 -sha256 -extfile x509.ini -extensions CA -out testca.rsa.crt.pem
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
