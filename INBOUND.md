# Inbound email certificate handling

Comprises the following tools:
- `readSMIMEsig.py` - read an email and parse out intermediate and user certificates
- `webapp.py` - simple Flask-compabible web application for use with SparkPost Inbound Relay Webhooks
- `webapp.ini` - configuration file for the above
- Logfile formats created by these tools

# readSMIMEsig.py

Can be invoked from the command-line to parse the specified mail file. This can be useful during
testing. When used as part of the web application (see following) the top-level worker function in this file `read_smime_email` is called directly.

## Usage

```
./readSMIMEsig.py -h
usage: readSMIMEsig.py [-h] emlfile

read an S/MIME signature from a .eml file

positional arguments:
  emlfile     filename to read (in RFC822 format)

optional arguments:
  -h, --help  show this help message and exit

```

# webapp.py

This web application file is designed to run under Flask / Gunicorn. It comprises a
basic SparkPost [Inbound Relay Webhooks](https://www.sparkpost.com/docs/tech-resources/inbound-email-relay-webhook/) parser.

Optional, but recommended: you can specify a required `X-MessageSystems-Webhook-Token` value in `webapp.ini`. This provides a means to ensure the inputs to the web application are coming from a source
that you trust, rather than from an unknown source.

## Starting

A sample shell script for starting the service is provided in [starting_gun.sh](starting_gun.sh). Modify the port numbers etc. to suit your environment.
The file includes some commentary on the parameters.

## Error handling

The web service responds on path `/`, and only to the `POST` http method. Other methods and addresses will return an http error response, such as

```
405 Method Not Allowed
The method is not allowed for the requested URL.
```

```
404 Not Found
The requested URL was not found on the server.  If you entered the URL manually please check your spelling and try again.
```

If the http(s) request is valid but the content is invalid, you will see a response giving the reason:

```
400 Bad Request
{
    "message": "Unknown Content-Type in request headers"
}
```

```
400 Bad Request
{
    "message": "Invalid X-MessageSystems-Webhook-Token in request headers"
}
```

# DKIM validation

DKIM checks are applied to the inbound mail. Specifically, the DKIM signature must be valid, and the signing domain `d=` must be identical to the `From:` domain.
This is an anti-spoofing safety measure, intended to prevent bad actors injecting seemingly valid-looking certificates.

The premise is that any competent personal mailbox provider should have applied a valid DKIM signature to the mail sent to this application.
You could bypass DKIM checks if necessary, but you are then solely relying on the certificate validity checks.

# Certificate validation

User certificates (and any intermediates found) are extracted from the inbound mail and
validated against the trusted certificate bundle file given in `webapp.ini`.

A valid bundle is necessary to operate the tools. A trusted bundle (from a recent CentOS host) is included in the project, but you may wish to
refer to your own host's trusted bundle instead.

# webapp.ini

The [webapp.ini](webapp.ini) file is used to configure the application behaviour.

## Certificate file output

The tool writes certificates into files named with the
full email address of the sender (e.g. `sender@example.com.crt`) in
[Privacy-Enhanced Mail (PEM)](https://en.wikipedia.org/wiki/Privacy-Enhanced_Mail) format.
File contents are base64 data comprising just the single user certificate:

bob.lumreeker\@gmail.com.crt:
```
-----BEGIN CERTIFICATE-----
MIIFOTCCBCGgAwIBAgIQSP9rjNDl9bQK5T+HiKtsRDANBgkqhkiG9w0BAQsFADCB
:
:
-----END CERTIFICATE-----
```

### Viewing received certificate file content

This can be done using `openssl`:

```
openssl x509 -inform PEM -in bob.lumreeker\@gmail.com.crt -text -noout
```

## Application logfile output

As well as the generic Gunicorn access logfile, the tools generate fairly verbose application-specific information:

webapp.log
```
2019-01-13 17:57:05,195,root,INFO,Request from 127.0.0.1,scheme=http,path=/
2019-01-13 17:57:05,207,root,INFO,| len(headers)=9,len(body)=14778
2019-01-13 17:57:43,998,root,INFO,| msg_from=bob.lumreeker@gmail.com,rcpt_to=secureme@inbound.thetucks.com,len(email_rfc822)=9223
2019-01-13 17:57:44,236,root,INFO,| from=bob.lumreeker@gmail.com,DKIM passed
2019-01-13 17:57:44,237,root,INFO,| content-type=multipart/signed; protocol="application/pkcs7-signature"; micalg=sha-256; boundary="------------ms010908020707040304020406",content-description=None
2019-01-13 17:57:44,237,root,INFO,| content-type=text/plain; charset=utf-8; format=flowed,content-description=None
2019-01-13 17:57:44,238,root,INFO,| content-type=application/pkcs7-signature; name="smime.p7s",content-description=S/MIME Cryptographic Signature
2019-01-13 17:57:44,239,root,INFO,| filename=smime.p7s,bytes=3998
2019-01-13 17:57:44,252,root,INFO,| Certificate: subject email_address=['bob.lumreeker@gmail.com'],not_valid_before=2018-10-03 00:00:00,not_valid_after=2019-10-03 23:59:59,hash_algorithm=sha256,key_size=2048 bytes, issuer={'countryName': 'GB', 'stateOrProvinceName': 'Greater Manchester', 'localityName': 'Salford', 'organizationName': 'COMODO CA Limited', 'commonName': 'COMODO RSA Client Authentication and Secure Email CA'}
2019-01-13 17:57:44,254,root,INFO,| Certificate: subject email_address=[],not_valid_before=2013-01-10 00:00:00,not_valid_after=2028-01-09 23:59:59,hash_algorithm=sha384,key_size=2048 bytes, issuer={'countryName': 'GB', 'stateOrProvinceName': 'Greater Manchester', 'localityName': 'Salford', 'organizationName': 'COMODO CA Limited', 'commonName': 'COMODO RSA Certification Authority'}
2019-01-13 17:57:44,259,root,INFO,| verifying intermediate certificates
2019-01-13 17:57:44,260,root,INFO,| intermediates passed, verifying user certificate
2019-01-13 17:57:44,261,root,INFO,| user certificate passed
2019-01-13 17:57:44,262,root,INFO,| written file ./bob.lumreeker@gmail.com.crt,bytes=1870,ok=True
```

The `| ` prefix indentation hopefully makes it easier to see that the above multiple lines of output relate back to the incoming request.

The logfile rotates at midnight, keeping previous x days history.

## Installation
Installation is handled entirely by `pipenv` as described in the project [README.md], no additional steps are needed except to choose the TCP
port number and ensure it's open to the outside world on your host.

## Internal implementation notes

Certificate parsing is naive. It attempts to validate intermediates in the order in which they were
found in the mail, rather than looking at internal structure for hierarchy. This could be improved.

Certificates are extracted only from plain mails with signature attached, i.e.
MIME content type `multipart/signed` with protocol `application/pkcs7-signature`.

Specifically, enveloped messages and encrypted messages `EnvelopedData` or `SignedData` are not currently supported.

As long as the basic JSON structure is OK, the web app will return a 200OK response. This is intentional, as it limits the external disclosure
of information on what this code considers a valid certificate.

Email replies to sender (e.g. passed - "thanks for your certificate", failed - "there is a problem with your certificate") are not done, for
similar reasons, but could easily be added.

Some text responses in the logfile are checked for specifically, in the automated test cases run by `pytest`, to determine test pass/fail.

The trusted certificates (approx 150 in the supplied file from CentOS) are loaded from scratch for each request.
This makes command-line invocation as similar as possible to web app invocation, but could probably be optimized.

Where possible, the newer [`cryptography`](https://cryptography.io/en/latest/) objects and methods have been used. Getting the PKCS#7 data, extracting the certs from that, and verifying
a stack of certs still seems to require the lower-level [`OpenSSL.crypto`](https://pyopenssl.org/en/stable/api/crypto.html) libraries.