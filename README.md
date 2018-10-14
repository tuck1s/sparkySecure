Tools to apply S/MIME encryption and signing, for sending messages through SparkPost.

```
$ ./sparkpostSMIME.py -h
usage: sparkpostSMIME.py [-h] [--encrypt] [--sign] emlfile

Send an email file via SparkPost with optional S/MIME encryption and signing.

positional arguments:
  emlfile     filename to read (in RFC822 format)

optional arguments:
  -h, --help  show this help message and exit
  --encrypt   Encrypt with a recipient certificate containing public key.
              Requires file.crt where file matches To: address.
  --sign      Sign with a sender key. Requires file.crt containing public key,
              and file.pem containing private key, where file matches From:
              address.
```

