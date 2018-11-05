<a href="https://www.sparkpost.com"><img src="https://www.sparkpost.com/sites/default/files/attachments/SparkPost_Logo_2-Color_Gray-Orange_RGB.svg" width="200px"/></a>

[Sign up](https://app.sparkpost.com/join?plan=free-0817?src=Social%20Media&sfdcid=70160000000pqBb&pc=GitHubSignUp&utm_source=github&utm_medium=social-media&utm_campaign=github&utm_content=sign-up) for a SparkPost account and visit our [Developer Hub](https://developers.sparkpost.com) for even more content.

# sparkySecure
[![Build Status](https://travis-ci.org/tuck1s/sparkySecure.svg?branch=master)](https://travis-ci.org/tuck1s/sparkySecure)

A collection of tools for working with secure S/MIME format files and SparkPost.

# sparkpostSMIME
Send an email file via SparkPost with optional S/MIME encryption and signing.

## Usage
```
$  ./sparkpostSMIME.py -h
usage: sparkpostSMIME.py [-h] [--encrypt] [--sign] [--send_api] emlfile

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
  --send_api  Send via SparkPost API (using env var SPARKPOST_API_KEY).
```

When sending an .eml file from sender@example.com to recip@gmail.com, the following key files are required:

|File|Containing|
|---|---|
|`recip@gmail.com.crt`|Recipient's public key in x509 certificate format, required for *encryption*|       
|`sender@example.com.crt`|Sender's public key in x509 certificate format, required for *signing*|
|`sender@example.com.pem`|Sender's private key required for *signing*|

### Default text output
If the `--send_api` option is absent, RFC822 output text is written to the console.
```
$ ./sparkpostSMIME.py testcases/img_and_attachment.eml --sign --encrypt
To: Bob <bob.lumreeker@gmail.com>
From: Steve <steve@thetucks.com>
Subject: Testing attachments etc
Content-Language: en-GB
MIME-Version: 1.0
Content-Type: application/pkcs7-mime; smime-type=enveloped-data; name=smime.p7m
Content-Transfer-Encoding: base64
Content-Disposition: attachment; filename=smime.p7m

MIMPPccGCSqGSIb3DQEHA6CDDz23MIMPPbICAQAxggHHMIIBwwIBADCBrDCBlzEL
MAkGA1UEBhMCR0IxGzAZBgNVBAgTEkdyZWF0ZXIgTWFuY2hlc3RlcjEQMA4GA1UE
:
:
```

### Sending via SparkPost API
If `--send_api` option is present, environment variables are used to send the email via SparkPost.

|Variable|Meaning|
|---|---|
|`SPARKPOST_API_KEY`|Required|
|`SPARKPOST_HOST`|For EU customers set to `https://api.eu.sparkpost.com`. Enterprise customers set to own specific host address|

Example:
```
$ ./sparkpostSMIME.py testcases/img_and_attachment.eml --sign --encrypt --send_api
Opened connection to https://api.sparkpost.com/api/v1
OK - in 3.921 seconds
```

# mimeshow
Display internal header and MIME structure of a mail file in RFC822 format, indented for ease of reading.

## Usage 
```
$ ./mimeshow.py -h
usage: mimeshow.py [-h] file

Display internal header and MIME structure of a mail file in RFC822 format,
indented for ease of reading

positional arguments:
  file        filename to read

optional arguments:
  -h, --help  show this help message and exit
```

### Example
```
$ ./mimeshow.py testcases/img_and_attachment.eml 
To Bob <bob.lumreeker@gmail.com>
From Steve <steve@thetucks.com>
Subject Testing attachments etc
MIME-Version 1.0
Content-Type multipart/mixed; boundary="------------7D48652042860D0098C65210"
Content-Language en-GB

  Content-Type multipart/alternative; boundary="------------58C0BF87598336550D70EB95"

    Content-Type text/plain; charset=utf-8; format=flowed
    Content-Transfer-Encoding 7bit

    Content-Transfer-Encoding quoted-printable
    Content-Type text/html; charset="utf-8"

  Content-Type application/pdf; name="sparkpost-datasheet-tam-technical-account-management.pdf"
  Content-Transfer-Encoding base64
  Content-Disposition attachment; filename="sparkpost-datasheet-tam-technical-account-management.pdf"
 
```

# Installing

Here's a basic installation sequence, starting from fresh Amazon Linux, using the dependencies
declared in the included `Pipfile` to create a Python virtual environment.

```
# First, get the Python interpreter and git cli tool. Doesn't have to be version 3.6 specifically,
# that's just what Amazon Linux requires.
sudo yum install -y python36 git

# Create environment. Note your pip command names and options may vary depending on OS.
# The following is for Amazon Linux.
# Your OS may name this tool pip3 rather than using a version-specific name.
/usr/bin/pip-3.6 install --user pipenv

# Install project
git clone https://github.com/tuck1s/sparkySecure.git
cd sparkySecure

# Install dependencies into virtualenv, including some specific lib versions.
# Virtual environments take away tool version / paths pain, once you have one.
pipenv --python 3.6 install
pipenv shell

# Now inside our virtual env
export SPARKPOST_API_KEY=<<<YOUR API KEY HERE>>>

# If the following gives you help text, then you're good.
./sparkpostSMIME.py -h
```

Then create your keys and send .eml files as above.

#### Internal implementation notes

The `Pipfile` currently declares a couple of specific library dependencies for the sparkpostSMIME tool:
- a [modified fork](https://github.com/tuck1s/python-smime) of the `python-smime` library
- a pre-release [fork](https://github.com/tuck1s/python-sparkpost) of the `python-sparkpost` library

