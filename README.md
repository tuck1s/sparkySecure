<a href="https://www.sparkpost.com"><img src="https://www.sparkpost.com/sites/default/files/attachments/SparkPost_Logo_2-Color_Gray-Orange_RGB.svg" width="200px"/></a>

[Sign up](https://app.sparkpost.com/join?plan=free-0817?src=Social%20Media&sfdcid=70160000000pqBb&pc=GitHubSignUp&utm_source=github&utm_medium=social-media&utm_campaign=github&utm_content=sign-up) for a SparkPost account and visit our [Developer Hub](https://developers.sparkpost.com) for even more content.

# sparkpostSMIME

Send an email file via SparkPost with optional S/MIME encryption and signing.

## Usage

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

When sending an .eml file from sender@example.com to recip@gmail.com, the following key files are required:

|File|Containing|
|---|---|
|`recip@gmail.com.crt`|Recipient's public key in x509 certificate format, required for *encryption*|       
|`sender@example.com.crt`|Sender's public key in x509 certificate format, required for *signing*|
|`sender@example.com.pem`|Sender's private key required for *signing*|

The following environment variable needs to be set: `SPARKPOST_API_KEY`

### Example

```
$ ./sparkpostSMIME.py testcases/img_and_attachment.eml --sign --encrypt
Opened connection to https://api.sparkpost.com/api/v1
Sending testcases/img_and_attachment.eml        From: steve@thetucks.com        To: bob.lumreeker@gmail.com     OK - in 3.664 seconds
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
sudo yum install -y python36
sudo yum install -y git

# Create environment
sudo -E /usr/bin/pip-3.6 install --upgrade pip
sudo -E /usr/bin/pip-3.6 install pipenv

# install project
git clone https://github.com/tuck1s/sparkySecure.git

cd sparkySecure
# install dependencies into env, including some specific lib versions
pipenv --python 3.6 install
pipenv shell

export SPARKPOST_API_KEY=<<<YOUR API KEY HERE>>>
```

Then create your keys and send .eml files as above.
