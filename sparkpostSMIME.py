#!/usr/bin/env python3
from __future__ import print_function
import email, os, time, argparse, smime, base64, sys
from sparkpost import SparkPost
from sparkpost.exceptions import SparkPostAPIException
from email.utils import parseaddr
from email.mime.text import MIMEText
from OpenSSL import crypto
from copy import deepcopy

def getConfig():
    """
    Read SparkPost API sending config from env vars
    """
    cfg ={
        'sparkpost_host': os.getenv('SPARKPOST_HOST', 'https://api.sparkpost.com'),
        'sparkpost_api_key': os.getenv('SPARKPOST_API_KEY'),
    }
    if not cfg['sparkpost_host'].startswith('https://'):
        cfg['sparkpost_host'] = 'https://' + cfg['sparkpost_host']  # Add schema
    if cfg['sparkpost_host'].endswith('/'):
        cfg['sparkpost_host'] = cfg['sparkpost_host'][:-1]          # Strip /

    for k, v in cfg.items():
        if v == None:
            print('Environment var {} not set - stopping'.format(k))
            exit(1)
    return cfg


def gatherAllRecips(msg):
    """
    Gather all recipients from the message into array of dicts ready for SparkPost API
    See https://support.sparkpost.com/customer/portal/articles/2432290-using-cc-and-bcc-with-the-rest-api
    :type msg: Message
    """
    assert isinstance(msg, email.message.Message)
    allRecips = []
    for hdrName in ['to', 'cc', 'bcc']:
        for i in email.utils.getaddresses(msg.get_all(hdrName, [])):
            r = {
                'address': {
                    'name': i[0],
                    'email': i[1]
                }
            }
            allRecips.append(r)
    return allRecips


PKCS7_NOSIGS = 0x4  # defined in pkcs7.h
def create_embedded_pkcs7_signature(data, cert, key):
    """
    Creates an embedded ("nodetached") pkcs7 signature.
    This is equivalent to the output of `openssl smime -sign -signer cert -inkey key -outform DER -nodetach < data`
    Thanks to https://stackoverflow.com/a/47098879/8545455

    :type data: bytes
    :type cert: str
    :type key: bytes
    """
    assert isinstance(data, bytes)
    assert isinstance(cert, str)
    assert isinstance(key, str)
    try:
        pkey = crypto.load_privatekey(crypto.FILETYPE_PEM, key)
        signcert = crypto.load_certificate(crypto.FILETYPE_PEM, cert)
    except crypto.Error as e:
        raise ValueError('Certificates files are invalid') from e

    bio_in = crypto._new_mem_buf(data)
    pkcs7 = crypto._lib.PKCS7_sign(signcert._x509, pkey._pkey, crypto._ffi.NULL, bio_in, PKCS7_NOSIGS)
    bio_out = crypto._new_mem_buf()
    crypto._lib.i2d_PKCS7_bio(bio_out, pkcs7)
    signed_data = crypto._bio_to_string(bio_out)
    return signed_data


def signEmailFrom(msg, fromAddr):
    """ Signs the provided email message object with the from address cert (.crt) & private key (.pem) from current dir.
    :type msg: email.message.Message
    :type fromAddr: str

    Returns signed message object, in format
        Content-Type: application/x-pkcs7-mime; smime-type=signed-data; name="smime.p7m"
        Content-Disposition: attachment; filename="smime.p7m"
        Content-Transfer-Encoding: base64
    See RFC5751 section 3.4
    The reason for choosing this format, rather than multipart/signed, is that it prevents the delivery service
    from applying open/link tracking or other manipulations on the body.
    """
    assert isinstance(msg, email.message.Message)
    assert isinstance(fromAddr, str)
    pubCertFile = fromAddr + '.crt'
    privkeyFile = fromAddr + '.pem'
    if os.path.isfile(pubCertFile) and os.path.isfile(privkeyFile):
        with open(pubCertFile) as cert_fp:
            cert = cert_fp.read()
            with open(privkeyFile) as key_fp:
                key = key_fp.read()
                rawMsg = msg.as_bytes()
                sgn = create_embedded_pkcs7_signature(rawMsg, cert, key)
                msg.set_payload(base64.encodebytes(sgn))
                hdrList = [
                    ('Content-Type', 'application/x-pkcs7-mime; smime-type=signed-data; name="smime.p7m"'),
                    ('Content-Transfer-Encoding', 'base64'),
                    ('Content-Disposition', 'attachment; filename="smime.p7m"')
                ]
                for i in hdrList:
                    if msg.get(i[0]):
                        msg.replace_header(i[0], i[1])
                    else:
                        msg.add_header(i[0], i[1])
    else:
        msg = None                  # message could not be signed
    return msg


def fixTextPlainParts(msg):
    """
    Fix up any text parts into base64 encoding, otherwise block cipher such as AES is unhappy.

    :type msg: email.message.Message
    """
    assert isinstance(msg, email.message.Message)
    if msg.is_multipart():
        parts = msg.get_payload()
        for i in range(len(parts)):
            q = fixTextPlainParts(parts[i])
            msg._payload[i] = q
        return msg
    elif msg.get_content_type() == 'text/plain':
        txt = msg.get_payload()
        m = MIMEText(txt, _charset='utf-8')
        return m
    else:
        return msg


def copyPayload(m1, m2):
    """
    Replace the message payload (and MIME headers) in m2 with the contents of m1, leaving m2's other headers intact.

    :type m1: email.message.Message
    :type m2: email.message.Message
    """
    assert isinstance(m1, email.message.Message)
    assert isinstance(m2, email.message.Message)
    m2._payload = m1._payload
    for i in m1.items():
        if m2.get(i[0]):
            m2.replace_header(i[0], i[1])
        else:
            m2.add_header(i[0], i[1])


def buildSMIMEemail(msg, encrypt=False, sign=False):
    """
    Build SMIME email, given a message file in RFC822 .eml format. Options to encrypt and sign.

    :type msg: email.message.Message
    """
    assert isinstance(msg, email.message.Message)
    _, fromAddr = parseaddr(msg.get('From'))
    _, toAddr = parseaddr(msg.get('To'))
    msg2 = deepcopy(msg)                # don't overwrite input object as we work on it
    body = fixTextPlainParts(msg2)
    copyPayload(body, msg2)
    # Sign the message, replacing it in-situ
    if sign:
        msg2 = signEmailFrom(msg2, fromAddr)
        if msg2==None:
            return None                 # failed
    # Encrypt the message, replacing it in-situ
    if encrypt:
        rcptFile = toAddr + '.crt'
        with open(rcptFile, 'rb') as crtFile:
            rcptPem = crtFile.read()
            msg2 = smime.encrypt(msg2, rcptPem)
    return msg2


def sendSparkPost(sp, msg):
    """
    Inject into a SparkPost endpoint, given a message object.

    :type sp: SparkPost
    :type msg: email.message.Message
    """
    assert isinstance(sp, SparkPost)
    assert isinstance(msg, email.message.Message)
    allRecips = gatherAllRecips(msg)
    # Prevent SparkPost from wrapping links and inserting tracking pixels, if signed or encrypted.
    # Also set "transactional" flag to suppress the List-Unsubscribe header.
    sendObj = {
        'campaign': 'sparkpost-SMIME',
        'track_opens': False,
        'track_clicks': False,
        'transactional': True,
        'email_rfc822': msg.as_string(),
        'recipients': allRecips
    }
    # send message via SparkPost
    startT = time.time()
    try:
        res = sp.transmissions.send(**sendObj)                  # Unpack for the call
        endT = time.time()
        if res['total_accepted_recipients'] != len(sendObj['recipients']):
            print(res)
        else:
            print('OK - in', round(endT - startT, 3), 'seconds')
        return res['total_accepted_recipients'], ''
    except SparkPostAPIException as err:
        errMsg = 'error code ' + str(err.status) + ' : ' + str(err.errors)
        print(errMsg)
        return 0, errMsg


# -----------------------------------------------------------------------------------------
# Main code
# -----------------------------------------------------------------------------------------
if __name__ == "__main__":
    parser = argparse.ArgumentParser(description='Send an email file via SparkPost with optional S/MIME encryption and signing.')
    parser.add_argument('emlfile', type=str, help='filename to read (in RFC822 format)')
    parser.add_argument('--encrypt', action='store_true', help='Encrypt with a recipient certificate containing public key. Requires file.crt where file matches To: address.')
    parser.add_argument('--sign', action='store_true', help='Sign with a sender key. Requires file.crt containing public key, and file.pem containing private key, where file matches From: address.')
    parser.add_argument('--send_api', action='store_true', help='Send via SparkPost API, using env var SPARKPOST_API_KEY and optional SPARKPOST_HOST.')

    args = parser.parse_args()
    if os.path.isfile(args.emlfile):
        with open(args.emlfile) as fp:
            msgOut = buildSMIMEemail(email.message_from_file(fp), encrypt=args.encrypt, sign=args.sign)
            if args.send_api:
                cfg = getConfig()
                sp = SparkPost(api_key=cfg['sparkpost_api_key'], base_uri=cfg['sparkpost_host'])
                print('Opened connection to', sp.base_uri)
                print('Sending {}\tFrom: {}\tTo: {} '.format(args.emlfile, msgOut.get('From'), msgOut.get('To')), end='')
                sendSparkPost(sp, msgOut)
            else:
                try:
                    print(msgOut.as_string())
                except BrokenPipeError:
                    # See https://docs.python.org/3/library/signal.html#note-on-sigpipe
                    devnull = os.open(os.devnull, os.O_WRONLY)
                    os.dup2(devnull, sys.stdout.fileno())
                    sys.exit(1)  # Python exits with error code 1 on EPIPE
    else:
        print('Unable to open file', args.emlfile)
        exit(1)
