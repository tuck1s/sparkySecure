#!/usr/bin/env python3
from __future__ import print_function
import email, os, time, argparse, smime, base64, sys
from sparkpost import SparkPost
import requests
from email.utils import parseaddr
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
from email.mime.application import MIMEApplication
from OpenSSL import crypto
from copy import deepcopy
from smtplib import SMTP, SMTPException

def getConfig(api=True):
    """
    Read SparkPost API sending config (or SMTP sending config) from env vars.

    :type api: bool
    """
    if(api):
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
    else:
        # SMTP settings. SMTP_HOST is a mandatory setting.
        cfg ={
            'smtp_host': os.getenv('SMTP_HOST'),
            'smtp_port': int(os.getenv('SMTP_PORT', '25')),
            'smtp_user': os.getenv('SMTP_USER', ''),
            'smtp_password': os.getenv('SMTP_PASSWORD', '')
        }
        if cfg['smtp_host'] == None:
            print('Environment var {} not set - stopping'.format('SMTP_HOST'))
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
PKCS7_DETACHED=0x40
def create_embedded_pkcs7_signature(data, cert, key, pkcs7_option):
    """
    Creates an pkcs7 signature.
    For PKCS7_OPT == PKCS7_NOSIGS: equivalent to the output of `openssl smime -sign -signer cert -inkey key -outform DER -nodetach < data`
    Thanks to https://stackoverflow.com/a/47098879/8545455

    For PKCS7_OPT == PKCS7_DETACHED: equivalent to the output of `openssl smime -sign -signer cert -inkey key -outform DER < data`

    :type data: bytes
    :type cert: str
    :type key: bytes
    :type pkcs7_option: int
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
    pkcs7 = crypto._lib.PKCS7_sign(signcert._x509, pkey._pkey, crypto._ffi.NULL, bio_in, pkcs7_option)
    bio_out = crypto._new_mem_buf()
    crypto._lib.i2d_PKCS7_bio(bio_out, pkcs7)
    signed_data = crypto._bio_to_string(bio_out)
    return signed_data


def signEmailFrom(msg, pubcert, privkey, sign_detached=False):
    """ Signs the provided email message object with the from address cert (.crt) & private key (.pem) from current dir.
    :type msg: email.message.Message
    :type pubcert: str
    :type privkey: str
    :type sign_detached: bool

    Default - Returns signed message object, in format
        Content-Type: application/x-pkcs7-mime; smime-type=signed-data; name="smime.p7m"
        Content-Disposition: attachment; filename="smime.p7m"
        Content-Transfer-Encoding: base64
    See RFC5751 section 3.4
    The reason for choosing this format, rather than multipart/signed, is that it prevents the delivery service
    from applying open/link tracking or other manipulations on the body.

    sign_detached == true:, Returns signed message object, in format
        Content-Type: multipart/signed; protocol="application/x-pkcs7-signature";

    The reason for choosing this format is for transparency on mail clients that do not understand S/MIME.
    """
    assert isinstance(msg, email.message.Message)
    assert isinstance(pubcert, str)
    assert isinstance(privkey, str)
    assert isinstance(sign_detached, bool)
    if sign_detached:
        # Need to fix up the header order and formatting here
        rawMsg = msg.as_bytes()
        sgn = create_embedded_pkcs7_signature(rawMsg, pubcert, privkey, PKCS7_DETACHED)
        # Wrap message with multipart/signed header
        msg2 = MIMEMultipart() # this makes a new boundary
        bound = msg2.get_boundary() # keep for later as we have to rewrite the header
        msg2.set_default_type('multipart/signed')
        copyHeaders(msg, msg2)
        del msg2['Content-Language'] # These don't apply to multipart/signed
        del msg2['Content-Transfer-Encoding']
        msg2.attach(msg)
        sgn_part = MIMEApplication(sgn, 'x-pkcs7-signature; name="smime.p7s"', _encoder=email.encoders.encode_base64)
        sgn_part.add_header('Content-Disposition', 'attachment; filename="smime.p7s"')
        msg2.attach(sgn_part)
        # Fix up Content-Type headers, as default class methods don't allow passing in protocol etc.
        msg2.replace_header('Content-Type', 'multipart/signed; protocol="application/x-pkcs7-signature"; micalg="sha1"; boundary="{}"'.format(bound))
        return msg2

    else:
        rawMsg = msg.as_bytes()
        sgn = create_embedded_pkcs7_signature(rawMsg, pubcert, privkey, PKCS7_NOSIGS)
        msg.set_payload(base64.encodebytes(sgn))
        hdrList = {
            'Content-Type': 'application/x-pkcs7-mime; smime-type=signed-data; name="smime.p7m"',
            'Content-Transfer-Encoding': 'base64',
            'Content-Disposition': 'attachment; filename="smime.p7m"'
        }
        copyHeaders(hdrList, msg)
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


def copyHeaders(m1, m2):
    """
    Replace the headers in m2 with the contents of m1, leaving m2's other headers intact.

    :type m1: email.message.Message
    :type m2: email.message.Message
    """
    for i in m1.items():
        if m2.get(i[0]):
            m2.replace_header(i[0], i[1])
        else:
            m2.add_header(i[0], i[1])


def copyPayload(m1, m2):
    """
    Replace the message payload in m2 with the contents of m1, leaving m2's other headers intact.

    :type m1: email.message.Message
    :type m2: email.message.Message
    """
    assert isinstance(m1, email.message.Message)
    assert isinstance(m2, email.message.Message)
    m2._payload = m1._payload


def buildSMIMEemail(msg, encrypt=False, sign=False, sign_detached=False, r_cert=None, s_pubcert=None, s_privkey=None):
    """
    Build SMIME email, given a message file in RFC822 .eml format. Options to encrypt and sign (and sign_detached).
    For encryption, requires recipient's public key cert.
    For signing, requires sender's public key cert and private key.

    :type msg: email.message.Message
    """
    assert isinstance(msg, email.message.Message)
    msg2 = deepcopy(msg)                # don't overwrite input object as we work on it
    body = fixTextPlainParts(msg2)      # ensure any text/plain parts are base64, block ciphers seem to require it
    copyPayload(body, msg2)
    copyHeaders(body, msg2)
    msg2.__delitem__('Bcc')             # always remove these from the delivered message

    # Sign the message, replacing it in-situ
    if sign or sign_detached:
        msg2 = signEmailFrom(msg2, s_pubcert, s_privkey, sign_detached = sign_detached)
        if msg2==None:
            return None                 # failure, exit early
    # Encrypt the message, replacing it in-situ
    if encrypt:
        msg2 = smime.encrypt(msg2, r_cert.encode('utf8'))
        # could be valid message or None if an operation failed
    return msg2


def sendSparkPost(sp, msg, track):
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
    # Now uses requests library rather than python-sparkpost library, to get access to all API features.
    sendObj = {
        'content': {
            'email_rfc822': msg.as_string(),
        },
        'campaign_id': 'sparkpost-SMIME',
        'options': {
            'open_tracking': track,
            'click_tracking': track,
            'transactional': not track,
        },
        'recipients': allRecips
    }
    # send message via SparkPost
    startT = time.time()
    try:
        headers = {
            'Content-Type': 'application/json',
            'Authorization': sp.get_api_key()
        }
        rawRes = requests.post(sp.transmissions.uri, json=sendObj, headers=headers)
        endT = time.time()
        if rawRes.status_code != 200:
            print(rawRes.text)
            return 0, rawRes.text

        resJSON = rawRes.json()
        res = resJSON.get('results')
        if res['total_accepted_recipients'] != len(sendObj['recipients']):
            print(res)
        else:
            print('OK - in', round(endT - startT, 3), 'seconds')
        return res['total_accepted_recipients'], ''
    except Exception as err:
        errMsg = 'error code ' + str(err)
        print(errMsg)
        return 0, errMsg


def getKeysFor(msg, encrypt, sign):
    """
    Get the keys for the message from current directory, depending on whether encypting, signing, or both.
    Prints console message if invalid.
    :type msg: email.message.Message
    :returns keys + error = None if OK, otherwise error string
    """
    assert isinstance(msg, email.message.Message)
    _, fromAddr = parseaddr(msg.get('From'))
    _, toAddr = parseaddr(msg.get('To'))
    r_cert, s_pubcert, s_privkey, error = None, None, None, None
    if encrypt:
        rcptCertFile = toAddr + '.crt'
        if not os.path.isfile(rcptCertFile):
            error = 'Recipient public cert file ' + rcptCertFile +  ' not found in current directory'
        else:
            with open(rcptCertFile, 'r') as crtFile:
                r_cert = crtFile.read()
    if sign:
        pubCertFile = fromAddr + '.crt'
        privKeyFile = fromAddr + '.pem'
        if not os.path.isfile(pubCertFile):
            error = 'Sender public cert file ' + pubCertFile + ' not found in current directory'
        else:
            with open(pubCertFile, 'r') as cert_fp:
                s_pubcert = cert_fp.read()
                if not os.path.isfile(privKeyFile):
                    error = 'Sender private key file ' + privKeyFile + ' not found in current directory'
                else:
                    with open(privKeyFile, 'r') as key_fp:
                        s_privkey = key_fp.read()
    return r_cert, s_pubcert, s_privkey, error


def do_smime(args):
    """
    Carry out the actions specified by the command-line args. Returns an RFC822 format email message, or exits with
    an error unable to complete.

    :param args: Namespace
    """
    if os.path.isfile(args.emlfile):
        with open(args.emlfile) as fp:
            eml = email.message_from_file(fp)
            r_cert, s_pubcert, s_privkey, error = getKeysFor(eml, encrypt=args.encrypt, sign=(args.sign or args.sign_detached))
            if error:
                print(error, '- stopping')
                exit(1)
            else:
                msgOut = buildSMIMEemail(eml, encrypt=args.encrypt, sign=args.sign, sign_detached=args.sign_detached,
                    r_cert=r_cert, s_pubcert=s_pubcert, s_privkey=s_privkey)
                if msgOut == None:
                    print('Error building S/MIME file - stopping')
                    exit(1)
                else:
                    return msgOut
    else:
        print('Unable to open file', args.emlfile, '- stopping')
        exit(1)


# -----------------------------------------------------------------------------------------
# Main code
# -----------------------------------------------------------------------------------------
if __name__ == "__main__":
    parser = argparse.ArgumentParser(description='Send an email file via SparkPost with optional S/MIME encryption and signing.')
    parser.add_argument('emlfile', type=str, help='filename to read (in RFC822 format)')
    parser.add_argument('--encrypt', action='store_true', help='Encrypt with a recipient certificate containing public key. Requires file.crt where file matches To: address.')

    p2 = parser.add_mutually_exclusive_group(required=False)
    p2.add_argument('--sign', action='store_true', help='Sign with a sender key. Requires file.crt containing public key, and file.pem containing private key, where file matches From: address.')
    p2.add_argument('--sign_detached', action='store_true', help='Sign with a sender key, but using ')

    output = parser.add_mutually_exclusive_group(required=False)
    output.add_argument('--send_api', action='store_true', help='Send via SparkPost API, using env var SPARKPOST_API_KEY and optional SPARKPOST_HOST.')
    output.add_argument('--send_smtp', action='store_true', help='Send via SMTP, using env vars SMTP_HOST, SMTP_PORT (optional, defaults to 25), SMTP_USER, SMTP_PASSWORD.')

    parser.add_argument('--track', action='store_true', help='Enable API engagement tracking (not allowed when signing; otherwise message will be marked as corrupt)')

    args = parser.parse_args()

    if (args.sign or args.sign_detached) and args.track:
        print('Invalid combination of arguments - cannot track signed messages')
        exit(1)
    msgOut = do_smime(args)
    if args.send_api:
        cfg = getConfig(api=True)
        sp = SparkPost(api_key=cfg['sparkpost_api_key'], base_uri=cfg['sparkpost_host'])
        print('Opened connection to', sp.base_uri)
        print('Sending {}\tFrom: {}\tTo: {}\tTracking: {}'.format(args.emlfile, msgOut.get('From'), msgOut.get('To'), args.track))
        sendSparkPost(sp, msgOut, args.track)

    elif args.send_smtp:
        #FIXME: SMTP code works OK for basic MTAs, but needs headers added to turn off tracking etc. for SparkPost
        cfg = getConfig(api=False)
        try:
            startT = time.time()
            with SMTP(cfg['smtp_host'], port=cfg['smtp_port']) as smtp:
                #smtp.set_debuglevel(2)    # Uncomment this if you wish to see the SMTP conversation / STARTTLS neg.
                smtp.ehlo(name='sparkpostSMIME')
                if 'starttls' in smtp.esmtp_features:
                    smtp.starttls()         # raises an exception if it fails. If continues, we're good
                    smtp.ehlo(name='sparkpostSMIME')
                    mode_str = 'STARTTLS'
                else:
                    mode_str = 'plain'
                if cfg['smtp_user'] and cfg['smtp_password']:
                    smtp.login(cfg['smtp_user'], cfg['smtp_password'])
                print('Opened SMTP connection ({}) to {}, port {}, user="{}", password="{}"'.format(
                    mode_str,
                    cfg['smtp_host'],
                    cfg['smtp_port'],
                    cfg['smtp_user'],
                    '*' * len(cfg['smtp_password'])))
                print('Sending {}\tFrom: {}\tTo: {} '.format(args.emlfile, msgOut.get('From'), msgOut.get('To')))
                smtp.send_message(msgOut)
                endT = time.time()
                print('OK - in', round(endT - startT, 3), 'seconds')
        except SMTPException as e:
            print(e)
            exit(1)
    else:
        # console output (stdout). See https://docs.python.org/3/library/signal.html#note-on-sigpipe
        try:
            print(msgOut.as_string())
        except BrokenPipeError:
            devnull = os.open(os.devnull, os.O_WRONLY)
            os.dup2(devnull, sys.stdout.fileno())
            exit(1)  # Python exits with error code 1 on EPIPE
