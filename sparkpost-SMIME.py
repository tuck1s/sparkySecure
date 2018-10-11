#!/usr/bin/env python3
from __future__ import print_function

import email, os, time, argparse
from sparkpost import SparkPost
from sparkpost.exceptions import SparkPostAPIException
from email.utils import parseaddr
import smime
import subprocess
from email.mime.text import MIMEText
from tempfile import NamedTemporaryFile

def getConfig():
    """read SparkPost sending config from env vars."""
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

#TODO: may not be necessary
def gatherAllRecips(msg):
    """ Gather all recipients from the message into array of dicts ready for SparkPost API
    See https://support.sparkpost.com/customer/portal/articles/2432290-using-cc-and-bcc-with-the-rest-api """
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


def signEmailFrom(msg, fromAddr):
    """ Signs the provided email message object with the from address cert (.crt) & private key (.pem) from current dir.
    Returns signed mail string """
    eml = msg.as_bytes()
    with NamedTemporaryFile('wb') as tmpFile:
        tmpFile.file.write(eml)
        tmpFile.file.close()
        pubCertFile = fromAddr + '.crt'
        privkeyFile = fromAddr + '.pem'
        if os.path.isfile(pubCertFile) and os.path.isfile(privkeyFile):
            myout = subprocess.run(['openssl', 'smime', '-in', tmpFile.name, '-sign', '-signer', pubCertFile, '-inkey', privkeyFile, '-md','sha256'], capture_output=True)
            if myout.returncode == 0:
                sout = myout.stdout.decode('utf8')
                return sout
                #signedMessage = email.message_from_string(sout)
                #return signedMessage
            else:
                return None
        else:
            print('Unable to open public and private key files for fromAddr', fromAddr)
            return None

def copyHeaders(e1, e2):
    """ Copy needed headers across from message e1 to e2 """
    for h in ['From', 'To', 'Cc', 'Subject']:
        if h in e1:
            e2[h] = e1[h]

def fixTextPlainParts(msg):
    if msg.is_multipart():
        parts = msg.get_payload()
        for i in range(len(parts)):
            q = fixTextPlainParts(parts[i])
            msg._payload[i] = q
        return msg
    elif msg.get_content_type() == 'text/plain':
        # Ensure any text parts are put into base64, otherwise block cipher e.g. AES is unhappy
        txt = msg.get_payload()
        m = MIMEText(txt, _charset='utf-8')
        return m
    else:
        return msg

def copyPayload(m1, m2):
    """ Replace the message payload (and MIME headers) in m2 with the contents of m1 """
    m2._payload = m1._payload
    for i in m1.items():
        m2.replace_header(i[0], i[1])

def sendEml(sp, emlfile, encrypt=False, sign=False):
    """ Inject into a SparkPost endpoint, given a message file in RFC822 .eml format and recipient public key. """
    with open(emlfile) as fp:
        msgIn = email.message_from_file(fp)
        allRecips = gatherAllRecips(msgIn)
        _, fromAddr = parseaddr(msgIn.get('From'))
        _, toAddr = parseaddr(msgIn.get('To'))

        copyPayload(fixTextPlainParts(msgIn), msgIn)

        # Sign the message
        if sign:
            signedPayload = signEmailFrom(msgIn, fromAddr)
            with open('debug2.eml', 'w') as f:
                f.write(signedPayload)
                f.close()
            signedMessage = email.message_from_string(signedPayload)
            copyPayload(signedMessage, msgIn)

        # Encrypt the message, returning as a string
        if encrypt:
            rcptFile = toAddr + '.crt'
            with open(rcptFile, 'rb') as crtFile:
                rcptPem = crtFile.read()
                s = smime.encrypt(msgIn, rcptPem)
        else:
            s = msgIn.as_string()

        # TODO: debug code, remove when done
        with open('debug3.eml', 'w') as f:
            f.write(s)
            f.close()

        sendObj = {
            'campaign': 'sparkpost-SMIME',
            'track_opens': True,
            'track_clicks': True,
            'email_rfc822': s,
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
parser = argparse.ArgumentParser(description='Send an email file via SparkPost with optional S/MIME encryption and signing.')
parser.add_argument('emlfile', type=str, help='filename to read (in RFC822 format)')
parser.add_argument('--encrypt', action='store_true', help='Encrypt with a recipient certificate containing public key. Requires file.crt where file matches To: address.')
parser.add_argument('--sign', action='store_true', help='Sign with a sender key. Requires file.crt containing public key, and file.pem containing private key, where file matches From: address.')
args = parser.parse_args()
cfg = getConfig()

if os.path.isfile(args.emlfile):
    sp = SparkPost(api_key=cfg['sparkpost_api_key'], base_uri=cfg['sparkpost_host'])
    print('Opened connection to', sp.base_uri)
    for fname in ['declaration.eml', 'img_and_attachment.eml']:
        for enc in [True]:                      # False
            for sign in [True]:
                sendEml(sp, fname, encrypt=enc, sign=sign)
else:
    print('Unable to open file', args.emlfile)
    exit(1)
