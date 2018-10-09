#!/usr/bin/env python3
from __future__ import print_function

import email, os, time, argparse
from sparkpost import SparkPost
from sparkpost.exceptions import SparkPostAPIException
from email.utils import parseaddr
import smime
import subprocess

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


def signEmailFrom(eml, fromAddr):
    """ Signs the provided email string with the from address cert (.crt) & private key (.pem) from current dir.
    Returns signed mail as a string. """
    pubCertFile = fromAddr + '.crt'
    privkeyFile = fromAddr + '.pem'
    if os.path.isfile(pubCertFile) and os.path.isfile(privkeyFile):
        myout = subprocess.run(['openssl', 'smime', '-in', eml, '-sign', '-signer', pubCertFile, '-inkey', privkeyFile, '-md','sha256'], capture_output=True)
        if myout.returncode == 0:
            r = myout.stdout
            return r.decode('utf8')
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

def sendEml(sp, emlfile, rcptPem):
    """ Inject into a SparkPost endpoint, given a message file in RFC822 .eml format and recipient public key. """
    with open(emlfile) as fp:
        msgIn = email.message_from_file(fp)
        allRecips = gatherAllRecips(msgIn)
        _, fromAddr = parseaddr(msgIn.get('From'))

        # sign the message
        signedText = signEmailFrom(emlfile, fromAddr)
        with open('debug2.eml', 'w') as f:
            f.write(signedText)
        signedMessage = email.message_from_string(signedText)
        copyHeaders(msgIn, signedMessage)

        # encrypt the message
        if rcptPem:
            s = smime.encrypt(signedMessage, rcptPem)
        else:
            s = signedMessage.as_string()

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
cfg = getConfig()
parser = argparse.ArgumentParser(description='Send an email file via SparkPost with S/MIME encryption')
parser.add_argument('emlfile', type=str, help='filename to read (in RFC822 format)')
parser.add_argument('--rcpt_cert', type=str, help='certificate containing recipient public key, used to encrypt message')
args = parser.parse_args()

if os.path.isfile(args.emlfile):
    if args.rcpt_cert:
        with open(args.rcpt_cert, 'rb') as pem:
            rcpt_cert = pem.read()
            print('Recipient cert for signing:', args.rcpt_cert)
    else:
        rcpt_cert = None

    sp = SparkPost(api_key=cfg['sparkpost_api_key'], base_uri=cfg['sparkpost_host'])
    print('Opened connection to', sp.base_uri)
    sendEml(sp, args.emlfile, rcpt_cert)
else:
    print('Unable to open file', args.emlfile)
    exit(1)
