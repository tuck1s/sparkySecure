# test readSMIMEsig functions

import os, configparser, logging
from readSMIMEsig import read_smime_email


def get_email_bytes(fname):
    assert os.path.isfile(fname)
    with open(fname, 'rb') as f:
        return f.read()


def mockConfig():
    config = configparser.ConfigParser()
    config['webapp'] = {
        'trusted-certs': '../ca-bundle.crt',
        'user-certs-dir': '.'
    }
    return config['webapp']


class mockLogger:
    """
    Naive mock logger class that currently handles only string input
    """
    def __init__(self):
        self.log = []

    def debug(self, s):
        self.log.append('DEBUG '+ str(s))

    def info(self, s):
        self.log.append('INFO '+ str(s))

    def warning(self, s):
        self.log.append('WARNING ' + str(s))

    def error(self, s):
       self.log.append('ERROR' + str(s))

    def contains(self, txt):
        """
        Search all lines logged for any occurrence of txt
        """
        for i in self.log:
            if txt in i:
                return True
        return False

# DKIM key missing
def test_readSMIMEsig_no_DKIM():
    l = mockLogger()
    eml_bytes = get_email_bytes('signed-from-bob-no-dkim.eml')
    cfg = mockConfig()
    read_smime_email(eml_bytes, cfg, l)
    assert l.contains('DKIM FAIL')


# DKIM invalid
def test_readSMIMEsig_bad_DKIM():
    l = mockLogger()
    eml_bytes = get_email_bytes('signed-from-bob-bad-dkim.eml')
    cfg = mockConfig()
    read_smime_email(eml_bytes, cfg, l)
    assert l.contains('DKIM FAIL')

# DKIM valid, with attachment that looks like a signature but is just plaintext
def test_readSMIMEsig_not_real_sig():
    l = mockLogger()
    eml_bytes = get_email_bytes('from-bob-attachment-not-sig.eml')
    cfg = mockConfig()
    read_smime_email(eml_bytes, cfg, l)
    assert l.contains('DKIM passed')
    assert not l.contains('written file')


# DKIM valid and with a signature file that's been corrupted in one byte
def test_readSMIMEsig_corrupt_sig():
    l = mockLogger()
    eml_bytes = get_email_bytes('from-bob-corrupt-signature.eml')
    cfg = mockConfig()
    read_smime_email(eml_bytes, cfg, l)
    assert l.contains('DKIM passed')
    assert l.contains('verifying intermediate certificates')
    assert l.contains('unable to get local issuer certificate')
    assert not l.contains('written file')


# DKIM valid and valid signature
def test_readSMIMEsig_valid():
    l = mockLogger()
    eml_bytes = get_email_bytes('signed-from-bob.eml')
    cfg = mockConfig()
    read_smime_email(eml_bytes, cfg, l)
    assert l.contains('DKIM passed')
    assert l.contains('user certificate passed')
    assert l.contains('written file')


# Stub test code when running directly rather than via pytest
if __name__ == "__main__":
    test_readSMIMEsig_no_DKIM()
    test_readSMIMEsig_bad_DKIM()
    test_readSMIMEsig_not_real_sig()
    test_readSMIMEsig_corrupt_sig()
    test_readSMIMEsig_valid()