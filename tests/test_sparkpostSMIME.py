# test sparkpostSMIME functions

import email, os
from sparkpostSMIME import buildSMIMEemail

def example_mail():
    # look for example email file in same dir as this script
    testdir = os.path.dirname(os.path.abspath(__file__))
    fname = os.path.join(testdir, 'example_email1.eml')
    with open(fname, 'r') as f:
        return email.message_from_file(f)


def delivery_headers_match(m1, m2):
    for i in ['To', 'From', 'Subject', 'MIME-Version']:
        if m1.get(i) != m2.get(i):
            return False
    return True


def content_headers_are_smime(msgOut):
    # also allow 'x-pkcs7-mime'
    return 'pkcs7-mime' in msgOut.get_content_type() and \
        msgOut.get_content_disposition() == 'attachment' and \
        msgOut.get_filename() == 'smime.p7m'


def test_plain_unsigned():
    msgIn = example_mail()
    msgOut = buildSMIMEemail(msgIn, encrypt=False, sign=False)
    assert msgOut is not None
    assert delivery_headers_match(msgIn, msgOut)


def test_plain_signed():
    msgIn = example_mail()
    msgOut = buildSMIMEemail(msgIn, encrypt=False, sign=True)
    assert msgOut is not None
    assert delivery_headers_match(msgIn, msgOut)
    assert content_headers_are_smime(msgOut)


def test_encrypted_unsigned():
    msgIn = example_mail()
    msgOut = buildSMIMEemail(msgIn, encrypt=True, sign=False)
    assert msgOut is not None
    assert delivery_headers_match(msgIn, msgOut)
    assert content_headers_are_smime(msgOut)


def test_encrypted_signed():
    msgIn = example_mail()
    msgOut = buildSMIMEemail(msgIn, encrypt=True, sign=True)
    assert msgOut is not None
    assert delivery_headers_match(msgIn, msgOut)
    assert content_headers_are_smime(msgOut)


# Stub test code when running directly rather than via pytest
if __name__ == "__main__":
    test_plain_unsigned()
    test_plain_signed()
    test_encrypted_unsigned()
    test_encrypted_signed()