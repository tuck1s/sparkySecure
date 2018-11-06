# test sparkpostSMIME functions

import email
from sparkpostSMIME import buildSMIMEemail, sendSparkPost

example_email1 = '''To: Bob <bob@example.com>
From: Alice <alice@example.com>
Subject: A message
MIME-Version: 1.0
Content-Type: text/plain; charset=utf-8; format=flowed
Content-Transfer-Encoding: 7bit\nContent-Language: en-GB

When in the Course of human events we send an email
'''

def delivery_headers_match(m1, m2):
    for i in ['To', 'From', 'Subject', 'MIME-Version']:
        if m1.get(i) != m2.get(i):
            return False
    return True


def test_plain_unsigned():
    msgIn = email.message_from_string(example_email1)
    msgOut = buildSMIMEemail(msgIn, encrypt=False, sign=False)
    assert delivery_headers_match(msgIn, msgOut)

"""
def test_plain_signed():
    msgIn = email.message_from_string(example_email1)
    msgOut = buildSMIMEemail(msgIn, encrypt=False, sign=True)
    assert delivery_headers_match(msgIn, msgOut)


def test_encrypted_unsigned():
    msgIn = email.message_from_string(example_email1)
    msgOut = buildSMIMEemail(msgIn, encrypt=True, sign=False)
    assert delivery_headers_match(msgIn, msgOut)


def test_encrypted_signed():
    msgIn = email.message_from_string(example_email1)
    msgOut = buildSMIMEemail(msgIn, encrypt=True, sign=True)
    assert delivery_headers_match(msgIn, msgOut)
"""

# Stub test code when running directly rather than via py.test
if __name__ == "__main__":
    test_plain_unsigned()
    test_plain_signed()
    test_encrypted_unsigned()
    test_encrypted_signed()