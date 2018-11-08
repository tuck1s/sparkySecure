# test sparkpostSMIME functions

import email
from argparse import Namespace
from sparkpostSMIME import do_smime

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


def run_testcase(args):
    with open(args.emlfile) as f:
        msgIn = email.message_from_file(f)
    msgOut = do_smime(args)
    assert msgOut is not None
    assert delivery_headers_match(msgIn, msgOut)
    if args.encrypt or args.sign:
        assert content_headers_are_smime(msgOut)


# Exercise the code by simulating the combinations of command-line flags
def test_smime_combinations():
    for s in [False, True]:
        for e in [False, True]:
            args = Namespace(emlfile='example_email1.eml', encrypt=e, sign=s, send_api=False)
            run_testcase(args)


# Stub test code when running directly rather than via pytest
if __name__ == "__main__":
    test_smime_combinations()