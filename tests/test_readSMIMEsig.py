# test readSMIMEsig functions

import email
from argparse import Namespace


def test_readSMIMEsig():
    # DKIM key missing
    # DKIM valid but no signature
    # DKIM valid and valid signature
    pass

# Stub test code when running directly rather than via pytest
if __name__ == "__main__":
    test_readSMIMEsig()