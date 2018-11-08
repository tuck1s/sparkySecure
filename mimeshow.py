#!/usr/bin/env python3
from __future__ import print_function
import email, argparse, sys

def xstr(s):
    return str(s) if s else ''

def print_part(m, depth):
    pad = '  ' * depth
    for i in m.items():
        hname, hcontent = i
        hcontent = hcontent.replace('\n', '')           # print all on one line for ease of reading
        print('{}{} {}'.format(pad, xstr(hname), xstr(hcontent)))
    print()

def showPart(m, depth=0):
    print_part(m, depth)
    if m.is_multipart():
        for p in m.get_payload():
            showPart(p, depth + 1)

# -----------------------------------------------------------------------------
# Main code
# -----------------------------------------------------------------------------
if __name__ == "__main__":
    parser = argparse.ArgumentParser(description='Display internal header and MIME structure of a mail file in RFC822 format, indented for ease of reading')
    parser.add_argument('file', type=str, nargs='?', default=None, help='filename to read. If file is absent, reads from the standard input (acts as a filter).')
    args = parser.parse_args()

    if args.file:
        with open(args.file) as f:
            msgIn = email.message_from_file(f)
    else:
        msgIn = email.message_from_file(sys.stdin)
    showPart(msgIn)

