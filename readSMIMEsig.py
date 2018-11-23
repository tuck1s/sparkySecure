#!/usr/bin/env python3
from __future__ import print_function
import email, os, argparse
from OpenSSL import crypto
from cryptography.hazmat.primitives import serialization
from datetime import datetime
from email.utils import parseaddr

def get_certificates(self):
    """
    https://github.com/pyca/pyopenssl/pull/367/files#r67300900

    Returns all certificates for the PKCS7 structure, if present. Only
    objects of type ``signedData`` or ``signedAndEnvelopedData`` can embed
    certificates.

    :return: The certificates in the PKCS7, or :const:`None` if
        there are none.
    :rtype: :class:`tuple` of :class:`X509` or :const:`None`
    """
    certs = crypto._ffi.NULL
    if self.type_is_signed():
        certs = self._pkcs7.d.sign.cert
    elif self.type_is_signedAndEnveloped():
        certs = self._pkcs7.d.signed_and_enveloped.cert

    pycerts = []
    for i in range(crypto._lib.sk_X509_num(certs)):
        pycert = crypto.X509.__new__(crypto.X509)
        pycert._x509 = crypto._lib.sk_X509_value(certs, i)
        pycerts.append(pycert)

    if not pycerts:
        return None
    return tuple(pycerts)

class Cert(object):
    """
    Convenient container object for human-readable and output-file friendly certificate contents
    """
    pem = ''
    email_signer = None
    startT = None
    endT = None
    issuer = {}
    algorithm = None


def extract_smime_signature(payload):
    """
    Extract public certificates from the PKCS7 binary payload.
    Returns a list of Cert objects, and a flag indicating if time-ranges are valid

    :param payload: bytes
    :return: certList: list of Cert, all_cert_times_valid
    """
    pkcs7 = crypto.load_pkcs7_data(crypto.FILETYPE_ASN1, payload)
    certs = get_certificates(pkcs7)
    certList = []
    # Collect the following info from the certificates
    for c in certs:
        # Convert to the modern & easier to use https://cryptography.io library objects
        c2 = crypto.X509.to_cryptography(c)
        c3 = Cert()

        # check each certificate's time validity, ANDing cumulatively across each one
        c3.startT = c2.not_valid_before
        c3.endT = c2.not_valid_after

        # get Issuer, unpacking the ASN.1 structure into a dict
        for i in c2.issuer.rdns:
            for j in i:
                c3.issuer[j.oid._name] = j.value

        # get email address from the cert "subject"
        for i in c2.subject.rdns:
            for j in i:
                attrName = j.oid._name
                if attrName == 'emailAddress':
                    c3.email_signer = j.value

        # Get hash alg - just for interest
        c3.algorithm = c2.signature_hash_algorithm.name
        c3.pem = c2.public_bytes(serialization.Encoding.PEM).decode('utf8')
        certList.append(c3)
    return certList


def checkCertList(certList, fromAddr):
    """
    Very basic check each of the supplied list of certificates as follows:
        - list is non-empty
        - email_signer (if present) matches fromAddr
        - cert time validity against time now

    Does NOT walk the cert chain - still an open issue on: https://github.com/pyca/cryptography/issues/2381

    TODO: should also check DKIM / SPF as not currently checked by inbound relay webhooks
    """
    if len(certList) > 0:
        all_cert_times_valid = True
        from_valid = True
        for c in certList:
            # Check time validity
            now = datetime.utcnow()
            all_cert_times_valid = all_cert_times_valid and (c.startT <= now) and (now <= c.endT)
            # Check signer matches fromAddr
            if c.email_signer:
                from_valid = from_valid and (c.email_signer == fromAddr)

        return all_cert_times_valid and from_valid
    else:
        return False


def writeCertList(certList, fromAddr):
    """
    Write the supplied list of certificates to a text file, named for the fromAddr
    i.e. <fromAddr>.crt

    :param certList: list of Cert, fromAddr
    """

    crtFileName = fromAddr + '.crt'
    try:
        with open(crtFileName, 'w') as fp:
            for c in certList:
                fp.write(c.pem)
        return True

    except Exception as e:
        # TODO: log error
        return False


def read_smime_email(args):
    """
    Reads S/MIME signature from the email file specified in args, and extracts the sender's public key (certificates)

    :param args: Namespace

    Thanks to:
      https://stackoverflow.com/questions/16899247/how-can-i-decode-a-ssl-certificate-using-python
      https://www.programcreek.com/python/example/64094/OpenSSL.crypto.dump_certificate
    """
    if os.path.isfile(args.emlfile):
        with open(args.emlfile) as fp:
            eml = email.message_from_file(fp)
            for part in eml.walk():
                if part.get_content_maintype() == 'application':
                    if part.get_content_subtype() == 'pkcs7-signature':
                        if part.get_content_disposition() == 'attachment':
                            fname = part.get_filename()
                            if fname == 'smime.p7s':
                                payload = part.get_payload(decode=True)
                                print('Signature: {}, {} bytes'.format(fname, len(payload)))
                                cert_list = extract_smime_signature(payload)
                                _, fromAddr = parseaddr(eml.get('From'))
                                if checkCertList(cert_list, fromAddr):
                                    ok = writeCertList(cert_list, fromAddr)


    else:
        print('Unable to open file', args.emlfile, '- stopping')
        exit(1)


# -----------------------------------------------------------------------------------------
# Main code
# -----------------------------------------------------------------------------------------
if __name__ == "__main__":
    parser = argparse.ArgumentParser(description='read an S/MIME signature from a .eml file')
    parser.add_argument('emlfile', type=str, help='filename to read (in RFC822 format)')
    args = parser.parse_args()
    print(read_smime_email(args))