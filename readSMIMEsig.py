#!/usr/bin/env python3
from __future__ import print_function
import email, os, sys, argparse, logging, logging.handlers, dkim
from OpenSSL import crypto
from cryptography.x509 import NameOID
from cryptography.hazmat.primitives import serialization
import pem

from datetime import datetime
from email.utils import parseaddr

def baseProgName():
    return os.path.basename(sys.argv[0])


def createLogger(logfile):
    """
    :return: logger

    Create a logger. Rotates at midnight (as per the machine's locale)
    """
    logfileBackupCount = 10                     # default to 10 files
    logger = logging.getLogger()
    logger.setLevel(logging.INFO)
    fh = logging.handlers.TimedRotatingFileHandler(logfile, when='midnight', backupCount=logfileBackupCount)
    formatter = logging.Formatter('%(asctime)s,%(name)s,%(levelname)s,%(message)s')
    fh.setFormatter(formatter)
    logger.addHandler(fh)
    return logger


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


def get_certificates(p7_data):
    """
    :param p7_data: bytes
    :return: tuple of OpenSSL.crypto.X509 objects

    Returns all certificates for the PKCS7 structure, if present. Only
    objects of type ``signedData`` or ``signedAndEnvelopedData`` can embed
    certificates.

    See:
      https://stackoverflow.com/questions/16899247/how-can-i-decode-a-ssl-certificate-using-python
      https://www.programcreek.com/python/example/64094/OpenSSL.crypto.dump_certificate
      https://github.com/pyca/pyopenssl/pull/367/files#r67300900
    """
    certs = crypto._ffi.NULL
    if p7_data.type_is_signed():
        certs = p7_data._pkcs7.d.sign.cert
    elif p7_data.type_is_signedAndEnveloped():
        certs = p7_data._pkcs7.d.signed_and_enveloped.cert

    pycerts = []
    for i in range(crypto._lib.sk_X509_num(certs)):
        pycert = crypto.X509.__new__(crypto.X509)
        pycert._x509 = crypto._lib.sk_X509_value(certs, i)
        pycerts.append(pycert)

    if not pycerts:
        return None
    return tuple(pycerts)


def verify_certificate_chain(certificate, intermediate, trusted_certs):
    """
    Verify that the certificate is valid, according to the list of trusted_certs.

    Certificate to examine, and the trusted chain are passed as objects, not as file handles.
    Based on https://gist.github.com/uilianries/0459f59287bd63e49b1b8ef03b30d421#file-cert-check-py

    :param certificate: OpenSSL.crypto.X509
    :param trusted_certs: list of OpenSSL.crypto.X509
    :return: bool
    """
    try:
        #Create a certificate store and add your trusted certs
        store = crypto.X509Store()
        for tc in trusted_certs:
            store.add_cert(tc)

        # Create a certificate context using the store and the intermediate certificate
        store_ctx = crypto.X509StoreContext(store, intermediate)
        store_ctx.verify_certificate()

        # Intermediate verified - so add the intermediate to the store
        store.add_cert(crypto.X509.from_cryptography(intermediate))

        # Validate certificate against (trusted + intermediate)
        store_ctx = crypto.X509StoreContext(store, certificate)
        # Verify the certificate, returns None if it can validate the certificate
        store_ctx.verify_certificate()
        return True

    except crypto.X509StoreContextError as e:
        print(e)
        return False


def get_trusted_certs(fname):
    """
    Reads a list of trusted certs from the provided file

    :param fname: filename to read
    :return: list of OpenSSL.crypto.X509
    """

    trustedList = pem.parse_file(fname)
    x509_list = []
    for t in trustedList:
        x509_list.append(crypto.load_certificate(crypto.FILETYPE_PEM, t.as_bytes()))
    return x509_list


def extract_smime_signature(payload):
    """
    :param payload: bytes
    :return: list of Cert

    Extract public certificates from the PKCS7 binary payload.
    Returns a list of Cert objects, and a flag indicating if time-ranges are valid
    """
    pkcs7 = crypto.load_pkcs7_data(crypto.FILETYPE_ASN1, payload)
    certs = get_certificates(pkcs7)

    cert, intermediate = None, None
    # Collect the following info from the certificates
    for c in certs:
        # Convert to the modern & easier to use https://cryptography.io library objects
        c2 = crypto.X509.to_cryptography(c)
        s2 = c2.subject.get_attributes_for_oid(NameOID.EMAIL_ADDRESS)
        if s2:
            cert = c2
        else:
            intermediate = c2

    trusted = get_trusted_certs('ca-bundle.crt')
    ok = verify_certificate_chain(cert, intermediate, trusted)
    if ok:
        #TODO: change this so we don't need homegrown "Cert" type
        c3 = Cert()
        c3.startT = cert.not_valid_before
        c3.endT = cert.not_valid_after

        # get Issuer, unpacking the ASN.1 structure into a dict
        for i in cert.issuer.rdns:
            for j in i:
                c3.issuer[j.oid._name] = j.value

        # get email address from the cert "subject". There should be only one email address.
        s2 = cert.subject.get_attributes_for_oid(NameOID.EMAIL_ADDRESS)
        if len(s2) == 1:
            c3.email_signer = s2[0].value

        # Get hash alg - just for interest
        c3.algorithm = cert.signature_hash_algorithm.name
        c3.pem = cert.public_bytes(serialization.Encoding.PEM).decode('utf8')
        return c3
    else:
        return None


def checkCert(cert, fromAddr):
    """
    :param cert: Cert
    :param fromAddr: str
    :return: bool

    Very basic check of the supplied certificate as follows:
        - email_signer (if present) matches fromAddr
        - cert time validity against time now
    Does NOT walk the cert chain - still an open issue on: https://github.com/pyca/cryptography/issues/2381
    """

    # Check time validity
    now = datetime.utcnow()
    all_cert_times_valid = (cert.startT <= now) and (now <= cert.endT)
    # Check signer matches fromAddr
    from_valid = cert.email_signer == fromAddr
    return all_cert_times_valid and from_valid


def writeCert(cert, fromFile, logger):
    """
    :param cert: Cert
    :param fromFile: str
    :param logger: logger
    :return: bool

    Write the supplied list of certificates to a text file in current dir, named accordingly
    i.e. **fromAddr**.crt
    """
    try:
        with open(fromFile, 'w') as fp:
            fp.write(cert.pem)
        return True

    except Exception as e:
        logger.error(e)
        return False


def check_dkim(msg_bytes, fromAddr, logger):
    """
    :param msg_bytes: bytes
    :param fromAddr: str
    :param logger: logger
    :return: bool

    Validate the message (passed as a byte sequence, as that's what the dkimpy library wants)
    """
    d = dkim.DKIM(msg_bytes, logger=logger)
    valid_dkim = d.verify()
    _, fromDomain = fromAddr.split('@')
    matching_from = d.domain.decode('utf8') == fromDomain
    return valid_dkim and matching_from

def read_smime_email(eml_bytes, logger):
    """
    :param eml_bytes: bytes
    :param logger: logger

    Checks DKIM validity - only accept messages that pass
    Reads S/MIME signature from the email , and extracts the sender's public key (certificates)
    """
    eml = email.message_from_bytes(eml_bytes)
    _, fromAddr = parseaddr(eml.get('From'))

    # Check message passes DKIM checks. Otherwise we can't trust the From: field
    dkim_ok = check_dkim(eml_bytes, fromAddr, logger)
    if not dkim_ok:
        logger.warning('| from={},DKIM FAIL'.format(fromAddr))
    else:
        logger.info('| from={},DKIM passed'.format(fromAddr))
        for part in eml.walk():
            full_type = part['Content-Type']
            content_desc = part['Content-Description']
            if part.get_content_maintype() == 'application':
                subtype = part.get_content_subtype()
                if subtype == 'pkcs7-signature':
                    if part.get_content_disposition() == 'attachment':
                        fname = part.get_filename()
                        if fname == 'smime.p7s':
                            # standalone signature
                            payload = part.get_payload(decode=True)
                            mailcert = extract_smime_signature(payload)
                            logger.info('| content-type={},content-description={},filename={},bytes={}'.format(full_type, content_desc, fname, len(payload) ))
                            logger.info('| email_signer={},not_valid_before={},not_valid_after={},algorithm={},pem bytes={},issuer={}'.format(
                                mailcert.email_signer, mailcert.startT, mailcert.endT, mailcert.algorithm, len(mailcert.pem), mailcert.issuer))
                            ok = checkCert(mailcert, fromAddr)
                            logger.info('| basic checks pass={}'.format(ok))
                            fromFile = fromAddr + '.crt'
                            ok = writeCert(mailcert, fromFile, logger)
                            logger.info('| written file {}={}'.format(fromFile, ok))

                elif part.get_content_subtype() == 'pkcs7-mime':
                    # EnvelopedData / SignedData - not currently supported
                    logger.warning('from={},type={},subtype={},content-description={} : ignored'.format(fromAddr, full_type, subtype, content_desc))
                else:
                    logger.warning('from={},type={},subtype={},content-description={} : ignored'.format(fromAddr, full_type, subtype, content_desc))


# -----------------------------------------------------------------------------------------
# Main code - used only for development. webapp.py will call read_smime_email directly.
# -----------------------------------------------------------------------------------------
if __name__ == '__main__':
    parser = argparse.ArgumentParser(description='read an S/MIME signature from a .eml file')
    parser.add_argument('emlfile', type=str, help='filename to read (in RFC822 format)')
    logger = createLogger('readSMIMEsig.log')
    args = parser.parse_args()
    if os.path.isfile(args.emlfile):
        with open(args.emlfile, 'rb') as fp:
            eml_bytes = fp.read()
            read_smime_email(eml_bytes, logger)
    else:
        print('Unable to open file', args.emlfile, '- stopping')
        exit(1)
