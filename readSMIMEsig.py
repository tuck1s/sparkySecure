#!/usr/bin/env python3
from __future__ import print_function
import email, os, sys, argparse, logging, logging.handlers, dkim
from OpenSSL import crypto
from cryptography.hazmat.primitives import serialization
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
    :param payload: bytes
    :return: list of Cert

    Extract public certificates from the PKCS7 binary payload.
    Returns a list of Cert objects, and a flag indicating if time-ranges are valid
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
    :param certList: list of Cert
    :param fromAddr: str
    :return: bool

    Very basic check each of the supplied list of certificates as follows:
        - list is non-empty
        - email_signer (if present) matches fromAddr
        - cert time validity against time now
    Does NOT walk the cert chain - still an open issue on: https://github.com/pyca/cryptography/issues/2381
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


def writeCertList(certList, fromFile, logger):
    """
    :param certList: list of Cert
    :param fromFile: str
    :param logger: logger
    :return: bool

    Write the supplied list of certificates to a text file in current dir, named accordingly
    i.e. **fromAddr**.crt
    """
    try:
        with open(fromFile, 'w') as fp:
            for c in certList:
                fp.write(c.pem)
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
        logger.warning('from={},DKIM FAIL'.format(fromAddr))
    else:
        logger.info('from={},DKIM passed'.format(fromAddr))
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
                            cert_list = extract_smime_signature(payload)
                            logger.info('| type={},subtype={},filename={},bytes={},certs={}'.format(type, subtype, fname, len(payload), len(cert_list)))
                            for c in cert_list:
                                logger.info('| email_signer={},not_valid_before={},not_valid_after={},algorithm={},pem bytes={},issuer={}'.format(c.email_signer, c.startT, c.endT, c.algorithm, len(c.pem), c.issuer))
                            ok = checkCertList(cert_list, fromAddr)
                            logger.info('| basic checks pass={}'.format(ok))
                            fromFile = fromAddr + '.crt'
                            ok = writeCertList(cert_list, fromFile , logger)
                            logger.info('| written file {}={}'.format(fromFile, ok))

                elif part.get_content_subtype() == 'pkcs7-mime':
                    # EnvelopedData / SignedData - not currently supported
                    logger.warning('from={},type={},subtype={},content-description={} : ignored'.format(fromAddr, full_type, subtype, content_desc))
                else:
                    logger.warning('from={},type={},subtype={},content-description={} : ignored'.format(fromAddr, full_type, subtype, content_desc))


# -----------------------------------------------------------------------------------------
# Main code
# -----------------------------------------------------------------------------------------
if __name__ == '__main__':
    parser = argparse.ArgumentParser(description='read an S/MIME signature from a .eml file')
    parser.add_argument('emlfile', type=str, help='filename to read (in RFC822 format)')
    logger = createLogger()
    args = parser.parse_args()
    if os.path.isfile(args.emlfile):
        with open(args.emlfile, 'rb') as fp:
            eml_bytes = fp.read()
            read_smime_email(eml_bytes, logger)
    else:
        print('Unable to open file', args.emlfile, '- stopping')
        exit(1)
