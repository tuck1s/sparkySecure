#!/usr/bin/env python3
from __future__ import print_function
import email, os, sys, argparse, logging, logging.handlers, dkim, pem
from email.utils import parseaddr

from OpenSSL import crypto
from cryptography.x509 import NameOID
from cryptography.hazmat.primitives import serialization

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


def verify_certificate_chain(certificate, intermediates, trusted_certs):
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

        # Create a certificate context using the store, to check any intermediate certificates
        for i in intermediates:
            store_ctx = crypto.X509StoreContext(store, i)
            store_ctx.verify_certificate()
            # no exception, so Intermediate verified - add the intermediate to the store
            store.add_cert(crypto.X509.from_cryptography(i))

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


def extract_smime_signature(payload, logger):
    """
    :param payload: bytes
    :return: list of Cert

    Extract public certificates from the PKCS7 binary payload.
    Returns a list of Cert objects, and a flag indicating if time-ranges are valid
    """
    pkcs7 = crypto.load_pkcs7_data(crypto.FILETYPE_ASN1, payload)
    certs = get_certificates(pkcs7)

    cert, intermediates = None, []
    # Collect the following info from the certificates
    for c in certs:
        # Convert to the modern & easier to use https://cryptography.io library objects
        c2 = crypto.X509.to_cryptography(c)

        # Log some human-readable info about each cert
        c2_email_addrs = []
        c2_issuer_info = {}
        for i in c2.subject.get_attributes_for_oid(NameOID.EMAIL_ADDRESS):
            c2_email_addrs.append(i.value)
        for i in c2.issuer:
            c2_issuer_info.update( {i.oid._name: i.value} )
        logger.info(
            '| Certificate: subject email_address={},not_valid_before={},not_valid_after={},hash_algorithm={},key_size={} bytes, issuer={}'.format(
                c2_email_addrs,
                c2.not_valid_before,
                c2.not_valid_after,
                c2.signature_hash_algorithm.name,
                c2.public_key().key_size,
                c2_issuer_info
            ))

        # Check if this is an email user certificate, or an intermediate
        if c2_email_addrs:
            cert = c2
        else:
            intermediates.append(c2)

    trusted = get_trusted_certs('ca-bundle.crt')
    if verify_certificate_chain(cert, intermediates, trusted):
        pem_bytes = cert.public_bytes(serialization.Encoding.PEM)
        return pem_bytes
    else:
        return None


def writeCert(pem_bytes, fromFile, logger):
    """
    Write the received public cert in PEM format to the local file. Return status indicates success.

    :param pem_bytes: array of bytes
    :param fromFile: str
    :param logger: logger
    :return: bool
    """
    try:
        with open(fromFile, 'wb') as fp:
            fp.write(pem_bytes)
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
            logger.info('| content-type={},content-description={}'.format(full_type, content_desc))

            if part.get_content_maintype() == 'application':
                subtype = part.get_content_subtype()
                if subtype == 'pkcs7-signature':
                    if part.get_content_disposition() == 'attachment':
                        fname = part.get_filename()
                        payload = part.get_payload(decode=True)
                        logger.info('| filename={},bytes={}'.format(fname, len(payload)))

                        if fname == 'smime.p7s':
                            # standalone signature
                            user_pem = extract_smime_signature(payload, logger)
                            if user_pem:
                                fromFile = fromAddr + '.crt'
                                ok = writeCert(user_pem, fromFile, logger)
                                logger.info('| written file {},bytes={},ok={}'.format(fromFile, len(user_pem), ok))

                elif part.get_content_subtype() == 'pkcs7-mime':
                    # EnvelopedData / SignedData - not currently supported
                    logger.warning('| Currently not implemented - ignored')
                else:
                    logger.warning('| Unknown subtype - ignored')


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
