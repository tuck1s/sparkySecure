#!/usr/bin/env python3
from __future__ import print_function
import email, os, argparse, logging, logging.handlers, dkim, pem, configparser, cryptography

from email.utils import parseaddr
from OpenSSL import crypto                  # need legacy cert checking functions from here
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.backends import default_backend


def get_trusted_certs(fname):
    """
    :param fname: filename to read
    :return: list of cryptography.x509.Certificate

    Reads a list of trusted certs from the provided file, using the "pem" library to parse the file.
    """
    if os.path.isfile(fname):
        trustedList = pem.parse_file(fname)
        x509_list = []
        for t in trustedList:
            trusted_cert = cryptography.x509.load_pem_x509_certificate(t.as_bytes(), default_backend())
            x509_list.append(trusted_cert)
        return x509_list
    else:
        return None


def createLogger(logfile):
    """
    :param logfile: str
    :return: logger

    Create a logger. Rotates at midnight (as per the machine's locale)
    """
    logfileBackupCount = 10                     # default to 10 files
    logger = logging.getLogger()
    logger.setLevel(logging.INFO)
    if not logger.handlers:                     # avoid adding more than one handler, as it causes duplicate lines in output
        fh = logging.handlers.TimedRotatingFileHandler(logfile, when='midnight', backupCount=logfileBackupCount)
        formatter = logging.Formatter('%(asctime)s,%(name)s,%(levelname)s,%(message)s')
        fh.setFormatter(formatter)
        logger.addHandler(fh)
    return logger


def get_certificates(p7_data):
    """
    :param p7_data: OpenSSL.crypto.PKCS7
    :return: list of cryptography.x509.Certificate

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
        pycerts.append(crypto.X509.to_cryptography(pycert))

    if not pycerts:
        return None
    return pycerts


def verify_certificate_chain(certificate, intermediates, trusted_certs):
    """
    :param certificate: cryptography.x509.Certificate
    :param intermediates: list of cryptography.x509.Certificate
    :param trusted_certs: list of cryptography.x509.Certificate

    Verify that the certificate is valid, according to the list of intermediates and trusted_certs.
    Uses legacy crypto.X509 functions as no current equivalent in https://cryptography.io/en/latest/

    See:
    https://gist.github.com/uilianries/0459f59287bd63e49b1b8ef03b30d421#file-cert-check-py

    :return: bool
    """
    try:
        #Create a certificate store and add your trusted certs
        store = crypto.X509Store()
        for tc in trusted_certs:
            store.add_cert(crypto.X509.from_cryptography(tc))

        # Create a certificate context using the store, to check any intermediate certificates
        for i in intermediates:
            i_X509 = crypto.X509.from_cryptography(i)
            store_ctx = crypto.X509StoreContext(store, i_X509)
            store_ctx.verify_certificate()
            # no exception, so Intermediate verified - add the intermediate to the store
            store.add_cert(i_X509)

        # Validate certificate against (trusted + intermediate)
        store_ctx = crypto.X509StoreContext(store, crypto.X509.from_cryptography(certificate))
        # Verify the certificate, returns None if it can validate the certificate
        store_ctx.verify_certificate()
        return True

    except crypto.X509StoreContextError as e:
        print(e)
        return False


def extract_smime_signature(payload, trusted, logger):
    """
    :param payload: bytes
    :param trusted: list of cryptography.x509.Certificate
    :param logger: logger
    :return: bytes or None

    Extract public certificates from the PKCS7 binary payload. Logs human-readable info about each cert found.
    Identifies which are intermediates and which is the sender's public-key cert.

    Verifies against provided list of trusted certs.
    If valid, returns the PEM-serialized contents of the sender's public-key certificate.
    If invalid, returns None.
    """
    pkcs7 = crypto.load_pkcs7_data(crypto.FILETYPE_ASN1, payload)
    certs = get_certificates(pkcs7)

    cert, intermediates = None, []
    for c in certs:
        # Log some human-readable info about each cert
        c_email_addrs = []
        c_issuer_info = {}
        for i in c.subject.get_attributes_for_oid(cryptography.x509.NameOID.EMAIL_ADDRESS):
            c_email_addrs.append(i.value)
        for i in c.issuer:
            c_issuer_info.update( {i.oid._name: i.value} )
        logger.info(
            '| Certificate: subject email_address={},not_valid_before={},not_valid_after={},hash_algorithm={},key_size={} bytes, issuer={}'.format(
                c_email_addrs, c.not_valid_before, c.not_valid_after, c.signature_hash_algorithm.name,
                c.public_key().key_size, c_issuer_info
            ))

        # Check if this is an email user certificate, or an intermediate
        if c_email_addrs:
            cert = c
        else:
            intermediates.append(c)

    if verify_certificate_chain(cert, intermediates, trusted):
        pem_bytes = cert.public_bytes(serialization.Encoding.PEM)
        return pem_bytes
    else:
        return None


def writeCert(pem_bytes, fromFile, logger):
    """
    Write the received cert (already serialized in pem format) to file fromFile. Return status indicates success.

    :param pem_bytes: bytes
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

    Validate the message (passed as a byte sequence, as that's what the dkimpy library wants).
    """
    d = dkim.DKIM(msg_bytes, logger=logger)
    valid_dkim = d.verify()
    _, fromDomain = fromAddr.split('@')
    matching_from = (d.domain != None) and (d.domain.decode('utf8') == fromDomain)
    return valid_dkim and matching_from


def read_smime_email(eml_bytes, cfg, logger):
    """
    :param eml_bytes: bytes
    :param cfg: configparser.SectionProxy
    :param logger: logger

    Reads S/MIME signature from the email, extracts and validates the sender's public key certificate.
    Expects cfg to supply the name of a ca-bundle.crt type file from the host environment containing trusted certs.

    Mail must also pass DKIM check so that the from address is trustworthy.
    """

    # Prepare to check certificate(s) validity by getting list of trusted certs from host environment
    trusted_certs_file = cfg.get('trusted-certs', '')
    trusted = get_trusted_certs(trusted_certs_file)
    if trusted == None:
        logger.error('Problem loading trusted certificate bundle from file {} - stopping. Check .ini file.'.format(trusted_certs_file))
    else:
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
                                user_pem = extract_smime_signature(payload, trusted, logger)
                                if user_pem:
                                    fromFile = os.path.join(cfg.get('user-certs-dir', '.'), fromAddr + '.crt')
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
    logger = createLogger('webapp.log')

    config = configparser.ConfigParser()
    config.read('webapp.ini')
    cfg = config['webapp']

    args = parser.parse_args()
    if os.path.isfile(args.emlfile):
        with open(args.emlfile, 'rb') as fp:
            eml_bytes = fp.read()
            read_smime_email(eml_bytes, cfg, logger)
    else:
        print('Unable to open file', args.emlfile, '- stopping')
        exit(1)
