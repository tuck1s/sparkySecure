# examples from http://proj.badc.rl.ac.uk/svn/ndg-security/branches/Dependencies/m2crypto/doc/howto.smime.html

from M2Crypto import BIO, Rand, SMIME, X509

def makebuf(text):
    return BIO.MemoryBuffer(text)


def signRecip():
    # examples from http://proj.badc.rl.ac.uk/svn/ndg-security/branches/Dependencies/m2crypto/doc/howto.smime.html
    # See also https://stackoverflow.com/questions/40849024/python-using-m2crypto-signing-a-message-with-s-mime
    # Make a MemoryBuffer of the message.
    buf = BIO.MemoryBuffer('This is an email signature'.encode('utf8'))

    # Seed the PRNG.
    Rand.load_file('randpool.dat', -1)

    # Instantiate an SMIME object.
    s = SMIME.SMIME()

    s.load_key('steve@thetucks.com_private.pem', 'steve@thetucks.com.crt')
    p7 = s.sign(buf, SMIME.PKCS7_DETACHED)

    # Dump out to a memory buffer
    out = BIO.MemoryBuffer()
    s.write(out, p7, buf)

    # Save the PRNG's state.
    Rand.save_file('randpool.dat')

    outBytes = out.read()
    outStr = outBytes.decode('ascii')
    return outStr


#------------
# Make a MemoryBuffer of the message.
buf = makebuf(b'a sign of our times')

# Seed the PRNG.
Rand.load_file('randpool.dat', -1)

# Instantiate an SMIME object.
s = SMIME.SMIME()

s.load_key('steve@thetucks.com_private.pem', 'steve@thetucks.com.crt')
p7 = s.sign(buf)

"""
# Load target cert to encrypt to.
x509 = X509.load_cert('boblumreeker@gmailcom.crt')
sk = X509.X509_Stack()
sk.push(x509)
s.set_x509_stack(sk)

# Set cipher
s.set_cipher(SMIME.Cipher('aes_256_cbc'))
#s.set_cipher(SMIME.Cipher('des_ede3_cbc'))

# Encrypt the buffer.
p7 = s.encrypt(buf)
"""

# Dump out to a memory buffer
out = BIO.MemoryBuffer()
s.write(out, p7)

outBytes = out.read()
print(outBytes.decode('ascii'))


