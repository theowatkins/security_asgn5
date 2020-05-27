import os
from Crypto.Cipher import AES
from Crypto.Util import Padding

def encrypt_file(filename):

    # open and read given bmp file
    with open(filename, 'rb') as f:
        data = bytearray(f.read())

    # preserve bmp header in output
    cbc_out = data[:54]
    ebc_out = data[:54]

    # remove bmp header 
    data = data[54:]

    # pad data to length divisible by 128
    data = Padding.pad(data, 128, style='pkcs7')

    # generate random key and initialization vector (for CBC)
    key = os.urandom(16)
    iv = os.urandom(16)

    # create new cbc and ebc cipher objects
    cbc = AES.new(key, AES.MODE_CBC, iv)
    ebc = AES.new(key, AES.MODE_ECB)

    # encrypt data
    cbc_encrypted = cbc.encrypt(data)
    ebc_encrypted = ebc.encrypt(data)

    # append encrypted data to bmp headers
    for b in cbc_encrypted:
        cbc_out.append(b)

    for b in ebc_encrypted:
        ebc_out.append(b)

    # write encrypted data to output files
    with open('cbc.bmp', 'wb') as o:
        o.write((''.join(chr(x) for x in cbc_out)).encode('charmap'))

    with open('ebc.bmp', 'wb') as o:
        o.write((''.join(chr(x) for x in ebc_out)).encode('charmap'))

