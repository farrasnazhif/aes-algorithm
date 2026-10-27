# NIST Source
# https://csrc.nist.gov/csrc/media/projects/cryptographic-algorithm-validation-program/documents/aes/aesavs.pdf

from aes import AES128


def main():
    key = bytes.fromhex('00000000000000000000000000000000')
    plain = bytes.fromhex('fffffffffffc00000000000000000000')
    expected = '678034dc9e41b5a560ed239eeab1bc78'
    aes = AES128(key)

    if((aes.encrypt_block(plain).hex() == expected) and 
    (aes.decrypt_block(bytes.fromhex(expected)) == plain) and 
    (aes.crypt_ctr(aes.crypt_ctr(b'hello world', b'12345678'), b'12345678') == b'hello world')):
        print('AES-128 NIST known-answer test: PASS')
    else:
        print('AES-128 NIST known-answer test: FAILED')


if __name__ == '__main__':
    main()

