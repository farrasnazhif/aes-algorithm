from aes import AES128


def main():
    key = bytes.fromhex('00000000000000000000000000000000')
    plain = bytes.fromhex('80000000000000000000000000000000')
    expected = '3ad78e726c1ec02b7ebfe92b23d9ec34'
    aes = AES128(key)

    if((aes.encrypt_block(plain).hex() == expected) and 
    (aes.decrypt_block(bytes.fromhex(expected)) == plain) and 
    (aes.crypt_ctr(aes.crypt_ctr(b'hello world', b'12345678'), b'12345678') == b'hello world')):
        print('AES-128 NIST known-answer test: PASS')
    else:
        print('AES-128 NIST known-answer test: FAILED')


if __name__ == '__main__':
    main()

