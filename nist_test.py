from aes import AES128


def main():
    key = bytes.fromhex('000102030405060708090a0b0c0d0e0f')
    plain = bytes.fromhex('00112233445566778899aabbccddeeff')
    expected = '69c4e0d86a7b0430d8cdb78070b4c55a'
    aes = AES128(key)

    if((aes.encrypt_block(plain).hex() == expected) and 
    (aes.decrypt_block(bytes.fromhex(expected)) == plain) and 
    (aes.crypt_ctr(aes.crypt_ctr(b'hello world', b'12345678'), b'12345678') == b'hello world')):
        print('AES-128 NIST known-answer test: PASS')
    else:
        print('AES-128 NIST known-answer test: FAILED')


if __name__ == '__main__':
    main()

