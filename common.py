import hashlib
import hmac
import json
import secrets
from aes import AES128

MAX_LINE = 65536

def ascii_key(value):
    raw = value.encode('ascii')
    if len(raw) != 16:
        raise ValueError('Key must contain exactly 16 ASCII characters')
    return raw


def seal(key, data):
    nonce = secrets.token_bytes(8)
    cipher = AES128(key).crypt_ctr(data, nonce)
    mac_key = hashlib.sha256(b'KI-demo-mac-v1' + key).digest()
    tag = hmac.new(mac_key, nonce + cipher, hashlib.sha256).digest()
    return {'nonce': nonce.hex(), 'ciphertext': cipher.hex(), 'tag': tag.hex()}

def send(sock, obj):
    data = (json.dumps(obj, separators=(',', ':')) + '\n').encode('ascii')
    sock.sendall(data)


def recv(sock):
    data = bytearray()
    while True:
        b = sock.recv(1)
        if not b:
            raise ConnectionError('Connection closed')
        if b == b'\n':
            break
        data.extend(b)
        if len(data) > MAX_LINE:
            raise ValueError('Message too large')
    return json.loads(data.decode('ascii'))

def show(label, packet):
    print(f'{label} ciphertext (hex): {packet["ciphertext"]}')