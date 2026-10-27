import json
import secrets
import threading
from common import ascii_key, connect, open_seal, recv, seal, send, show


def receive_chat(conn, ks):
    while True:
        try:
            message = recv(conn)
            if message.get('type') != 'chat':
                continue
            print('\n[Bob ciphertext hex]', message['packet']['ciphertext'])
            print('[Bob plaintext]', open_seal(ks, message['packet']).decode('ascii'))
        except (ConnectionError, OSError):
            print('\nBob disconnected')
            return
        except Exception as exc:
            print('Invalid message:', exc)


def main():
    ka = ascii_key(input('Alice-KDC key Ka (16 ASCII): '))
    n1 = secrets.token_hex(16)
    with connect('alice_kdc') as kdc:
        send(kdc, {'type': 'request', 'alice': 'Alice', 'bob': 'Bob', 'n1': n1})
        print('(1) KDC request sent, N1:', n1)
        reply = recv(kdc)
    data = json.loads(open_seal(ka, reply['payload']).decode('ascii'))
    if reply.get('type') != 'kdc_reply' or data['n1'] != n1 or data['bob'] != 'Bob':
        raise ValueError('Invalid KDC reply')
    ks = bytes.fromhex(data['ks'])
    print('(2) KDC reply decrypted, N1 verified')
    show('KDC response', reply['payload'])
    with connect('alice_bob') as bob:
        send(bob, {'type': 'ticket', 'ticket': data['ticket']})
        print('(3) Ticket forwarded to Bob')
        challenge = recv(bob)
        n2 = open_seal(ks, challenge['packet']).decode('ascii')
        print('(4) Bob challenge decrypted')
        proof = seal(ks, n2[::-1].encode('ascii'))
        send(bob, {'type': 'proof', 'packet': proof})
        print('(5) Challenge response sent')
        show('Alice proof', proof)
        if recv(bob).get('type') != 'ready':
            raise ValueError('Bob did not accept authentication')
        print('AES chat enabled; type ASCII messages')
        threading.Thread(target=receive_chat, args=(bob, ks), daemon=True).start()
        while True:
            line = input('Alice> ')
            packet = seal(ks, line.encode('ascii'))
            send(bob, {'type': 'chat', 'packet': packet})
            show('Alice', packet)


if __name__ == '__main__':
    main()
