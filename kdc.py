import json
import secrets
from common import BROKER, PORT, ascii_key, connect, recv, seal, send, show


def main():
    ka = ascii_key(input('Alice-KDC key Ka (16 ASCII): '))
    kb = ascii_key(input('Bob-KDC key Kb (16 ASCII): '))
    with connect('kdc') as conn:
        print(f'KDC connected to MQTT broker {BROKER}:{PORT}')
        while True:
            try:
                req = recv(conn)
                if req.get('type') != 'request' or req.get('alice') != 'Alice' or req.get('bob') != 'Bob':
                    raise ValueError('Unknown principal')
                n1 = req['n1']
                print(f'(1) request from Alice: Alice | Bob | N1={n1}')
                ks = secrets.token_bytes(16)
                ticket = seal(kb, json.dumps({'ks': ks.hex(), 'alice': 'Alice'}).encode('ascii'))
                payload = seal(ka, json.dumps({'ks': ks.hex(), 'bob': 'Bob', 'n1': n1, 'ticket': ticket}).encode('ascii'))
                send(conn, {'type': 'kdc_reply', 'payload': payload})
                print('(2) encrypted response sent; new random session key generated')
                show('KDC to Alice', payload)
                show('Ticket for Bob', ticket)
            except Exception as exc:
                print('Request failed:', exc)


if __name__ == '__main__':
    main()
