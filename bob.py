import argparse
import json
import secrets
import socket
from common import ascii_key, open_seal, recv, seal, send, show


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--host', default='0.0.0.0')
    parser.add_argument('--port', type=int, default=9002)
    args = parser.parse_args()
    kb = ascii_key(input('Bob-KDC key Kb (16 ASCII): '))
    with socket.socket() as server:
        server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        server.bind((args.host, args.port))
        server.listen()
        print(f'Bob listening on {args.host}:{args.port}')
        while True:
            conn, addr = server.accept()
            with conn:
                try:
                    step3 = recv(conn)
                    ticket = json.loads(open_seal(kb, step3['ticket']).decode('ascii'))
                    if step3.get('type') != 'ticket' or ticket['alice'] != 'Alice':
                        raise ValueError('Invalid ticket')
                    ks = bytes.fromhex(ticket['ks'])
                    print('(3) Ticket decrypted, session key received')
                    n2 = secrets.token_hex(16)
                    challenge = seal(ks, n2.encode('ascii'))
                    send(conn, {'type': 'challenge', 'packet': challenge})
                    print('(4) challenge N2 sent')
                    show('Bob challenge', challenge)
                    step5 = recv(conn)
                    answer = open_seal(ks, step5['packet']).decode('ascii')
                    if step5.get('type') != 'proof' or answer != n2[::-1]:
                        raise ValueError('Challenge verification failed')
                    print('(5) Alice authenticated.')
                    send(conn, {'type': 'ready'})
                except (ConnectionError, BrokenPipeError, OSError, EOFError):
                    print('Connection ended; waiting for Alice again')
                except Exception as exc:
                    print('Session failed:', exc)


if __name__ == '__main__':
    main()
