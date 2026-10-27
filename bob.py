import json
import secrets
import threading
from common import BROKER, PORT, ConsoleChat, ascii_key, connect, open_seal, recv, seal, send, show


def receive_chat(conn, ks, chat):
    while True:
        try:
            message = recv(conn)
            if message.get('type') != 'chat':
                continue
            plain = open_seal(ks, message['packet']).decode('ascii')
            chat.display_incoming('Alice', message['packet']['ciphertext'], plain)
        except (ConnectionError, OSError):
            print('\nAlice disconnected')
            return
        except Exception as exc:
            print('Session failed:', exc)


def main():
    kb = ascii_key(input('Bob-KDC key Kb (16 ASCII): '))
    with connect('bob') as conn:
        print(f'Bob connected to MQTT broker {BROKER}:{PORT}')
        while True:
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
                print('(5) Alice authenticated. AES chat enabled.')
                send(conn, {'type': 'ready'})
                chat = ConsoleChat('Bob> ')
                threading.Thread(target=receive_chat, args=(conn, ks, chat), daemon=True).start()
                while True:
                    line = chat.readline()
                    packet = seal(ks, line.encode('ascii'))
                    send(conn, {'type': 'chat', 'packet': packet})
                    show('Bob', packet)
            except (ConnectionError, BrokenPipeError, OSError, EOFError):
                print('Connection ended; waiting for Alice again')
            except Exception as exc:
                print('Session failed:', exc)


if __name__ == '__main__':
    main()