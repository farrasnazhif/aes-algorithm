import hashlib
import hmac
import json
import queue
import secrets
import threading
import paho.mqtt.client as mqtt
from aes import AES128

BROKER = 'broker.emqx.io'
PORT = 1883
TOPIC_BASE = 'tugas/keamanan_informasi/aes_kdc'
CHANNELS = {
    'kdc': (f'{TOPIC_BASE}/alice_to_kdc', f'{TOPIC_BASE}/kdc_to_alice'),
    'alice_kdc': (f'{TOPIC_BASE}/kdc_to_alice', f'{TOPIC_BASE}/alice_to_kdc'),
    'bob': (f'{TOPIC_BASE}/alice_to_bob', f'{TOPIC_BASE}/bob_to_alice'),
    'alice_bob': (f'{TOPIC_BASE}/bob_to_alice', f'{TOPIC_BASE}/alice_to_bob'),
}


class MqttChannel:
    def __init__(self, role):
        self.sub_topic, self.pub_topic = CHANNELS[role]
        self.inbox = queue.Queue()
        self.ready = threading.Event()
        self.client = mqtt.Client(mqtt.CallbackAPIVersion.VERSION2)
        self.client.on_connect = self._on_connect
        self.client.on_subscribe = self._on_subscribe
        self.client.on_message = self._on_message

    def _on_connect(self, client, userdata, flags, reason_code, properties):
        if reason_code == 0:
            client.subscribe(self.sub_topic)

    def _on_subscribe(self, client, userdata, mid, reason_code_list, properties):
        self.ready.set()

    def _on_message(self, client, userdata, msg):
        if msg.retain:
            return
        try:
            self.inbox.put(json.loads(msg.payload.decode('ascii')))
        except Exception:
            pass

    def __enter__(self):
        self.client.connect(BROKER, PORT, keepalive=60)
        self.client.loop_start()
        if not self.ready.wait(timeout=15):
            self.client.loop_stop()
            self.client.disconnect()
            raise ConnectionError('MQTT connection timeout')
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        self.client.loop_stop()
        self.client.disconnect()


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


def open_seal(key, packet):
    nonce = bytes.fromhex(packet['nonce'])
    cipher = bytes.fromhex(packet['ciphertext'])
    tag = bytes.fromhex(packet['tag'])
    mac_key = hashlib.sha256(b'KI-demo-mac-v1' + key).digest()
    expected = hmac.new(mac_key, nonce + cipher, hashlib.sha256).digest()
    if not hmac.compare_digest(tag, expected):
        raise ValueError('Authentication tag invalid')
    return AES128(key).crypt_ctr(cipher, nonce)


def send(channel, obj):
    data = json.dumps(obj, separators=(',', ':'))
    info = channel.client.publish(channel.pub_topic, data)
    info.wait_for_publish(timeout=10)


def recv(channel):
    while True:
        try:
            return channel.inbox.get(timeout=0.5)
        except queue.Empty:
            continue


def connect(role):
    return MqttChannel(role)


def show(label, packet):
    print(f'{label} ciphertext (hex): {packet["ciphertext"]}')
