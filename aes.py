def gf_mul(a, b):
    out = 0
    for _ in range(8):
        if b & 1:
            out ^= a
        high = a & 0x80
        a = (a << 1) & 255
        if high:
            a ^= 0x1b
        b >>= 1
    return out


def gf_pow(a, n):
    result = 1
    while n:
        if n & 1:
            result = gf_mul(result, a)
        a = gf_mul(a, a)
        n >>= 1
    return result


def rotl(x, n):
    return ((x << n) | (x >> (8 - n))) & 255


def make_sbox():
    s = []
    for x in range(256):
        y = gf_pow(x, 254) if x else 0
        s.append((y ^ rotl(y, 1) ^ rotl(y, 2) ^ rotl(y, 3) ^ rotl(y, 4) ^ 0x63) & 255)
    return s


SBOX = make_sbox()
INV_SBOX = [0] * 256
for i, value in enumerate(SBOX):
    INV_SBOX[value] = i


def expand_key(key):
    if len(key) != 16:
        raise ValueError('AES-128 key must be exactly 16 ASCII bytes')
    words = [list(key[i:i + 4]) for i in range(0, 16, 4)]
    rcon = 1
    for i in range(4, 44):
        temp = words[-1][:]
        if i % 4 == 0:
            temp = [SBOX[v] for v in temp[1:] + temp[:1]]
            temp[0] ^= rcon
            rcon = gf_mul(rcon, 2)
        words.append([a ^ b for a, b in zip(words[i - 4], temp)])
    return [sum(words[i:i + 4], []) for i in range(0, 44, 4)]


def add_round_key(s, key):
    return [a ^ b for a, b in zip(s, key)]


def shift_rows(s, inverse=False):
    out = s[:]
    for r in range(4):
        row = [s[r + 4 * c] for c in range(4)]
        row = (row[-r:] + row[:-r]) if inverse and r else (row[r:] + row[:r])
        for c in range(4):
            out[r + 4 * c] = row[c]
    return out


def mix_columns(s, inverse=False):
    matrix = ([14, 11, 13, 9], [9, 14, 11, 13], [13, 9, 14, 11], [11, 13, 9, 14]) if inverse else ([2, 3, 1, 1], [1, 2, 3, 1], [1, 1, 2, 3], [3, 1, 1, 2])
    out = s[:]
    for c in range(4):
        col = s[4 * c:4 * c + 4]
        for r in range(4):
            out[4 * c + r] = 0
            for k in range(4):
                out[4 * c + r] ^= gf_mul(matrix[r][k], col[k])
    return out


class AES128:
    def __init__(self, key):
        self.keys = expand_key(key)

    def encrypt_block(self, block):
        if len(block) != 16:
            raise ValueError('block must contain 16 bytes')
        s = add_round_key(list(block), self.keys[0])
        for rnd in range(1, 10):
            s = add_round_key(mix_columns(shift_rows([SBOX[x] for x in s])), self.keys[rnd])
        return bytes(add_round_key(shift_rows([SBOX[x] for x in s]), self.keys[10]))

    def decrypt_block(self, block):
        if len(block) != 16:
            raise ValueError('block must contain 16 bytes')
        s = add_round_key(list(block), self.keys[10])
        for rnd in range(9, 0, -1):
            s = [INV_SBOX[x] for x in shift_rows(s, inverse=True)]
            s = mix_columns(add_round_key(s, self.keys[rnd]), inverse=True)
        return bytes(add_round_key([INV_SBOX[x] for x in shift_rows(s, inverse=True)], self.keys[0]))

    def crypt_ctr(self, data, nonce):
        if len(nonce) != 8:
            raise ValueError('CTR nonce must contain 8 bytes')
        output = bytearray()
        for offset in range(0, len(data), 16):
            counter = (offset // 16).to_bytes(8, 'big')
            stream = self.encrypt_block(nonce + counter)
            output.extend(a ^ b for a, b in zip(data[offset:offset + 16], stream))
        return bytes(output)