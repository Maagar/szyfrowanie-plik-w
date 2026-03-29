"""
Czysta implementacja AES-256-GCM i ChaCha20-Poly1305 w Pythonie.
Bez zewnętrznych bibliotek — tylko stdlib.
"""

import os
import struct

# =========================================================================
# AES
# =========================================================================

SBOX = [
    0x63,0x7c,0x77,0x7b,0xf2,0x6b,0x6f,0xc5,0x30,0x01,0x67,0x2b,0xfe,0xd7,0xab,0x76,
    0xca,0x82,0xc9,0x7d,0xfa,0x59,0x47,0xf0,0xad,0xd4,0xa2,0xaf,0x9c,0xa4,0x72,0xc0,
    0xb7,0xfd,0x93,0x26,0x36,0x3f,0xf7,0xcc,0x34,0xa5,0xe5,0xf1,0x71,0xd8,0x31,0x15,
    0x04,0xc7,0x23,0xc3,0x18,0x96,0x05,0x9a,0x07,0x12,0x80,0xe2,0xeb,0x27,0xb2,0x75,
    0x09,0x83,0x2c,0x1a,0x1b,0x6e,0x5a,0xa0,0x52,0x3b,0xd6,0xb3,0x29,0xe3,0x2f,0x84,
    0x53,0xd1,0x00,0xed,0x20,0xfc,0xb1,0x5b,0x6a,0xcb,0xbe,0x39,0x4a,0x4c,0x58,0xcf,
    0xd0,0xef,0xaa,0xfb,0x43,0x4d,0x33,0x85,0x45,0xf9,0x02,0x7f,0x50,0x3c,0x9f,0xa8,
    0x51,0xa3,0x40,0x8f,0x92,0x9d,0x38,0xf5,0xbc,0xb6,0xda,0x21,0x10,0xff,0xf3,0xd2,
    0xcd,0x0c,0x13,0xec,0x5f,0x97,0x44,0x17,0xc4,0xa7,0x7e,0x3d,0x64,0x5d,0x19,0x73,
    0x60,0x81,0x4f,0xdc,0x22,0x2a,0x90,0x88,0x46,0xee,0xb8,0x14,0xde,0x5e,0x0b,0xdb,
    0xe0,0x32,0x3a,0x0a,0x49,0x06,0x24,0x5c,0xc2,0xd3,0xac,0x62,0x91,0x95,0xe4,0x79,
    0xe7,0xc8,0x37,0x6d,0x8d,0xd5,0x4e,0xa9,0x6c,0x56,0xf4,0xea,0x65,0x7a,0xae,0x08,
    0xba,0x78,0x25,0x2e,0x1c,0xa6,0xb4,0xc6,0xe8,0xdd,0x74,0x1f,0x4b,0xbd,0x8b,0x8a,
    0x70,0x3e,0xb5,0x66,0x48,0x03,0xf6,0x0e,0x61,0x35,0x57,0xb9,0x86,0xc1,0x1d,0x9e,
    0xe1,0xf8,0x98,0x11,0x69,0xd9,0x8e,0x94,0x9b,0x1e,0x87,0xe9,0xce,0x55,0x28,0xdf,
    0x8c,0xa1,0x89,0x0d,0xbf,0xe6,0x42,0x68,0x41,0x99,0x2d,0x0f,0xb0,0x54,0xbb,0x16,
]

RCON = [0x01,0x02,0x04,0x08,0x10,0x20,0x40,0x80,0x1b,0x36]

def _xtime(a):
    return ((a << 1) ^ 0x1b) & 0xff if a & 0x80 else (a << 1) & 0xff

def _gmul(a, b):
    p = 0
    for _ in range(8):
        if b & 1:
            p ^= a
        hi = a & 0x80
        a = (a << 1) & 0xff
        if hi:
            a ^= 0x1b
        b >>= 1
    return p

def _key_expansion(key: bytes):
    assert len(key) == 32
    w = [list(key[i*4:i*4+4]) for i in range(8)]
    for i in range(8, 60):
        temp = w[i-1][:]
        if i % 8 == 0:
            temp = [SBOX[temp[1]] ^ RCON[i//8-1], SBOX[temp[2]], SBOX[temp[3]], SBOX[temp[0]]]
        elif i % 8 == 4:
            temp = [SBOX[b] for b in temp]
        w.append([w[i-8][j] ^ temp[j] for j in range(4)])
    rk = []
    for r in range(15):
        rk.append([w[r*4+c][j] for j in range(4) for c in range(4)])
    return rk

def _sub_bytes(s):
    return [[SBOX[s[r][c]] for c in range(4)] for r in range(4)]

def _shift_rows(s):
    return [
        [s[0][0], s[0][1], s[0][2], s[0][3]],
        [s[1][1], s[1][2], s[1][3], s[1][0]],
        [s[2][2], s[2][3], s[2][0], s[2][1]],
        [s[3][3], s[3][0], s[3][1], s[3][2]],
    ]

def _mix_columns(s):
    def mix(col):
        return [
            _gmul(2,col[0])^_gmul(3,col[1])^col[2]^col[3],
            col[0]^_gmul(2,col[1])^_gmul(3,col[2])^col[3],
            col[0]^col[1]^_gmul(2,col[2])^_gmul(3,col[3]),
            _gmul(3,col[0])^col[1]^col[2]^_gmul(2,col[3]),
        ]
    return [[mix([s[r][c] for r in range(4)])[r] for c in range(4)] for r in range(4)]

def _add_round_key(s, rk):
    return [[s[r][c] ^ rk[r*4+c] for c in range(4)] for r in range(4)]

def aes_encrypt_block(block: bytes, round_keys) -> bytes:
    s = [[block[r+4*c] for c in range(4)] for r in range(4)]
    s = _add_round_key(s, round_keys[0])
    for rnd in range(1, 14):
        s = _sub_bytes(s)
        s = _shift_rows(s)
        s = _mix_columns(s)
        s = _add_round_key(s, round_keys[rnd])
    s = _sub_bytes(s)
    s = _shift_rows(s)
    s = _add_round_key(s, round_keys[14])
    return bytes(s[r][c] for c in range(4) for r in range(4))

def _inc32(counter: bytearray):
    for i in range(15, 11, -1):
        counter[i] = (counter[i] + 1) & 0xff
        if counter[i]:
            break

def aes_ctr_crypt(key: bytes, nonce: bytes, data: bytes) -> bytes:
    rk = _key_expansion(key)
    counter = bytearray(nonce + b'\x00\x00\x00\x01')
    out = bytearray()
    for i in range(0, len(data), 16):
        ks = aes_encrypt_block(bytes(counter), rk)
        chunk = data[i:i+16]
        out += bytes(a ^ b for a, b in zip(chunk, ks))
        _inc32(counter)
    return bytes(out)

def _ghash(h: bytes, aad: bytes, ciphertext: bytes) -> bytes:
    def _gf_mul(x: int, y: int) -> int:
        z = 0
        for _ in range(128):
            if y >> 127 & 1:
                z ^= x
            if x & 1:
                x = (x >> 1) ^ (0xe1 << 120)
            else:
                x >>= 1
            y <<= 1
            y &= (1 << 128) - 1
        return z

    def pad(b):
        r = len(b) % 16
        return b + b'\x00' * (16 - r) if r else b

    tag = 0
    h_int = int.from_bytes(h, 'big')
    for block in [pad(aad)[i:i+16] for i in range(0, len(pad(aad)), 16)] + \
                 [pad(ciphertext)[i:i+16] for i in range(0, len(pad(ciphertext)), 16)]:
        tag ^= int.from_bytes(block, 'big')
        tag = _gf_mul(tag, h_int)
    length_block = struct.pack('>QQ', len(aad)*8, len(ciphertext)*8)
    tag ^= int.from_bytes(length_block, 'big')
    tag = _gf_mul(tag, h_int)
    return tag.to_bytes(16, 'big')

def pure_aes_gcm_encrypt(key: bytes, plaintext: bytes):
    nonce = os.urandom(12)
    rk = _key_expansion(key)
    h = aes_encrypt_block(b'\x00'*16, rk)
    ciphertext = aes_ctr_crypt(key, nonce, plaintext)
    tag = _ghash(h, b'', ciphertext)
    j0 = bytearray(nonce + b'\x00\x00\x00\x01')
    ks = aes_encrypt_block(bytes(j0), rk)
    tag = bytes(a ^ b for a, b in zip(tag, ks))
    return nonce + tag + ciphertext

def pure_aes_gcm_decrypt(key: bytes, blob: bytes):
    nonce, tag, ciphertext = blob[:12], blob[12:28], blob[28:]
    rk = _key_expansion(key)
    h = aes_encrypt_block(b'\x00'*16, rk)
    tag_check = _ghash(h, b'', ciphertext)
    j0 = bytearray(nonce + b'\x00\x00\x00\x01')
    ks = aes_encrypt_block(bytes(j0), rk)
    tag_check = bytes(a ^ b for a, b in zip(tag_check, ks))
    if tag_check != tag:
        raise ValueError("Tag mismatch")
    return aes_ctr_crypt(key, nonce, ciphertext)

# =========================================================================
# ChaCha20-Poly1305
# =========================================================================

def _rotl32(v, n):
    return ((v << n) | (v >> (32 - n))) & 0xFFFFFFFF

def _quarter_round(s, a, b, c, d):
    s[a] = (s[a] + s[b]) & 0xFFFFFFFF; s[d] ^= s[a]; s[d] = _rotl32(s[d], 16)
    s[c] = (s[c] + s[d]) & 0xFFFFFFFF; s[b] ^= s[c]; s[b] = _rotl32(s[b], 12)
    s[a] = (s[a] + s[b]) & 0xFFFFFFFF; s[d] ^= s[a]; s[d] = _rotl32(s[d],  8)
    s[c] = (s[c] + s[d]) & 0xFFFFFFFF; s[b] ^= s[c]; s[b] = _rotl32(s[b],  7)

def _chacha20_block(key: bytes, counter: int, nonce: bytes) -> bytes:
    constants = [0x61707865, 0x3320646e, 0x79622d32, 0x6b206574]
    k = list(struct.unpack('<8I', key))
    n = list(struct.unpack('<3I', nonce))
    state = constants + k + [counter] + n
    working = state[:]
    for _ in range(10):
        _quarter_round(working, 0,4,8,12)
        _quarter_round(working, 1,5,9,13)
        _quarter_round(working, 2,6,10,14)
        _quarter_round(working, 3,7,11,15)
        _quarter_round(working, 0,5,10,15)
        _quarter_round(working, 1,6,11,12)
        _quarter_round(working, 2,7,8,13)
        _quarter_round(working, 3,4,9,14)
    return struct.pack('<16I', *[(working[i]+state[i]) & 0xFFFFFFFF for i in range(16)])

def _chacha20_encrypt(key: bytes, counter: int, nonce: bytes, data: bytes) -> bytes:
    out = bytearray()
    for i in range(0, len(data), 64):
        ks = _chacha20_block(key, counter + i // 64, nonce)
        chunk = data[i:i+64]
        out += bytes(a ^ b for a, b in zip(chunk, ks))
    return bytes(out)

def _poly1305_mac(key: bytes, msg: bytes) -> bytes:
    r = int.from_bytes(key[:16], 'little') & 0x0ffffffc0ffffffc0ffffffc0fffffff
    s = int.from_bytes(key[16:], 'little')
    p = (1 << 130) - 5
    acc = 0
    for i in range(0, len(msg), 16):
        chunk = msg[i:i+16]
        n = int.from_bytes(chunk + b'\x01', 'little')
        acc = (acc + n) % p
        acc = (r * acc) % p
    return ((acc + s) & 0xffffffffffffffffffffffffffffffff).to_bytes(16, 'little')

def pure_chacha20_poly1305_encrypt(key: bytes, plaintext: bytes):
    nonce = os.urandom(12)
    otk = _chacha20_block(key, 0, nonce)[:32]
    ciphertext = _chacha20_encrypt(key, 1, nonce, plaintext)
    mac_data = ciphertext + b'\x00' * ((-len(ciphertext)) % 16)
    mac_data += struct.pack('<Q', 0) + struct.pack('<Q', len(ciphertext))
    tag = _poly1305_mac(otk, mac_data)
    return nonce + tag + ciphertext

def pure_chacha20_poly1305_decrypt(key: bytes, blob: bytes):
    nonce, tag, ciphertext = blob[:12], blob[12:28], blob[28:]
    otk = _chacha20_block(key, 0, nonce)[:32]
    mac_data = ciphertext + b'\x00' * ((-len(ciphertext)) % 16)
    mac_data += struct.pack('<Q', 0) + struct.pack('<Q', len(ciphertext))
    expected_tag = _poly1305_mac(otk, mac_data)
    if expected_tag != tag:
        raise ValueError("Tag mismatch")
    return _chacha20_encrypt(key, 1, nonce, ciphertext)