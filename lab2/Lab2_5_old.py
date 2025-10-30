# AES-192 ECB (optimized, no external libs)
# Helper conversion functions included; full AES-192 implementation (PKCS#7 padding).
# Change `encoding` in main() if you want to try utf-8 / utf-16le etc.

SBOX = [
0x63,0x7C,0x77,0x7B,0xF2,0x6B,0x6F,0xC5,0x30,0x01,0x67,0x2B,0xFE,0xD7,0xAB,0x76,
0xCA,0x82,0xC9,0x7D,0xFA,0x59,0x47,0xF0,0xAD,0xD4,0xA2,0xAF,0x9C,0xA4,0x72,0xC0,
0xB7,0xFD,0x93,0x26,0x36,0x3F,0xF7,0xCC,0x34,0xA5,0xE5,0xF1,0x71,0xD8,0x31,0x15,
0x04,0xC7,0x23,0xC3,0x18,0x96,0x05,0x9A,0x07,0x12,0x80,0xE2,0xEB,0x27,0xB2,0x75,
0x09,0x83,0x2C,0x1A,0x1B,0x6E,0x5A,0xA0,0x52,0x3B,0xD6,0xB3,0x29,0xE3,0x2F,0x84,
0x53,0xD1,0x00,0xED,0x20,0xFC,0xB1,0x5B,0x6A,0xCB,0xBE,0x39,0x4A,0x4C,0x58,0xCF,
0xD0,0xEF,0xAA,0xFB,0x43,0x4D,0x33,0x85,0x45,0xF9,0x02,0x7F,0x50,0x3C,0x9F,0xA8,
0x51,0xA3,0x40,0x8F,0x92,0x9D,0x38,0xF5,0xBC,0xB6,0xDA,0x21,0x10,0xFF,0xF3,0xD2,
0xCD,0x0C,0x13,0xEC,0x5F,0x97,0x44,0x17,0xC4,0xA7,0x7E,0x3D,0x64,0x5D,0x19,0x73,
0x60,0x81,0x4F,0xDC,0x22,0x2A,0x90,0x88,0x46,0xEE,0xB8,0x14,0xDE,0x5E,0x0B,0xDB,
0xE0,0x32,0x3A,0x0A,0x49,0x06,0x24,0x5C,0xC2,0xD3,0xAC,0x62,0x91,0x95,0xE4,0x79,
0xE7,0xC8,0x37,0x6D,0x8D,0xD5,0x4E,0xA9,0x6C,0x56,0xF4,0xEA,0x65,0x7A,0xAE,0x08,
0xBA,0x78,0x25,0x2E,0x1C,0xA6,0xB4,0xC6,0xE8,0xDD,0x74,0x1F,0x4B,0xBD,0x8B,0x8A,
0x70,0x3E,0xB5,0x66,0x48,0x03,0xF6,0x0E,0x61,0x35,0x57,0xB9,0x86,0xC1,0x1D,0x9E,
0xE1,0xF8,0x98,0x11,0x69,0xD9,0x8E,0x94,0x9B,0x1E,0x87,0xE9,0xCE,0x55,0x28,0xDF,
0x8C,0xA1,0x89,0x0D,0xBF,0xE6,0x42,0x68,0x41,0x99,0x2D,0x0F,0xB0,0x54,0xBB,0x16
]

RCON_WORD = [
  0x00000000,0x01000000,0x02000000,0x04000000,0x08000000,0x10000000,
  0x20000000,0x40000000,0x80000000,0x1b000000,0x36000000
]

def bytes_from_hex(h):
    h = h.strip()
    return bytes(int(h[i:i+2],16) for i in range(0,len(h),2))

def hex_from_bytes(b):
    return bytes(b).hex()

def pkcs7_pad(b):
    pad_len = 16 - (len(b) % 16)
    if pad_len == 0:
        pad_len = 16
    return b + bytes([pad_len]) * pad_len

def pkcs7_unpad(b):
    if not b:
        return b
    pad_len = b[-1]
    return b[:-pad_len]

def xtime(a):
    a <<= 1
    if a & 0x100:
        a ^= 0x11B
    return a & 0xFF

def gf_mul(a,b):
    res = 0
    while b:
        if b & 1:
            res ^= a
        a = xtime(a)
        b >>= 1
    return res & 0xFF

def sub_word32(w):
    return (
        (SBOX[(w>>24) & 0xFF] << 24) |
        (SBOX[(w>>16) & 0xFF] << 16) |
        (SBOX[(w>>8) & 0xFF] << 8) |
        (SBOX[w & 0xFF])
    ) & 0xFFFFFFFF

def rot_word32(w):
    return ((w << 8) & 0xFFFFFFFF) | (w >> 24)

def key_expansion_192(key_bytes24):
    Nk = 6
    Nb = 4
    Nr = 12
    total = Nb * (Nr + 1)  # 52 words
    w = [0] * total
    for i in range(Nk):
        w[i] = (key_bytes24[4*i] << 24) | (key_bytes24[4*i+1] << 16) | (key_bytes24[4*i+2] << 8) | key_bytes24[4*i+3]
    for i in range(Nk, total):
        temp = w[i-1]
        if i % Nk == 0:
            temp = sub_word32(rot_word32(temp)) ^ RCON_WORD[i//Nk]
        elif i % Nk == 4:
            temp = sub_word32(temp)
        w[i] = w[i-Nk] ^ temp
    return w

def bytes_to_state(block16):
    s = [[0]*4 for _ in range(4)]
    for r in range(4):
        for c in range(4):
            s[r][c] = block16[r + 4*c]
    return s

def state_to_bytes(s):
    out = bytearray(16)
    for r in range(4):
        for c in range(4):
            out[r + 4*c] = s[r][c]
    return bytes(out)

def add_round_key(state, w, round_idx):
    for c in range(4):
        wk = w[round_idx*4 + c]
        state[0][c] ^= (wk >> 24) & 0xFF
        state[1][c] ^= (wk >> 16) & 0xFF
        state[2][c] ^= (wk >> 8) & 0xFF
        state[3][c] ^= wk & 0xFF

def sub_bytes(state):
    for r in range(4):
        for c in range(4):
            state[r][c] = SBOX[state[r][c]]

def shift_rows(state):
    state[1] = state[1][1:] + state[1][:1]
    state[2] = state[2][2:] + state[2][:2]
    state[3] = state[3][3:] + state[3][:3]

def mix_single_column(col):
    a0,a1,a2,a3 = col
    t = a0 ^ a1 ^ a2 ^ a3
    u = a0
    col[0] ^= t ^ xtime(a0 ^ a1)
    col[1] ^= t ^ xtime(a1 ^ a2)
    col[2] ^= t ^ xtime(a2 ^ a3)
    col[3] ^= t ^ xtime(a3 ^ u)

def mix_columns(state):
    for c in range(4):
        col = [state[r][c] for r in range(4)]
        mix_single_column(col)
        for r in range(4):
            state[r][c] = col[r]

def aes192_encrypt_block(block16, round_keys):
    state = bytes_to_state(block16)
    add_round_key(state, round_keys, 0)
    for rnd in range(1,12):
        sub_bytes(state)
        shift_rows(state)
        mix_columns(state)
        add_round_key(state, round_keys, rnd)
    sub_bytes(state)
    shift_rows(state)
    add_round_key(state, round_keys, 12)
    return state_to_bytes(state)

def aes192_ecb_encrypt(plaintext_bytes, key_hex):
    key_bytes = bytes_from_hex(key_hex)
    if len(key_bytes) != 24:
        raise ValueError("AES-192 requires 24-byte key (48 hex chars).")
    round_keys = key_expansion_192(list(key_bytes))
    pt = pkcs7_pad(plaintext_bytes)
    out = b''
    for i in range(0, len(pt), 16):
        out += aes192_encrypt_block(pt[i:i+16], round_keys)
    return out

def aes192_ecb_decrypt(cipher_bytes, key_hex):
    # Minimal decryption (works for verification) - inverse ops implemented inline
    key_bytes = bytes_from_hex(key_hex)
    if len(key_bytes) != 24:
        raise ValueError("AES-192 requires 24-byte key (48 hex chars).")
    round_keys = key_expansion_192(list(key_bytes))
    def inv_sub_bytes(s):
        inv = [0]*256
        for i,v in enumerate(SBOX): inv[v]=i
        for r in range(4):
            for c in range(4):
                s[r][c] = inv[s[r][c]]
    def inv_shift_rows(s):
        s[1] = s[1][-1:] + s[1][:-1]
        s[2] = s[2][-2:] + s[2][:-2]
        s[3] = s[3][-3:] + s[3][:-3]
    def inv_mix_columns(s):
        for c in range(4):
            a0,a1,a2,a3 = s[0][c], s[1][c], s[2][c], s[3][c]
            r0 = gf_mul(a0,14) ^ gf_mul(a1,11) ^ gf_mul(a2,13) ^ gf_mul(a3,9)
            r1 = gf_mul(a0,9)  ^ gf_mul(a1,14) ^ gf_mul(a2,11) ^ gf_mul(a3,13)
            r2 = gf_mul(a0,13) ^ gf_mul(a1,9)  ^ gf_mul(a2,14) ^ gf_mul(a3,11)
            r3 = gf_mul(a0,11) ^ gf_mul(a1,13) ^ gf_mul(a2,9)  ^ gf_mul(a3,14)
            s[0][c],s[1][c],s[2][c],s[3][c] = r0&0xFF,r1&0xFF,r2&0xFF,r3&0xFF
    out = b''
    for i in range(0, len(cipher_bytes), 16):
        block = cipher_bytes[i:i+16]
        s = bytes_to_state(block)
        add_round_key(s, round_keys, 12)
        for rnd in range(11,0,-1):
            inv_shift_rows(s)
            inv_sub_bytes(s)
            add_round_key(s, round_keys, rnd)
            inv_mix_columns(s)
        inv_shift_rows(s)
        inv_sub_bytes(s)
        add_round_key(s, round_keys, 0)
        out += state_to_bytes(s)
    return pkcs7_unpad(out)

# -------------------- Demo --------------------
def main():
    plaintext = "Top Secret Data"
    # Replace/ensure key is 48 hex chars (24 bytes) for AES-192:
    key_hex = "FEDCBA9876543210FEDCBA9876543210FEDCBA9876543210"
    # Try utf-8 and utf-16le to compare with other implementations
    for enc in ('utf-8','utf-16le'):
        pb = plaintext.encode(enc)
        ct = aes192_ecb_encrypt(pb, key_hex)
        print(f"Encoding={enc}, Cipher(hex)={hex_from_bytes(ct)}")
        # verify decrypt
        pt_back = aes192_ecb_decrypt(ct, key_hex)
        print(f"Decoded back ({enc}):", pt_back.decode(enc))

if __name__ == "__main__":
    main()
