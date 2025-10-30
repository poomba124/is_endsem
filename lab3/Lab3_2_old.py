from Crypto.Cipher import AES
import random

p = 9739
a = 497
b = 1768
G = (1804, 5368)
n = 9739

def mod_inv(x, p):
    return pow(x, -1, p)

def point_add(P, Q):
    if P == (None, None):
        return Q
    if Q == (None, None):
        return P
    if P == Q:
        lam = (3 * P[0]**2 + a) * mod_inv(2 * P[1], p) % p
    else:
        lam = (Q[1] - P[1]) * mod_inv(Q[0] - P[0], p) % p
    x_r = (lam**2 - P[0] - Q[0]) % p
    y_r = (lam * (P[0] - x_r) - P[1]) % p
    return (x_r, y_r)

def scalar_mult(k, P):
    R = (None, None)
    for bit in bin(k)[2:]:
        R = point_add(R, R)
        if bit == '1':
            R = point_add(R, P)
    return R

priv_key = random.randint(1, n-1)
pub_key = scalar_mult(priv_key, G)

msg = b"Secure Transactions"
print("Original Message:", msg.decode())

eph_priv = random.randint(1, n-1)
eph_pub = scalar_mult(eph_priv, G)

shared = scalar_mult(eph_priv, pub_key)
aes_key = shared[0].to_bytes(32, 'big')[:16]

cipher = AES.new(aes_key, AES.MODE_ECB)
pad_len = 16 - (len(msg) % 16)
msg_padded = msg + bytes([pad_len] * pad_len)
ct = cipher.encrypt(msg_padded)

print("Ciphertext (hex):", ct.hex())

shared_recv = scalar_mult(priv_key, eph_pub)
aes_key_recv = shared_recv[0].to_bytes(32, 'big')[:16]

decipher = AES.new(aes_key_recv, AES.MODE_ECB)
pt_padded = decipher.decrypt(ct)
pt = pt_padded[:-pt_padded[-1]]

print("Decrypted Message:", pt.decode())
