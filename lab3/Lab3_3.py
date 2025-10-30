from Crypto.Util.number import *
import random

p = getPrime(256)
g = 2
x = random.randint(1, p-2)
h = pow(g, x, p)

public_key = (p, g, h)
privat_key = x

m = b'Confidential Data'

def encrypt(m, pubkey):
    p, g, h = pubkey
    m = bytes_to_long(m)
    k = random.randint(1, p-2)
    c1 = pow(g, k, p)
    c2 = (m * pow(h, k, p)) % p

    return (c1, c2)

def decrypt(c, x):
    c1, c2 = c
    s = pow(c1, x, p)
    m = (c2 * inverse(s, p)) % p
    return long_to_bytes(m)

c = encrypt(m, public_key)
print(c)
p = decrypt(c, privat_key)
print(p)