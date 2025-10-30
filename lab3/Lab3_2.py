from Crypto.Util.number import *
from Crypto.Cipher import AES
from Crypto.Util.Padding import *
from collections import namedtuple
import random
import hashlib

Point = namedtuple("Point", "x y")
O = 'Origin'

# y**2 = x**3 + ax + b
def check_point(P: tuple):
    if P == O:
        return True
    else:
        return (P.y**2 - (P.x**3 + a*P.x + b)) % p == 0 and 0 <= P.x < p and 0 <= P.y < p

def point_inverse(P: tuple):
    if P == O:
        return P
    return Point(P.x, (-P.y) % p)

def point_addition(P: tuple, Q: tuple):
    if P == O:
        return Q
    elif Q == O:
        return P
    elif Q == point_inverse(P):
        return O
    else:
        if P == Q:
            lam = (3*P.x**2 + a) * inverse(2*P.y, p) % p
        else:
            lam = (Q.y - P.y) * inverse(Q.x - P.x, p) % p
    Rx = (lam**2 - P.x - Q.x) % p
    Ry = (lam*(P.x - Rx) - P.y) % p
    R = Point(Rx, Ry)
    assert check_point(R)
    return R

def double_and_add(P: tuple, n: int):
    Q = O
    R = P
    while n > 0:
        if n & 1:
            Q = point_addition(Q, R)
        R = point_addition(R, R)
        n >>= 1
    assert check_point(Q)
    return Q

def mod_sqrt(a, p): # p == 3 mod 4
    return pow(a, (p + 1) // 4, p)

while True:
    try:
        p = getPrime(128)
        a = 2
        b = 3
        # y**2 = x**3 + ax + b
        # G gotta be on curve y^2 = x^3 + ax + b (mod p)
        while True:
            x = random.randint(0, p-1)
            rhs = (x**3 + a*x + b) % p
            # Check if rhs is quadratic residue mod p
            if pow(rhs, (p - 1) // 2, p) == 1:
                y = mod_sqrt(rhs, p)
                G = Point(x, y)
                break

        # alice ka shit
        priv_a = random.randint(1, p-1)
        A = double_and_add(G, priv_a)

        # bob ka shit
        priv_b = random.randint(1, p-1)
        B = double_and_add(G, priv_b)

        shared_secret = double_and_add(G, priv_a * priv_b)

        break
    except Exception:
        continue

print('Params :')

print(f'y^2 = x^3 + {a}x + {b} mod p')
print(f'{p = }')
print(f'{G = }')
print(f'{A = }')
print(f'{B = }')
assert double_and_add(A, priv_b) == double_and_add(B, priv_a) == shared_secret, "uh oh"
print(shared_secret)

def encrypt(m, key):
    key = hashlib.sha256(str(key).encode()).hexdigest()# 256 bits
    m = pad(m.encode(), 16)
    ciph = AES.new(bytes.fromhex(key), AES.MODE_ECB)
    ct = ciph.encrypt(m)
    return ct.hex()

def decrypt(c, key):
    key = hashlib.sha256(str(key).encode()).hexdigest() # 256 bits
    ciph = AES.new(bytes.fromhex(key), AES.MODE_ECB)
    pt = ciph.decrypt(bytes.fromhex(c))
    return unpad(pt, 16).decode()

# alice does a * B for shared_secret
# bob does b * A for shared_secret
ct = encrypt("Secure Transactions", shared_secret)
print(f"\n{ct = }")
pt = decrypt(ct, shared_secret)
print(f"{pt = }")