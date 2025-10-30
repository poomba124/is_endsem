from Crypto.Util.number import *
from Crypto.Cipher import AES
from Crypto.Util.Padding import *
from collections import namedtuple
import random
import hashlib

# Defines a Point object for convenience.
Point = namedtuple("Point", "x y")
# Represents the point at infinity.
O = 'Origin'

# --- ELLIPTIC CURVE MATH FUNCTIONS ---

# Checks if a point P is on the defined curve.
def check_point(P: tuple):
    if P == O:
        return True
    # The curve equation is y^2 = x^3 + ax + b (mod p).
    # This checks if the point's coordinates satisfy the equation.
    return (P.y**2 - (P.x**3 + a*P.x + b)) % p == 0

# Calculates the inverse of a point P on the curve.
def point_inverse(P: tuple):
    if P == O:
        return P
    return Point(P.x, (-P.y) % p)

# Adds two points P and Q on the elliptic curve.
def point_addition(P: tuple, Q: tuple):
    # Handles special cases like adding the point at infinity.
    if P == O: return Q
    if Q == O: return P
    if Q == point_inverse(P): return O

    # Calculates the slope 'lam' of the line through P and Q.
    if P == Q: # Point doubling
        lam = (3*P.x**2 + a) * inverse(2*P.y, p) % p
    else: # Point addition
        lam = (Q.y - P.y) * inverse(Q.x - P.x, p) % p

    # Calculates the coordinates of the resulting point R.
    Rx = (lam**2 - P.x - Q.x) % p
    Ry = (lam*(P.x - Rx) - P.y) % p
    R = Point(Rx, Ry)
    assert check_point(R)
    return R

# Performs scalar multiplication (n * P) using the efficient double-and-add algorithm.
def double_and_add(P: tuple, n: int):
    Q = O
    R = P
    while n > 0:
        if n & 1: # If the last bit of n is 1, add R to the result.
            Q = point_addition(Q, R)
        R = point_addition(R, R) # Double R.
        n >>= 1 # Shift n to the right.
    assert check_point(Q)
    return Q

# Finds the modular square root, needed to find a y-coordinate for a given x.
def mod_sqrt(a, p):
    return pow(a, (p + 1) // 4, p)

# --- KEY EXCHANGE AND AES ENCRYPTION/DECRYPTION ---

# Generate curve parameters and a valid generator point G.
while True:
    try:
        p = getPrime(128) # A 128-bit prime modulus
        a, b = 2, 3       # Curve parameters
        # Loop to find a valid point G on the curve
        while True:
            x = random.randint(0, p-1)
            rhs = (x**3 + a*x + b) % p
            # Check if a modular square root exists
            if pow(rhs, (p - 1) // 2, p) == 1:
                y = mod_sqrt(rhs, p)
                G = Point(x, y) # G is our generator point
                break

        # --- ECDH KEY EXCHANGE SIMULATION ---
        # Alice generates her private key (a random number) and public key (A = priv_a * G)
        priv_a = random.randint(1, p-1)
        A = double_and_add(G, priv_a)

        # Bob generates his private key and public key (B = priv_b * G)
        priv_b = random.randint(1, p-1)
        B = double_and_add(G, priv_b)

        # Alice computes the shared secret: S = priv_a * B
        shared_secret_A = double_and_add(B, priv_a)
        # Bob computes the shared secret: S = priv_b * A
        shared_secret_B = double_and_add(A, priv_b)

        # Both should arrive at the same secret point.
        assert shared_secret_A == shared_secret_B
        shared_secret = shared_secret_A
        break
    except Exception:
        continue

# --- AES ENCRYPTION/DECRYPTION USING THE SHARED SECRET ---

# Encrypts a message using a key derived from the shared secret.
def encrypt(m, key_point):
    # Use SHA-256 to hash the point's coordinates into a 256-bit AES key.
    key = hashlib.sha256(str(key_point).encode()).digest()
    m_padded = pad(m.encode(), AES.block_size)
    cipher = AES.new(key, AES.MODE_ECB)
    ct = cipher.encrypt(m_padded)
    return ct.hex()

# Decrypts a ciphertext.
def decrypt(c, key_point):
    key = hashlib.sha256(str(key_point).encode()).digest()
    cipher = AES.new(key, AES.MODE_ECB)
    pt_padded = cipher.decrypt(bytes.fromhex(c))
    return unpad(pt_padded, AES.block_size).decode()

# --- EXECUTION ---
print('Curve Parameters:')
print(f'y^2 = x^3 + {a}x + {b} (mod p)')
print(f'p = {p}')
print(f'G (generator) = {G}')

print('\nKey Exchange:')
print(f'Alice public key (A) = {A}')
print(f'Bob public key (B) = {B}')
print(f'Shared Secret Point = {shared_secret}')

# Use the shared secret to encrypt and decrypt the message.
message = "Secure Transactions"
ct = encrypt(message, shared_secret)
print(f"\nEncrypted Ciphertext (hex) = {ct}")
pt = decrypt(ct, shared_secret)
print(f"Decrypted Plaintext = {pt}")
assert pt == message



from Crypto.Util.number import *
from Crypto.Cipher import AES
from Crypto.Util.Padding import *
from collections import namedtuple
import random
import hashlib

# --- STRUCTURE & CONSTANTS ---
Point = namedtuple("Point", "x y")
O = 'Origin'  # Point at infinity

# --- ELLIPTIC CURVE MATH FUNCTIONS ---
def check_point(P):
    if P == O:
        return True
    return (P.y**2 - (P.x**3 + a*P.x + b)) % p == 0

def point_inverse(P):
    if P == O:
        return P
    return Point(P.x, (-P.y) % p)

def point_addition(P, Q):
    if P == O: return Q
    if Q == O: return P
    if Q == point_inverse(P): return O

    if P == Q:
        lam = (3*P.x**2 + a) * inverse(2*P.y, p) % p
    else:
        lam = (Q.y - P.y) * inverse(Q.x - P.x, p) % p

    Rx = (lam**2 - P.x - Q.x) % p
    Ry = (lam*(P.x - Rx) - P.y) % p
    R = Point(Rx, Ry)
    assert check_point(R)
    return R

def double_and_add(P, n):
    Q = O
    R = P
    while n > 0:
        if n & 1:
            Q = point_addition(Q, R)
        R = point_addition(R, R)
        n >>= 1
    assert check_point(Q)
    return Q

def mod_sqrt(a, p):
    return pow(a, (p + 1) // 4, p)

# --- AES ENCRYPTION/DECRYPTION ---
def encrypt(m, key_point):
    key = hashlib.sha256(str(key_point).encode()).digest()
    m_padded = pad(m.encode(), AES.block_size)
    cipher = AES.new(key, AES.MODE_ECB)
    ct = cipher.encrypt(m_padded)
    return ct.hex()

def decrypt(c, key_point):
    key = hashlib.sha256(str(key_point).encode()).digest()
    cipher = AES.new(key, AES.MODE_ECB)
    pt_padded = cipher.decrypt(bytes.fromhex(c))
    return unpad(pt_padded, AES.block_size).decode()

# --- USER INPUT SECTION ---
print("Elliptic Curve Key Exchange + AES Encryption")
print("=============================================")

# Message input
message = input("\nEnter a message to encrypt: ")

# Curve parameter input
try:
    a = int(input("Enter curve parameter a (default 2): ") or 2)
    b = int(input("Enter curve parameter b (default 3): ") or 3)
except ValueError:
    print("Invalid input, using defaults a=2, b=3")
    a, b = 2, 3

# Modulus input
choice = input("Enter 'A' to auto-generate prime p or 'M' to manually enter: ").strip().upper()
if choice == 'M':
    try:
        p = int(input("Enter a prime number p: "))
        if not isPrime(p):
            print("⚠️ Not a prime number. Generating a random 128-bit prime instead.")
            p = getPrime(128)
    except ValueError:
        print("⚠️ Invalid input. Using random prime.")
        p = getPrime(128)
else:
    p = getPrime(128)

# --- FIND VALID GENERATOR POINT G ---
while True:
    try:
        x = random.randint(0, p-1)
        rhs = (x**3 + a*x + b) % p
        if pow(rhs, (p - 1) // 2, p) == 1:
            y = mod_sqrt(rhs, p)
            G = Point(x, y)
            break
    except Exception:
        continue

# --- ECDH KEY EXCHANGE ---
priv_a = random.randint(1, p-1)
priv_b = random.randint(1, p-1)
A = double_and_add(G, priv_a)
B = double_and_add(G, priv_b)
shared_secret_A = double_and_add(B, priv_a)
shared_secret_B = double_and_add(A, priv_b)
assert shared_secret_A == shared_secret_B
shared_secret = shared_secret_A

# --- AES ENCRYPTION/DECRYPTION ---
ct = encrypt(message, shared_secret)
pt = decrypt(ct, shared_secret)

# --- OUTPUT ---
print("\n--- CURVE PARAMETERS ---")
print(f"Equation: y^2 = x^3 + {a}x + {b} (mod {p})")
print(f"Generator point G = {G}")

print("\n--- KEYS ---")
print(f"Alice private key = {priv_a}")
print(f"Alice public key (A) = {A}")
print(f"Bob private key = {priv_b}")
print(f"Bob public key (B) = {B}")
print(f"Shared secret point = {shared_secret}")

print("\n--- AES ENCRYPTION ---")
print(f"Ciphertext (hex): {ct}")
print(f"Decrypted plaintext: {pt}")

assert pt == message, "❌ Decryption failed!"
print("\n✅ Decryption successful! Message verified.")
