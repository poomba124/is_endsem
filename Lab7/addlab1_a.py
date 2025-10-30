# -----------------------------------------------
# ElGamal Homomorphic Multiplication Demo
# -----------------------------------------------
from Crypto.Util import number
import random
from math import gcd

# ----------------- Key Generation -----------------
def elgamal_keygen(bits=256):
    # Generate a large prime p
    p = number.getPrime(bits)
    # Choose generator g (primitive root)
    g = random.randint(2, p-2)
    # Private key x
    x = random.randint(1, p-2)
    # Public key y = g^x mod p
    y = pow(g, x, p)
    return (p, g, y, x)

# ----------------- Encryption -----------------
def elgamal_encrypt(m, p, g, y):
    k = random.randint(1, p-2)        # Random ephemeral key
    c1 = pow(g, k, p)
    c2 = (m * pow(y, k, p)) % p
    return (c1, c2)

# ----------------- Decryption -----------------
def elgamal_decrypt(cipher, p, x):
    c1, c2 = cipher
    s = pow(c1, x, p)
    s_inv = number.inverse(s, p)       # Modular inverse
    m = (c2 * s_inv) % p
    return m

# ----------------- Homomorphic Multiplication -----------------
def elgamal_homomorphic_mult(c1, c2, p):
    # Multiply ciphertexts component-wise
    c1_new = (c1[0] * c2[0]) % p
    c2_new = (c1[1] * c2[1]) % p
    return (c1_new, c2_new)

# ----------------- Demo -----------------
p, g, y, x = elgamal_keygen()
m1, m2 = 5, 7
c1 = elgamal_encrypt(m1, p, g, y)
c2 = elgamal_encrypt(m2, p, g, y)
c_mult = elgamal_homomorphic_mult(c1, c2, p)
decrypted = elgamal_decrypt(c_mult, p, x)

print("ElGamal Homomorphic Multiplication Demo")
print("m1:", m1, "m2:", m2)
print("Decrypted m1*m2:", decrypted)  # Should be 35
