from Crypto.Util.number import *
import random

# --- KEY GENERATION ---
# 1. Choose a large prime p and a generator g.
p = getPrime(256)
g = 2
# 2. Choose a private key x, which is a random integer.
x = random.randint(1, p-2)
# 3. Compute the public key h = g^x mod p.
h = pow(g, x, p)

# Assemble the keys.
public_key = (p, g, h)
private_key = x
message = b'Confidential Data'

# Encrypts a message using the ElGamal public key.
def encrypt(m, pubkey):
    p, g, h = pubkey
    # Convert the message to a large integer.
    m_long = bytes_to_long(m)
    # Choose a random secret number k for this encryption session.
    k = random.randint(1, p-2)

    # The ciphertext consists of two parts, c1 and c2.
    # c1 = g^k mod p
    c1 = pow(g, k, p)
    # c2 = (m * h^k) mod p
    c2 = (m_long * pow(h, k, p)) % p
    return (c1, c2)

# Decrypts an ElGamal ciphertext using the private key.
def decrypt(c, privkey_x, p):
    c1, c2 = c
    # Compute the shared secret s = c1^x mod p.
    s = pow(c1, privkey_x, p)
    # Recover the message by computing m = (c2 * s^-1) mod p.
    # s^-1 is the modular multiplicative inverse of s.
    m_long = (c2 * inverse(s, p)) % p
    return long_to_bytes(m_long)

# --- EXECUTION ---
print("Public Parameters:")
print(f"p = {public_key[0]}")
print(f"g = {public_key[1]}")
print(f"h = {public_key[2]}")

# Encrypt the message.
c = encrypt(message, public_key)
print(f"\nEncrypted Ciphertext (c1, c2): {c}")

# Decrypt the ciphertext.
pt = decrypt(c, private_key, p)
print(f"Decrypted Plaintext: {pt.decode()}")

# Verify correctness.
assert pt == message


from Crypto.Util.number import *
import random

# --- ENCRYPTION FUNCTION ---
def encrypt(m, pubkey):
    p, g, h = pubkey
    m_long = bytes_to_long(m)
    k = random.randint(1, p-2)
    c1 = pow(g, k, p)
    c2 = (m_long * pow(h, k, p)) % p
    return (c1, c2)

# --- DECRYPTION FUNCTION ---
def decrypt(c, privkey_x, p):
    c1, c2 = c
    s = pow(c1, privkey_x, p)
    m_long = (c2 * inverse(s, p)) % p
    return long_to_bytes(m_long)

# --- USER INPUT SECTION ---
print("ElGamal Encryption/Decryption System")
print("====================================")

# 1️⃣ Message input
msg_input = input("\nEnter a message to encrypt: ")
message = msg_input.encode()

# 2️⃣ Choose key generation mode
choice = input("Enter 'A' to auto-generate p and g, or 'M' to manually enter: ").strip().upper()

if choice == 'M':
    try:
        p = int(input("Enter a prime number p: "))
        if not isPrime(p):
            print("⚠️ Not a prime number! Generating random 256-bit prime instead.")
            p = getPrime(256)
        g = int(input("Enter generator g (default 2): ") or 2)
    except ValueError:
        print("⚠️ Invalid input, generating default parameters.")
        p = getPrime(256)
        g = 2
else:
    p = getPrime(256)
    g = 2

# 3️⃣ Generate private and public keys
x = random.randint(1, p-2)        # Private key
h = pow(g, x, p)                  # Public key part
public_key = (p, g, h)
private_key = x

# --- DISPLAY KEYS ---
print("\n--- PUBLIC PARAMETERS ---")
print(f"Prime (p) = {p}")
print(f"Generator (g) = {g}")
print(f"Public key (h) = {h}")
print(f"Private key (x) = {x}")

# --- ENCRYPTION ---
c = encrypt(message, public_key)
print("\n--- ENCRYPTION ---")
print(f"Ciphertext (c1, c2): {c}")

# --- DECRYPTION ---
pt = decrypt(c, private_key, p)
print("\n--- DECRYPTION ---")
print(f"Decrypted message: {pt.decode()}")

# --- VERIFICATION ---
assert pt == message, "❌ Decryption failed!"
print("\n✅ Decryption successful! Message verified.")



