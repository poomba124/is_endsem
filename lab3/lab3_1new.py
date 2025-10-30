from Crypto.Util.number import *

# Encrypts a message using an RSA public key (n, e).
def encrypt(m, pubkey):
    # Unpack the public key
    n, e = pubkey
    # Convert message bytes to a large integer, then perform modular exponentiation: c = m^e mod n
    return long_to_bytes(pow(bytes_to_long(m), e, n))

# Decrypts a ciphertext using an RSA private key (n, d).
def decrypt(c, privkey):
    # Unpack the private key
    n, d = privkey
    # Convert ciphertext bytes to a large integer, then perform modular exponentiation: m = c^d mod n
    return long_to_bytes(pow(bytes_to_long(c), d, n))

# --- KEY GENERATION AND EXECUTION ---
# The message to be encrypted
msg = b'Asymmetric Encryption'

# 1. Generate two large 1024-bit prime numbers, p and q.
p, q = getPrime(1024), getPrime(1024)
# 2. Calculate the modulus n by multiplying p and q.
n = p * q
# 3. Choose the public exponent e (a common choice is 65537).
e = 0x10001
# 4. Calculate the private exponent d, which is the modular multiplicative inverse of e mod phi(n).
phi = (p-1)*(q-1)
d = inverse(e, phi)

# Assemble the public and private keys into tuples.
pubkey = (n, e)
privkey = (n, d)

# Encrypt the message using the public key.
ct = encrypt(msg, pubkey)
print(f"Ciphertext (bytes): {ct}")

# Decrypt the ciphertext using the private key.
pt = decrypt(ct, privkey)
print(f"Decrypted: {pt.decode()}")

# Verify that the decrypted plaintext matches the original message.
assert pt == msg, "Decryption failed!"



from Crypto.Util.number import *

# Encrypts a message using an RSA public key (n, e)
def encrypt(m, pubkey):
    n, e = pubkey
    return long_to_bytes(pow(bytes_to_long(m), e, n))

# Decrypts a ciphertext using an RSA private key (n, d)
def decrypt(c, privkey):
    n, d = privkey
    return long_to_bytes(pow(bytes_to_long(c), d, n))

# --- KEY GENERATION AND EXECUTION ---

# 1. Take user input for message
msg_input = input("Enter a message to encrypt: ")
msg = msg_input.encode()

# 2. Take input for two prime numbers p and q
while True:
    try:
        p = int(input("Enter a prime number p: "))
        q = int(input("Enter another prime number q: "))
        if isPrime(p) and isPrime(q):
            break
        else:
            print("❌ Both numbers must be prime. Try again.\n")
    except ValueError:
        print("❌ Please enter valid integers.\n")

# 3. Compute modulus and totient
n = p * q
phi = (p - 1) * (q - 1)

# 4. Choose public exponent e
e = 0x10001  # 65537

# 5. Compute private exponent d
d = inverse(e, phi)

# Assemble keys
pubkey = (n, e)
privkey = (n, d)

# 6. Encrypt message
ct = encrypt(msg, pubkey)
print("\n--- ENCRYPTION ---")
print("Ciphertext (bytes):", ct)

# 7. Decrypt message
pt = decrypt(ct, privkey)
print("\n--- DECRYPTION ---")
print("Decrypted message:", pt.decode())

# 8. Verify correctness
assert pt == msg, "Decryption failed!"
print("\n✅ Decryption successful! Message verified.")

p = 1125899906842597
q = 1125899906842679

