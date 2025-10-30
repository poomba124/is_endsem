import math
#pip install pycryptodome

# ------------------------------------------------------------
# 1️⃣ Helper Function: Modular Inverse
# ------------------------------------------------------------
def mod_inverse(a, m):
    """Compute modular inverse of a under modulo m using Extended Euclid Algorithm"""
    m0, x0, x1 = m, 0, 1
    if m == 1:
        return 0
    while a > 1:
        # q is quotient
        q = a // m
        a, m = m, a % m
        x0, x1 = x1 - q * x0, x0
    # Make x1 positive
    if x1 < 0:
        x1 += m0
    return x1


# ------------------------------------------------------------
# 2️⃣ Key Generation
# ------------------------------------------------------------
def generate_keys():
    """
    Generate RSA public and private keys.
    (For simplicity, use small primes — NOT secure for real use!)
    """
    # Pick two prime numbers
    p = 11
    q = 13

    # Compute n = p × q
    n = p * q

    # Compute φ(n) = (p−1)×(q−1)
    phi_n = (p - 1) * (q - 1)

    # Choose public exponent e such that gcd(e, φ(n)) = 1
    e = 7  # small public exponent for demonstration
    if math.gcd(e, phi_n) != 1:
        raise ValueError("e and φ(n) are not coprime!")

    # Compute private exponent d = e⁻¹ mod φ(n)
    d = mod_inverse(e, phi_n)

    # Public key (e, n), Private key (d, n)
    return (e, n), (d, n)


# ------------------------------------------------------------
# 3️⃣ Encryption
# ------------------------------------------------------------
def encrypt(m, public_key):
    """
    Encrypt plaintext integer m using RSA public key (e, n)
    c = m^e mod n
    """
    e, n = public_key
    c = pow(m, e, n)
    return c


# ------------------------------------------------------------
# 4️⃣ Decryption
# ------------------------------------------------------------
def decrypt(c, private_key):
    """
    Decrypt ciphertext integer c using RSA private key (d, n)
    m = c^d mod n
    """
    d, n = private_key
    m = pow(c, d, n)
    return m


# ------------------------------------------------------------
# 5️⃣ Main Demonstration
# ------------------------------------------------------------
def main():
    # Key Generation
    public_key, private_key = generate_keys()
    print("🔑 Public Key (e, n):", public_key)
    print("🔐 Private Key (d, n):", private_key)

    # Original numbers to encrypt
    m1 = 7
    m2 = 3
    print(f"\nOriginal numbers: m1 = {m1}, m2 = {m2}")

    # Encrypt both numbers
    c1 = encrypt(m1, public_key)
    c2 = encrypt(m2, public_key)
    print(f"\n🔒 Encrypted m1 (ciphertext): {c1}")
    print(f"🔒 Encrypted m2 (ciphertext): {c2}")

    # Multiplicative Homomorphism:
    # Multiply ciphertexts → corresponds to multiplying plaintexts
    e, n = public_key
    c_product = (c1 * c2) % n
    print(f"\n✖️ Encrypted product (c1 × c2 mod n): {c_product}")

    # Decrypt the encrypted product
    decrypted_product = decrypt(c_product, private_key)
    print(f"\n🔓 Decrypted result of multiplication: {decrypted_product}")

    # Check correctness
    expected_product = m1 * m2
    print(f"✅ Expected product: {expected_product}")
    if decrypted_product == expected_product:
        print("🎉 Multiplicative homomorphic property verified successfully!")
    else:
        print("❌ Something went wrong!")


# ------------------------------------------------------------
# Run Program
# ------------------------------------------------------------
if __name__ == "__main__":
    main()
