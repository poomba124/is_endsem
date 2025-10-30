import random
import math
#PIP INSTALL PHE
# ------------------------------------------------------------
# 1️⃣ Helper Functions
# ------------------------------------------------------------

def lcm(x, y):
    """Compute Least Common Multiple (LCM) of x and y."""
    return x * y // math.gcd(x, y)

def L(u, n):
    """Paillier's L function: L(u) = (u - 1) // n"""
    return (u - 1) // n


# ------------------------------------------------------------
# 2️⃣ Key Generation
# ------------------------------------------------------------
def generate_keys():
    """
    Generate public and private keys for Paillier encryption.
    For simplicity, we'll use small primes (NOT secure for real use).
    """

    # Choose two prime numbers p and q
    p = 17
    q = 19

    # Compute n and n^2
    n = p * q
    n_sq = n * n

    # λ = lcm(p−1, q−1)
    lam = lcm(p - 1, q - 1)

    # Choose g = n + 1 (common trick for simplicity)
    g = n + 1

    # μ = (L(g^λ mod n²))⁻¹ mod n
    x = pow(g, lam, n_sq)
    Lx = L(x, n)
    mu = pow(Lx, -1, n)  # modular multiplicative inverse

    # Public key = (n, g)
    public_key = (n, g)
    # Private key = (λ, μ)
    private_key = (lam, mu)

    return public_key, private_key


# ------------------------------------------------------------
# 3️⃣ Encryption
# ------------------------------------------------------------
def encrypt(m, public_key):
    """
    Encrypt plaintext m using public key (n, g)
    c = g^m * r^n mod n²
    """
    n, g = public_key
    n_sq = n * n

    # Choose random r in [1, n-1] such that gcd(r, n) = 1
    while True:
        r = random.randint(1, n - 1)
        if math.gcd(r, n) == 1:
            break

    # c = (g^m * r^n) mod n²
    c1 = pow(g, m, n_sq)
    c2 = pow(r, n, n_sq)
    c = (c1 * c2) % n_sq

    return c


# ------------------------------------------------------------
# 4️⃣ Decryption
# ------------------------------------------------------------
def decrypt(c, public_key, private_key):
    """
    Decrypt ciphertext c using private key (λ, μ)
    m = L(c^λ mod n²) × μ mod n
    """
    n, g = public_key
    lam, mu = private_key
    n_sq = n * n

    # u = c^λ mod n²
    u = pow(c, lam, n_sq)
    L_u = L(u, n)
    m = (L_u * mu) % n

    return m


# ------------------------------------------------------------
# 5️⃣ Main Demonstration
# ------------------------------------------------------------
def main():
    # Generate keys
    public_key, private_key = generate_keys()
    print("🔑 Public Key (n, g):", public_key)
    print("🔐 Private Key (λ, μ):", private_key)

    # Original messages
    m1 = 15
    m2 = 25
    print(f"\nOriginal numbers: m1 = {m1}, m2 = {m2}")

    # Encrypt both numbers
    c1 = encrypt(m1, public_key)
    c2 = encrypt(m2, public_key)
    print(f"\n🔒 Encrypted m1 (ciphertext): {c1}")
    print(f"🔒 Encrypted m2 (ciphertext): {c2}")

    # Homomorphic addition (without decrypting)
    n, g = public_key
    n_sq = n * n
    c_sum = (c1 * c2) % n_sq
    print(f"\n➕ Homomorphic addition (encrypted): {c_sum}")

    # Decrypt the result of the addition
    decrypted_sum = decrypt(c_sum, public_key, private_key)
    print(f"\n🔓 Decrypted result of addition: {decrypted_sum}")

    # Verify
    expected_sum = m1 + m2
    print(f"✅ Expected sum: {expected_sum}")
    if decrypted_sum == expected_sum:
        print("🎉 Homomorphic addition verified successfully!")
    else:
        print("❌ Something went wrong!")


# ------------------------------------------------------------
# Run the program
# ------------------------------------------------------------
if __name__ == "__main__":
    main()
