from Crypto.Util.number import *
import random
import time

# Generates the public parameters (a large prime p and a generator g).
def gen_public_params():
    p = getPrime(256)
    g = random.randrange(2, p-1)
    return g, p

# Generates a private key x and a public key G = g^x mod p.
def gen_params(g, p):
    # Private key 'x' is a random number.
    x = random.randrange(2, p-2)
    # Public key 'G' is computed using modular exponentiation.
    G = pow(g, x, p)
    return x, G

# Represents Alice in the key exchange.
class Alice:
    def __init__(self, g, p):
        self.g, self.p = g, p
        # Alice generates her own private key 'a' and public key 'A'.
        self.a, self.A = gen_params(g, p)
        self.shared_secret = None

    # Computes the shared secret using her private key and Bob's public key.
    def compute_shared_secret(self, B):
        # s = B^a mod p
        self.shared_secret = pow(B, self.a, self.p)
        return self.shared_secret

# Represents Bob in the key exchange.
class Bob:
    def __init__(self, g, p):
        self.g, self.p = g, p
        # Bob generates his own private key 'b' and public key 'B'.
        self.b, self.B = gen_params(g, p)
        self.shared_secret = None

    # Computes the shared secret using his private key and Alice's public key.
    def compute_shared_secret(self, A):
        # s = A^b mod p
        self.shared_secret = pow(A, self.b, self.p)
        return self.shared_secret

# --- EXECUTION AND TIMING ---
if __name__ == "__main__":
    # Time the generation of public parameters (p and g).
    t0 = time.time()
    g, p = gen_public_params()
    t1 = time.time()

    # Time the generation of key pairs for both Alice and Bob.
    t2 = time.time()
    alice = Alice(g, p)
    bob = Bob(g, p)
    t3 = time.time()

    # Time the computation of the shared secret by both parties.
    t4 = time.time()
    s_alice = alice.compute_shared_secret(bob.B)
    s_bob = bob.compute_shared_secret(alice.A)
    t5 = time.time()

    # --- PRINT RESULTS ---
    print("Public parameters:")
    print(f"  p (prime modulus): {p}")
    print(f"  g (generator): {g}\n")

    print("Timings (seconds):")
    print(f"  Public param generation: {t1 - t0:.6f}")
    print(f"  Keypair generation (Alice + Bob): {t3 - t2:.6f}")
    print(f"  Shared secret computation: {t5 - t4:.6f}\n")

    print("Key Exchange Values:")
    print(f"  Alice's public key A: {alice.A}")
    print(f"  Bob's public key   B: {bob.B}")
    print(f"  Alice's computed shared secret: {s_alice}")
    print(f"  Bob's computed shared secret  : {s_bob}")
    print(f"  Secrets are equal? -> {s_alice == s_bob}")

    # Verify correctness
    assert s_alice == s_bob