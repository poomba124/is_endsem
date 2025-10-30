from Crypto.Util.number import getPrime
import random

class DiffieHellman:
    def __init__(self, bits=512):
        # Generate a large prime p and a primitive root g
        self.p = getPrime(bits)
        self.g = 2  # small primitive root (works for most safe primes)

    def generate_private_key(self):
        # Private key is a random number
        return random.randint(2, self.p - 2)

    def generate_public_key(self, private_key):
        # Public key = g^private mod p
        return pow(self.g, private_key, self.p)

    def compute_shared_secret(self, received_public, private_key):
        # Shared secret = received_public^private mod p
        return pow(received_public, private_key, self.p)


if __name__ == "__main__":
    dh = DiffieHellman(bits=256)  # use smaller size for quick demo
    print("Diffie-Hellman parameters generated.")

    # Alice generates her keys
    alice_private = dh.generate_private_key()
    alice_public = dh.generate_public_key(alice_private)

    # Bob generates his keys
    bob_private = dh.generate_private_key()
    bob_public = dh.generate_public_key(bob_private)

    # Exchange and compute shared secrets
    alice_shared = dh.compute_shared_secret(bob_public, alice_private)
    bob_shared = dh.compute_shared_secret(alice_public, bob_private)

    print(f"Alice's Public Key: {alice_public}")
    print(f"Bob's Public Key:   {bob_public}")
    print(f"Alice's Shared Secret: {alice_shared}")
    print(f"Bob's Shared Secret:   {bob_shared}")

    assert alice_shared == bob_shared
    print("✅ Shared secret successfully established!")


#-------------------##-------------------#

from Crypto.Util.number import getPrime

class DiffieHellman:
    def __init__(self, bits=256):
        # Generate large prime p and generator g
        self.p = getPrime(bits)
        self.g = 2  # primitive root candidate

    def generate_public_key(self, private_key):
        return pow(self.g, private_key, self.p)

    def compute_shared_secret(self, received_public, private_key):
        return pow(received_public, private_key, self.p)


if __name__ == "__main__":
    dh = DiffieHellman(bits=256)
    print("Diffie-Hellman parameters:")
    print("p =", dh.p)
    print("g =", dh.g)

    # --- User input for private keys ---
    alice_private = int(input("\nEnter Alice's private key (integer): "))
    bob_private   = int(input("Enter Bob's private key (integer): "))

    # --- Compute public keys ---
    alice_public = dh.generate_public_key(alice_private)
    bob_public   = dh.generate_public_key(bob_private)

    print("\nAlice's Public Key:", alice_public)
    print("Bob's Public Key:  ", bob_public)

    # --- Compute shared secrets ---
    alice_shared = dh.compute_shared_secret(bob_public, alice_private)
    bob_shared   = dh.compute_shared_secret(alice_public, bob_private)

    print("\nAlice's Shared Secret:", alice_shared)
    print("Bob's Shared Secret:  ", bob_shared)

    if alice_shared == bob_shared:
        print("✅ Shared secret successfully established!")
    else:
        print("❌ Shared secret mismatch.")
