from Crypto.Util.number import getPrime, inverse, GCD, bytes_to_long, long_to_bytes
import hashlib
import random

# --- HASHING HELPER ---
# A standard function to hash a message using SHA-256.
def hash_message(msg: bytes):
    return bytes_to_long(hashlib.sha256(msg).digest())

# --- ELGAMAL DIGITAL SIGNATURE ---
class ElGamalSignature:
    # Generates the public and private keys.
    def generate_keys(self, bits=512):
        p = getPrime(bits)
        # The generator 'g' is a primitive root modulo p, 2 is a common choice.
        g = 2
        # The private key 'x' is a random secret number.
        x = random.randint(2, p - 2)
        # The public key 'h' is computed from the private key.
        h = pow(g, x, p)
        # Public key is (p, g, h), Private key is x.
        self.public_key = (p, g, h)
        self.private_key = x
        print("ElGamal keys generated.")

    # Creates a digital signature for a message using the private key.
    def sign(self, msg: bytes):
        p, g, h = self.public_key
        x = self.private_key
        
        # 1. Hash the message to get a number 'm'.
        m = hash_message(msg)
        
        # 2. Choose a secret random number 'k' for this signature only.
        k = random.randint(2, p - 2)
        while GCD(k, p - 1) != 1:
            k = random.randint(2, p - 2)
        
        # 3. Compute the two parts of the signature, r and s.
        r = pow(g, k, p)
        k_inv = inverse(k, p - 1)
        s = (k_inv * (m - x * r)) % (p - 1)
        
        # The signature is the pair (r, s).
        return (r, s)

    # Verifies a signature using the public key.
    def verify(self, msg: bytes, signature: tuple):
        p, g, h = self.public_key
        r, s = signature
        
        # 1. Hash the message to get the same number 'm'.
        m = hash_message(msg)
        
        # 2. Perform the verification check.
        # Check if (h^r * r^s) mod p is equal to g^m mod p.
        left_side = (pow(h, r, p) * pow(r, s, p)) % p
        right_side = pow(g, m, p)
        
        return left_side == right_side

# --- SCHNORR DIGITAL SIGNATURE ---
class SchnorrSignature:
    # Generates keys. q is a prime factor of p-1.
    def generate_keys(self, bits=512):
        q = getPrime(160)
        p = getPrime(bits)
        while (p - 1) % q != 0:
            p = getPrime(bits)
        
        # Find a generator g
        h_val = random.randint(2, p - 2)
        g = pow(h_val, (p - 1) // q, p)
        while g == 1:
             h_val = random.randint(2, p - 2)
             g = pow(h_val, (p - 1) // q, p)

        x = random.randint(2, q - 1)
        h = pow(g, x, p)
        self.public_key = (p, q, g, h)
        self.private_key = x
        print("\nSchnorr keys generated.")

    # Creates a signature for a message.
    def sign(self, msg: bytes):
        p, q, g, h = self.public_key
        x = self.private_key
        
        # 1. Choose a secret random number 'k'.
        k = random.randint(2, q - 1)
        r = pow(g, k, p)
        
        # 2. Hash the message concatenated with r.
        e = hash_message(msg + long_to_bytes(r))
        
        # 3. Compute the second part of the signature, s.
        s = (k - x * e) % q
        
        # The signature is (e, s).
        return (e, s)

    # Verifies a signature using the public key.
    def verify(self, msg: bytes, signature: tuple):
        p, q, g, h = self.public_key
        e, s = signature
        
        # 1. Compute a value 'rv' from the signature and public key.
        rv = (pow(g, s, p) * pow(h, e, p)) % p
        
        # 2. Hash the message concatenated with the computed rv.
        ev = hash_message(msg + long_to_bytes(rv))
        
        # 3. Check if the computed hash matches the 'e' from the signature.
        return ev == e

if __name__ == "__main__":
    message = b"This is a signed document."
    
    # --- ElGamal Demo ---
    elgamal = ElGamalSignature()
    elgamal.generate_keys()
    signature_elg = elgamal.sign(message)
    is_valid_elg = elgamal.verify(message, signature_elg)
    print(f"Message: '{message.decode()}'")
    print(f"ElGamal Signature (r, s): {signature_elg}")
    print(f"ElGamal Verification successful? -> {is_valid_elg}")
    assert is_valid_elg

    # --- Schnorr Demo ---
    schnorr = SchnorrSignature()
    schnorr.generate_keys()
    signature_sch = schnorr.sign(message)
    is_valid_sch = schnorr.verify(message, signature_sch)
    print(f"Message: '{message.decode()}'")
    print(f"Schnorr Signature (e, s): {signature_sch}")
    print(f"Schnorr Verification successful? -> {is_valid_sch}")
    assert is_valid_sch