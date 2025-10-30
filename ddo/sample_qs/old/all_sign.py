from Crypto.Util.number import getPrime, inverse, GCD, bytes_to_long, long_to_bytes
from ecdsa import SigningKey, NIST256p
import hashlib
import random

# --------------------------
# RSA SIGNATURE
# --------------------------
class RSASignature:
    def generate_keys(self, bits=1024):
        p = getPrime(bits // 2)
        q = getPrime(bits // 2)
        n = p * q
        phi = (p - 1) * (q - 1)

        e = 65537
        while phi % e == 0:
            e = random.randrange(2, phi)
        d = inverse(e, phi)

        self.public_key = (n, e)
        self.private_key = d
        print("\nRSA keys generated.")

    def sign(self, msg: bytes):
        n, e = self.public_key
        d = self.private_key
        h = int.from_bytes(hashlib.sha256(msg).digest(), "big")
        return pow(h, d, n)

    def verify(self, msg: bytes, signature: int):
        n, e = self.public_key
        h = int.from_bytes(hashlib.sha256(msg).digest(), "big")
        return pow(signature, e, n) == h

# --------------------------
# ECDSA SIGNATURE
# --------------------------
class ECDSASignature:
    def generate_keys(self):
        self.sk = SigningKey.generate(curve=NIST256p)   # private key
        self.vk = self.sk.verifying_key                 # public key
        print("\nECDSA keys generated.")

    def sign(self, msg: bytes):
        return self.sk.sign(msg)

    def verify(self, msg: bytes, signature: bytes):
        return self.vk.verify(signature, msg)

# --------------------------
# EL GAMAL SIGNATURE
# --------------------------
class ElGamalSignature:
    def generate_keys(self, bits=512):
        p = getPrime(bits)
        g = 2
        x = random.randint(2, p - 2)
        h = pow(g, x, p)
        self.public_key = (p, g, h)
        self.private_key = x
        print("\nElGamal keys generated.")

    def hash_message(self, msg: bytes):
        return bytes_to_long(hashlib.sha256(msg).digest())

    def sign(self, msg: bytes):
        p, g, h = self.public_key
        x = self.private_key
        m = self.hash_message(msg)
        k = random.randint(2, p - 2)
        while GCD(k, p - 1) != 1:
            k = random.randint(2, p - 2)
        r = pow(g, k, p)
        k_inv = inverse(k, p - 1)
        s = (k_inv * (m - x * r)) % (p - 1)
        return (r, s)

    def verify(self, msg: bytes, signature: tuple):
        p, g, h = self.public_key
        r, s = signature
        m = self.hash_message(msg)
        left = (pow(h, r, p) * pow(r, s, p)) % p
        right = pow(g, m, p)
        return left == right

# --------------------------
# DEMO
# --------------------------
if __name__ == "__main__":
    #message = b"This is a signed document."
    message = input("Enter the message to sign: ").encode()

    # RSA
    rsa = RSASignature()
    rsa.generate_keys()
    sig_rsa = rsa.sign(message)
    print(f"\nRSA Signature: {sig_rsa}")
    print("RSA Verified?", rsa.verify(message, sig_rsa))

    # ECDSA
    ecdsa = ECDSASignature()
    ecdsa.generate_keys()
    sig_ecdsa = ecdsa.sign(message)
    print(f"\nECDSA Signature (hex): {sig_ecdsa.hex()}")
    print("ECDSA Verified?", ecdsa.verify(message, sig_ecdsa))

    # ElGamal
    elgamal = ElGamalSignature()
    elgamal.generate_keys()
    sig_elg = elgamal.sign(message)
    print(f"\nElGamal Signature (r, s): {sig_elg}")
    print("ElGamal Verified?", elgamal.verify(message, sig_elg))
