import time
import json
from Crypto.Util.number import getPrime, inverse, GCD, bytes_to_long, long_to_bytes
import random
import hashlib


# --------------------------
# EL GAMAL SIGNATURE CLASS
# --------------------------
class ElGamalSignature:
    def generate_keys(self, bits=256):
        p = getPrime(bits)
        g = 2
        x = random.randint(2, p - 2)
        h = pow(g, x, p)
        self.public_key = (p, g, h)
        self.private_key = x

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
# RSA FUNCTIONS
# --------------------------
def generate_rsa_keys(bits=512):
    p = getPrime(bits // 2)
    q = getPrime(bits // 2)
    n = p * q
    phi = (p - 1) * (q - 1)
    e = 65537
    while phi % e == 0:
        e = random.randrange(2, phi)
    d = inverse(e, phi)
    return (n, e), d


def rsa_encrypt(message: str, public_key):
    n, e = public_key
    m = bytes_to_long(message.encode())
    c = pow(m, e, n)
    return c


def rsa_decrypt(ciphertext: int, private_key, n):
    m = pow(ciphertext, private_key, n)
    return long_to_bytes(m).decode()


# --------------------------
# TRANSACTION RECORD
# --------------------------
transactions = []


# --------------------------
# CLIENT SIDE
# --------------------------
def client_send_payment():
    print("\n--- CLIENT SIDE ---")
    payment_info = input("Enter payment details (Card/Amount/ID): ")
    timestamp = time.ctime()

    # RSA Encryption
    rsa_cipher = rsa_encrypt(payment_info, merchant_rsa_public)

    # ElGamal signature
    signature = client_eg.sign(payment_info.encode())

    # Record transaction
    tx = {
        "payment_encrypted": rsa_cipher,
        "eg_signature": signature,
        "timestamp": timestamp,
        "plaintext": payment_info
    }
    transactions.append(tx)

    print("Payment sent securely with RSA encryption and ElGamal signature.")


# --------------------------
# MERCHANT SIDE
# --------------------------
def merchant_receive_payment():
    print("\n--- MERCHANT SIDE ---")
    for i, tx in enumerate(transactions):
        print(f"\nTransaction {i + 1}:")
        # RSA Decrypt
        decrypted = rsa_decrypt(tx["payment_encrypted"], merchant_rsa_private, merchant_rsa_public[0])
        print("Decrypted Payment Info:", decrypted)

        # Verify signature
        valid = client_eg.verify(decrypted.encode(), tx["eg_signature"])
        print("ElGamal Signature Valid?:", valid)
        print("Timestamp:", tx["timestamp"])


# --------------------------
# AUDITOR SIDE
# --------------------------
def auditor_view():
    print("\n--- AUDITOR VIEW (Read-Only) ---")
    for i, tx in enumerate(transactions):
        print(f"\nTransaction {i + 1}:")
        print("Encrypted Payment (RSA):", tx["payment_encrypted"])
        print("ElGamal Signature:", tx["eg_signature"])
        print("Timestamp:", tx["timestamp"])


# --------------------------
# SETUP KEYS
# --------------------------
client_eg = ElGamalSignature()
client_eg.generate_keys()

merchant_rsa_public, merchant_rsa_private = generate_rsa_keys()


# --------------------------
# MENU LOOP
# --------------------------
def main_menu():
    while True:
        print("\n--- SECURE PAYMENT SYSTEM ---")
        print("1. Client: Send Payment")
        print("2. Merchant: Receive & Verify Payment")
        print("3. Auditor: View Transactions (Read-Only)")
        print("4. Exit")
        choice = input("Select option: ").strip()
        if choice == "1":
            client_send_payment()
        elif choice == "2":
            merchant_receive_payment()
        elif choice == "3":
            auditor_view()
        elif choice == "4":
            break
        else:
            print("Invalid option. Try again.")


if __name__ == "__main__":
    main_menu()
