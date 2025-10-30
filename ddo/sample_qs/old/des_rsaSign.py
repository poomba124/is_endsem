from Crypto.Cipher import DES
from Crypto.Util.Padding import pad, unpad
from Crypto.Util.number import getPrime, inverse, bytes_to_long, long_to_bytes
import random
import hashlib
import binascii

# --------------------------
# RSA SIGNATURE FUNCTIONS
# --------------------------
def generate_rsa_keys(bits=512):
    p = getPrime(bits//2)
    q = getPrime(bits//2)
    n = p * q
    phi = (p-1)*(q-1)
    e = 65537
    while GCD(phi, e) != 1:
        e = random.randrange(2, phi)
    d = inverse(e, phi)
    return (n, e), d

def rsa_sign(message: str, private_key, n):
    m = bytes_to_long(message.encode())
    signature = pow(m, private_key, n)
    return signature

def rsa_verify(message: str, signature, public_key):
    n, e = public_key
    m_check = pow(signature, e, n)
    return m_check == bytes_to_long(message.encode())

# --------------------------
# DES ENCRYPTION/DECRYPTION
# --------------------------
def des_encrypt(message: str, key: bytes) -> bytes:
    cipher = DES.new(key, DES.MODE_ECB)
    padded = pad(message.encode(), DES.block_size)
    ciphertext = cipher.encrypt(padded)
    return ciphertext

def des_decrypt(ciphertext: bytes, key: bytes) -> str:
    cipher = DES.new(key, DES.MODE_ECB)
    decrypted = unpad(cipher.decrypt(ciphertext), DES.block_size)
    return decrypted.decode()

# --------------------------
# UTILS
# --------------------------
def GCD(a, b):
    while b:
        a, b = b, a % b
    return a

# --------------------------
# TRANSACTION STORAGE
# --------------------------
transactions = []

# DES key (8 bytes)
DES_KEY = b'8ByteKey'

# RSA keys for customer
customer_rsa_pub, customer_rsa_priv = generate_rsa_keys()

# --------------------------
# CUSTOMER SIDE
# --------------------------
def customer_menu():
    while True:
        print("\n--- Customer Menu ---")
        print("1. Send Secure Message")
        print("2. View Previous Transactions")
        print("3. Back to Main Menu")
        choice = input("Choose option: ").strip()

        if choice == "1":
            msg = input("Enter your message/payment details: ")
            encrypted = des_encrypt(msg, DES_KEY)
            signature = rsa_sign(msg, customer_rsa_priv, customer_rsa_pub[0])
            transactions.append({
                "ciphertext": encrypted,
                "signature": signature,
                "plaintext": msg
            })
            print("Message sent securely!")
        elif choice == "2":
            if not transactions:
                print("No transactions yet.")
            else:
                for i, tx in enumerate(transactions):
                    print(f"{i+1}. Plaintext: {tx['plaintext']}")
        elif choice == "3":
            break
        else:
            print("Invalid option.")

# --------------------------
# OFFICER SIDE
# --------------------------
def officer_menu():
    if not transactions:
        print("No transactions to view.")
        return

    for i, tx in enumerate(transactions):
        print(f"\n--- Transaction {i+1} ---")
        ciphertext_hex = binascii.hexlify(tx["ciphertext"]).decode()
        print("Cipher Text (Hex):", ciphertext_hex)
        try:
            decrypted = des_decrypt(tx["ciphertext"], DES_KEY)
        except ValueError:
            print("Decryption failed!")
            continue
        verified = rsa_verify(decrypted, tx["signature"], customer_rsa_pub)
        print("Decrypted Message:", decrypted)
        print("RSA Signature Verified?", verified)

# --------------------------
# MAIN MENU
# --------------------------
def main():
    while True:
        print("\n=== SecureBank Menu ===")
        print("1. Customer")
        print("2. Officer")
        print("3. Exit")
        choice = input("Select option: ").strip()

        if choice == "1":
            customer_menu()
        elif choice == "2":
            officer_menu()
        elif choice == "3":
            break
        else:
            print("Invalid option.")

if __name__ == "__main__":
    main()
