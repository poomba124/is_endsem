import os
import time
import json
import hashlib
import random
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
from Crypto.Util.number import getPrime, inverse, bytes_to_long, long_to_bytes


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
        print("RSA keys generated.")

    def sign(self, msg: bytes):
        n, e = self.public_key
        d = self.private_key
        h = int.from_bytes(hashlib.sha512(msg).digest(), "big")
        return pow(h, d, n)

    def verify(self, msg: bytes, signature: int):
        n, e = self.public_key
        h = int.from_bytes(hashlib.sha512(msg).digest(), "big")
        return pow(signature, e, n) == h


# --------------------------
# AES ENCRYPTION/DECRYPTION
# --------------------------
class AESCipher:
    def __init__(self, key: bytes):
        self.key = key

    def encrypt_file(self, filepath: str):
        with open(filepath, "rb") as f:
            data = f.read()
        cipher = AES.new(self.key, AES.MODE_ECB)
        encrypted = cipher.encrypt(pad(data, AES.block_size))
        enc_path = filepath + ".enc"
        with open(enc_path, "wb") as f:
            f.write(encrypted)
        return enc_path

    def decrypt_file(self, enc_path: str):
        with open(enc_path, "rb") as f:
            encrypted = f.read()
        cipher = AES.new(self.key, AES.MODE_ECB)
        decrypted = unpad(cipher.decrypt(encrypted), AES.block_size)
        return decrypted


# --------------------------
# SYSTEM STORAGE
# --------------------------
patients_records = {}  # patient_name -> list of records
verification_log = []  # doctor verified info

AES_KEY = b'16ByteAESKey1234'  # 16 bytes for AES-128
aes_cipher = AESCipher(AES_KEY)
rsa = RSASignature()
rsa.generate_keys()


# --------------------------
# PATIENT MENU
# --------------------------
def patient_menu(patient_name: str):
    while True:
        print(f"\n--- Patient Menu ({patient_name}) ---")
        print("1. Upload Medical Record")
        print("2. View Past Records")
        print("3. Back")
        choice = input("Select option: ").strip()

        if choice == "1":
            filepath = input("Enter file path of medical record: ").strip()
            if not os.path.exists(filepath):
                print("File not found!")
                continue

            # Encrypt file
            enc_file = aes_cipher.encrypt_file(filepath)
            with open(filepath, "rb") as f:
                data = f.read()
            # Sign SHA512 hash
            signature = rsa.sign(data)
            timestamp = time.ctime()

            # Store record
            record = {"enc_file": enc_file, "signature": signature, "timestamp": timestamp}
            patients_records.setdefault(patient_name, []).append(record)
            print(f"Medical record uploaded and encrypted. Timestamp: {timestamp}")

        elif choice == "2":
            if patient_name not in patients_records or not patients_records[patient_name]:
                print("No records found.")
            else:
                for i, rec in enumerate(patients_records[patient_name], 1):
                    print(f"{i}. File: {rec['enc_file']}, Timestamp: {rec['timestamp']}")
        elif choice == "3":
            break
        else:
            print("Invalid option.")


# --------------------------
# DOCTOR MENU
# --------------------------
def doctor_menu():
    while True:
        print("\n--- Doctor Menu ---")
        print("1. View/Decrypt Patient Record")
        print("2. Back")
        choice = input("Select option: ").strip()

        if choice == "1":
            patient_name = input("Enter patient name: ").strip()
            if patient_name not in patients_records or not patients_records[patient_name]:
                print("No records found.")
                continue

            for i, rec in enumerate(patients_records[patient_name], 1):
                print(f"{i}. Encrypted File: {rec['enc_file']}, Timestamp: {rec['timestamp']}")

            sel = int(input("Select record number to decrypt: ").strip()) - 1
            if sel < 0 or sel >= len(patients_records[patient_name]):
                print("Invalid selection.")
                continue

            rec = patients_records[patient_name][sel]
            decrypted_data = aes_cipher.decrypt_file(rec["enc_file"])
            print("\nDecrypted Content:\n", decrypted_data.decode())

            # Compute SHA512 hash
            file_hash = hashlib.sha512(decrypted_data).hexdigest()
            # Verify signature
            is_verified = rsa.verify(decrypted_data, rec["signature"])
            print("SHA512 Hash:", file_hash)
            print("RSA Signature Verified?", is_verified)

            # Log verification
            verification_log.append({
                "patient": patient_name,
                "file": rec['enc_file'],
                "hash": file_hash,
                "verified": is_verified,
                "timestamp": time.ctime()
            })

        elif choice == "2":
            break
        else:
            print("Invalid option.")


# --------------------------
# AUDITOR MENU
# --------------------------
def auditor_menu():
    print("\n--- Auditor Menu (Read-Only) ---")
    print("\nAll Patient Records:")
    for pname, recs in patients_records.items():
        print(f"\nPatient: {pname}")
        for r in recs:
            print(f"File: {r['enc_file']}, Timestamp: {r['timestamp']}, Signature: {r['signature']}")

    print("\nAll Verification Logs:")
    for log in verification_log:
        print(log)


# --------------------------
# MAIN MENU
# --------------------------
def main_menu():
    while True:
        print("\n=== Hospital Management System ===")
        print("1. Patient")
        print("2. Doctor")
        print("3. Auditor")
        print("4. Exit")
        choice = input("Select role: ").strip()

        if choice == "1":
            pname = input("Enter patient name: ").strip()
            patient_menu(pname)
        elif choice == "2":
            doctor_menu()
        elif choice == "3":
            auditor_menu()
        elif choice == "4":
            break
        else:
            print("Invalid option.")


if __name__ == "__main__":
    main_menu()


#-----------------------------##------------------------------#

import time
import hashlib
import random
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
from Crypto.Util.number import getPrime, inverse, bytes_to_long, long_to_bytes


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
        print("RSA keys generated.")

    def sign(self, msg: bytes):
        n, e = self.public_key
        d = self.private_key
        h = int.from_bytes(hashlib.sha512(msg).digest(), "big")
        return pow(h, d, n)

    def verify(self, msg: bytes, signature: int):
        n, e = self.public_key
        h = int.from_bytes(hashlib.sha512(msg).digest(), "big")
        return pow(signature, e, n) == h


# --------------------------
# AES ENCRYPTION/DECRYPTION
# --------------------------
class AESCipher:
    def __init__(self, key: bytes):
        self.key = key

    def encrypt(self, data: bytes):
        cipher = AES.new(self.key, AES.MODE_ECB)
        encrypted = cipher.encrypt(pad(data, AES.block_size))
        return encrypted

    def decrypt(self, encrypted: bytes):
        cipher = AES.new(self.key, AES.MODE_ECB)
        decrypted = unpad(cipher.decrypt(encrypted), AES.block_size)
        return decrypted


# --------------------------
# SYSTEM STORAGE
# --------------------------
patients_records = {}  # patient_name -> list of records
verification_log = []  # doctor verified info

AES_KEY = b'16ByteAESKey1234'  # 16 bytes for AES-128
aes_cipher = AESCipher(AES_KEY)
rsa = RSASignature()
rsa.generate_keys()


# --------------------------
# PATIENT MENU
# --------------------------
def patient_menu(patient_name: str):
    while True:
        print(f"\n--- Patient Menu ({patient_name}) ---")
        print("1. Upload Medical Record (as string)")
        print("2. View Past Records")
        print("3. Back")
        choice = input("Select option: ").strip()

        if choice == "1":
            record_str = input("Enter your medical record: ").strip()
            data_bytes = record_str.encode()

            # Encrypt the record
            encrypted_data = aes_cipher.encrypt(data_bytes)

            # Sign SHA512 hash
            signature = rsa.sign(data_bytes)
            timestamp = time.ctime()

            # Store record
            record = {
                "encrypted_data": encrypted_data,
                "signature": signature,
                "timestamp": timestamp,
                "original": record_str  # optional for patient view
            }
            patients_records.setdefault(patient_name, []).append(record)
            print(f"Medical record uploaded and encrypted. Timestamp: {timestamp}")

        elif choice == "2":
            if patient_name not in patients_records or not patients_records[patient_name]:
                print("No records found.")
            else:
                for i, rec in enumerate(patients_records[patient_name], 1):
                    print(
                        f"{i}. Timestamp: {rec['timestamp']}, Encrypted Data Length: {len(rec['encrypted_data'])} bytes")
        elif choice == "3":
            break
        else:
            print("Invalid option.")


# --------------------------
# DOCTOR MENU
# --------------------------
def doctor_menu():
    while True:
        print("\n--- Doctor Menu ---")
        print("1. View/Decrypt Patient Record")
        print("2. Back")
        choice = input("Select option: ").strip()

        if choice == "1":
            patient_name = input("Enter patient name: ").strip()
            if patient_name not in patients_records or not patients_records[patient_name]:
                print("No records found.")
                continue

            for i, rec in enumerate(patients_records[patient_name], 1):
                print(f"{i}. Timestamp: {rec['timestamp']}, Encrypted Data Length: {len(rec['encrypted_data'])} bytes")

            sel = int(input("Select record number to decrypt: ").strip()) - 1
            if sel < 0 or sel >= len(patients_records[patient_name]):
                print("Invalid selection.")
                continue

            rec = patients_records[patient_name][sel]
            decrypted_data = aes_cipher.decrypt(rec["encrypted_data"])
            print("\nDecrypted Content:\n", decrypted_data.decode())

            # Compute SHA512 hash
            file_hash = hashlib.sha512(decrypted_data).hexdigest()
            # Verify signature
            is_verified = rsa.verify(decrypted_data, rec["signature"])
            print("SHA512 Hash:", file_hash)
            print("RSA Signature Verified?", is_verified)

            # Log verification
            verification_log.append({
                "patient": patient_name,
                "hash": file_hash,
                "verified": is_verified,
                "timestamp": time.ctime()
            })

        elif choice == "2":
            break
        else:
            print("Invalid option.")


# --------------------------
# AUDITOR MENU
# --------------------------
def auditor_menu():
    print("\n--- Auditor Menu (Read-Only) ---")
    print("\nAll Patient Records:")
    for pname, recs in patients_records.items():
        print(f"\nPatient: {pname}")
        for r in recs:
            print(
                f"Encrypted Data Length: {len(r['encrypted_data'])} bytes, Timestamp: {r['timestamp']}, Signature: {r['signature']}")

    print("\nAll Verification Logs:")
    for log in verification_log:
        print(log)


# --------------------------
# MAIN MENU
# --------------------------
def main_menu():
    while True:
        print("\n=== Hospital Management System ===")
        print("1. Patient")
        print("2. Doctor")
        print("3. Auditor")
        print("4. Exit")
        choice = input("Select role: ").strip()

        if choice == "1":
            pname = input("Enter patient name: ").strip()
            patient_menu(pname)
        elif choice == "2":
            doctor_menu()
        elif choice == "3":
            auditor_menu()
        elif choice == "4":
            break
        else:
            print("Invalid option.")


if __name__ == "__main__":
    main_menu()




