import socket
import pickle
import json
import hashlib
import time
import getpass
from Crypto.Util import number
from Crypto.Util.number import bytes_to_long, inverse, long_to_bytes
from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP, AES
from Crypto.Hash import SHA256
from Crypto.Random import get_random_bytes

# --- Global Configurations ---
HOST = "127.0.0.1"
PORT = 65432
KEY_BITS = 2048
KEY_BYTE_LENGTH = KEY_BITS // 8
REPORT_FILE = "medical_report.txt"

# --- Client State ---
CLIENT_ID = None
CLIENT_DEPT = None
ELGAMAL_SIGN_KEYS = None


# --- Cryptographic Helpers ---

def hash_message(msg: bytes):
    """Generates SHA-256 hash (used for indexing and signing)."""
    return bytes_to_long(SHA256.new(msg).digest())


def generate_elgamal_sign_keys(p, g):
    """Generates ElGamal signing keys using server's params (p, g)."""
    p_minus_1 = p - 1
    a = number.getRandomRange(2, p_minus_1)
    y_a = pow(g, a, p)

    return ((p, g, y_a), a)


def elgamal_sign(msg_hash, private_key, p, g):
    """Generates an ElGamal signature (r, s)."""
    a = private_key
    p_minus_1 = p - 1

    while True:
        k = number.getRandomRange(2, p_minus_1)
        if math.gcd(k, p_minus_1) == 1:
            break

    # r = g^k mod p
    r = pow(g, k, p)

    # s = (msg_hash - a*r) * k^-1 mod (p-1)
    k_inv = inverse(k, p_minus_1)
    s = ((msg_hash - a * r) % p_minus_1) * k_inv % p_minus_1

    return (r, s)


def rsa_he_encrypt(plaintext, public_key):
    """RSA Multiplicative Homomorphic Encryption: c = m^e mod n."""
    n, e = public_key

    # Textbooks require m < n for proper decryption, and m must be a number
    if plaintext >= n:
        raise ValueError(f"Plaintext {plaintext} is too large for RSA HE modulus N.")

    return pow(plaintext, e, n)


def rsa_encrypt_aes_key(aes_key, rsa_pub_n, rsa_pub_e):
    """Encrypts the AES key using Auditor's RSA public key (PKCS1_OAEP)."""
    rsa_pub = RSA.construct((rsa_pub_n, rsa_pub_e))
    cipher_rsa = PKCS1_OAEP.new(rsa_pub)
    return cipher_rsa.encrypt(aes_key)


def aes_encrypt_report(report_text, aes_key):
    """Encrypts the report contents using AES-256 GCM (Authenticated)."""
    cipher_aes = AES.new(aes_key, AES.MODE_GCM)
    ciphertext, tag = cipher_aes.encrypt_and_digest(report_text.encode('utf-8'))
    # Return nonce, ciphertext, and authentication tag
    return cipher_aes.nonce, ciphertext, tag


# --- Socket Communication Helpers ---
def recv_all(conn):
    """Receives data over socket using length prefixing."""
    length_bytes = conn.recv(8)
    if not length_bytes: return None

    data_len = int.from_bytes(length_bytes, 'big')

    chunks = []
    bytes_recd = 0
    while bytes_recd < data_len:
        chunk = conn.recv(min(data_len - bytes_recd, 4096))
        if not chunk:
            raise ConnectionResetError("Connection lost before receiving full payload.")
        chunks.append(chunk)
        bytes_recd += len(chunk)

    return pickle.loads(b"".join(chunks))


def send_data(conn, data):
    """Sends data over socket using length prefixing."""
    serialized_data = pickle.dumps(data)
    conn.sendall(len(serialized_data).to_bytes(8, 'big'))
    conn.sendall(serialized_data)


# --- Client Menu Functions ---

def menu_register_doctor():
    """Handles client registration and key setup."""
    global CLIENT_ID, CLIENT_DEPT, ELGAMAL_SIGN_KEYS

    print("\n--- DOCTOR REGISTRATION ---")

    # Input and Validation
    if CLIENT_ID:
        print(f"Doctor {CLIENT_ID} is already registered.")
        return

    CLIENT_ID = input("Enter Doctor ID (e.g., DoctorA): ").strip()
    CLIENT_DEPT = input("Enter Department (e.g., Cardiology): ").strip()

    if not CLIENT_ID or not CLIENT_DEPT:
        print("[ERROR] ID and Department cannot be empty.")
        CLIENT_ID = None
        return

    # 1. Connect to get ElGamal Parameters for signing key generation
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.connect((HOST, PORT))

            # Send initial signature size placeholder
            s.sendall(b'\x00' * KEY_BYTE_LENGTH * 2)

            # Receive Auditor's Public Keys
            received_keys = recv_all(s)

            if not received_keys:
                print("[ERROR] Failed to receive keys from Auditor.")
                return

            elgamal_params = received_keys['elgamal_params']
            p, g = elgamal_params

            # 2. Generate ElGamal Signing Keys using server's params
            ELGAMAL_SIGN_KEYS = generate_elgamal_sign_keys(p, g)
            print(f"[SUCCESS] Doctor {CLIENT_ID} registered with Department: {CLIENT_DEPT}")
            print(f"Generated ElGamal Signing Keys based on Auditor's parameters.")

    except ConnectionRefusedError:
        print("\n[ERROR] Connection refused. Make sure the Auditor Server is running!")
    except Exception as e:
        print(f"\n[CRITICAL ERROR] Registration failed: {e}")


def menu_submit_report():
    """Handles report submission, encryption, signing, and transmission."""
    global CLIENT_ID, CLIENT_DEPT, ELGAMAL_SIGN_KEYS

    if not CLIENT_ID:
        print("[ERROR] Please register first (Option 1).")
        return

    print("\n--- REPORT SUBMISSION ---")

    # 1. Load and Parse Report Data
    try:
        with open(REPORT_FILE, 'r') as f:
            report_text = f.read()
            # Use regex to extract expense amount
            match = re.search(r'Expense Amount:\s*(\d+)', report_text)
            expense_amount = int(match.group(1)) if match else 0

    except FileNotFoundError:
        print(f"[ERROR] Input file '{REPORT_FILE}' not found. Please create it.")
        return
    except Exception as e:
        print(f"[ERROR] Failed to parse report: {e}")
        return

    # 2. Connect and Get Updated Public Keys
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.connect((HOST, PORT))

            # Send signing key placeholder (p, g)
            p, g, y_a = ELGAMAL_SIGN_KEYS[0]
            p_bytes = p.to_bytes(KEY_BYTE_LENGTH, 'big')
            g_bytes = g.to_bytes(KEY_BYTE_LENGTH, 'big')
            s.sendall(p_bytes + g_bytes)

            # Receive Auditor's Public Keys (HE and Key Transport)
            received_keys = recv_all(s)
            if not received_keys: return

            # Extract keys
            rsa_he_pub = received_keys['rsa_he_pub']
            rsa_pub_n = received_keys['rsa_pub_n']
            rsa_pub_e = received_keys['rsa_pub_e']

            # --- 3. Cryptographic Operations ---

            # a. AES Key Generation (Symmetric Key for bulk encryption)
            aes_key = get_random_bytes(32)  # AES-256

            # b. RSA Encryption of AES Key (Asymmetric key transport)
            encrypted_aes_key = rsa_encrypt_aes_key(aes_key, rsa_pub_n, rsa_pub_e)

            # c. AES Encryption of Report Content (Authenticated Encryption)
            nonce, encrypted_report, tag = aes_encrypt_report(report_text, aes_key)

            # d. RSA HE Encryption of Expense (Multiplicative Homomorphism)
            encrypted_expense = rsa_he_encrypt(expense_amount, rsa_he_pub)

            # e. SHA-256 Indexing for Department Search
            dept_hash = hash_message(CLIENT_DEPT.encode('utf-8'))

            # f. ElGamal Digital Signature (on integrity hash)

            # Data to Sign: Doctor ID + Dept Hash + Expense + Timestamp + Report Hash
            current_ts = int(time.time())
            report_body_hash = hash_message(report_text.encode('utf-8'))

            data_to_sign_str = f"{CLIENT_ID}|{CLIENT_DEPT}|{expense_amount}|{current_ts}|{report_body_hash}"
            msg_hash = hash_message(data_to_sign_str.encode('utf-8'))

            elgamal_priv = ELGAMAL_SIGN_KEYS[1]
            signature = elgamal_sign(msg_hash, elgamal_priv, p, g)

            print(f"[SUCCESS] Expense: {expense_amount}. Encrypted to: {hex(encrypted_expense)[:20]}...")
            print(f"[SUCCESS] Report signed. Hash: {hex(msg_hash)[:20]}...")

            # --- 4. Build and Send Final Payload ---
            final_payload = {
                'doctor_id': CLIENT_ID,
                'dept_hash': dept_hash,
                'encrypted_expense': encrypted_expense,
                'encrypted_aes_key': encrypted_aes_key,
                'encrypted_report': (nonce, encrypted_report, tag),
                'signature': signature,
                'msg_hash': msg_hash,
                'timestamp': current_ts,
                'elgamal_pub': y_a,  # Only send the public key component y_a
            }
            send_data(s, final_payload)
            print("[Client] Final payload sent to Auditor.")

            # 5. Receive Server Response
            response = recv_all(s)
            print(f"[Auditor Response] Status: {response.get('status')}")
            print(f"[Auditor Response] Message: {response.get('message')}")

    except ConnectionRefusedError:
        print("\n[ERROR] Connection refused. Make sure the Auditor Server is running!")
    except Exception as e:
        print(f"\n[CRITICAL ERROR] Submission failed: {e}")


def main():
    print("============================================================")
    print("           DOCTOR CLIENT APPLICATION")
    print("============================================================")

    while True:
        print("\n--- MENU ---")
        print("1. Register/Setup Doctor Identity")
        if CLIENT_ID:
            print(f"2. Submit Report & Log Expense (as {CLIENT_ID}/{CLIENT_DEPT})")
        print("3. Exit")

        choice = input("Enter your choice: ")

        if choice == '1':
            menu_register_doctor()
        elif choice == '2' and CLIENT_ID:
            menu_submit_report()
        elif choice == '3':
            print("Doctor client shutting down.")
            break
        else:
            print("Invalid choice or need to register first.")


if __name__ == "__main__":
    import math

    main()