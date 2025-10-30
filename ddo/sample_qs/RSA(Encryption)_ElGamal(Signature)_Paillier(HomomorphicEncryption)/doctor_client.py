#This file implements the Paillier Encryptor, ElGamal Signer, RSA Encryptor, and the Doctor's menu.

import socket
import pickle
import hashlib
import re
from Crypto.Util.number import getPrime, bytes_to_long, inverse
from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP

# --- Global Configurations ---
HOST = "127.0.0.1"
PORT = 65432
KEY_BITS = 2048
KEY_BYTE_LENGTH = KEY_BITS // 8
INPUT_FILE = "doctor_report.txt"


# --- ElGamal Signature Generation ---

# ElGamal Signing Keys (reusing key size for simplicity)
def elgamal_sign_key_generation(n_length=KEY_BITS):
    # Prime p, Generator g, Private key a
    p = number.getPrime(n_length)
    g = number.getPrime(n_length // 2)
    a = number.getRandomRange(2, p - 1)

    # Public key y_a
    y_a = pow(g, a, p)

    return ((p, g, y_a), a)


# ElGamal Signing
def elgamal_sign(msg_hash, private_key, p, g):
    a = private_key

    # k must be gcd(k, p-1) == 1
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


# Hashing (MD5 required by the prompt)
def hash_message(msg: bytes):
    return bytes_to_long(hashlib.md5(msg).digest())


# --- Paillier Encryption (Homomorphic Addition) ---

# Paillier Encryption
def paillier_encrypt(plaintext, public_key):
    n, g = public_key
    n_squared = n * n

    # Paillier requires plaintext m < n
    if plaintext >= n:
        print(f"[ERROR] Paillier plaintext {plaintext} is too large. Max m is {n - 1}.")
        return 0

    # Random r must be 0 < r < n and gcd(r, n) == 1
    while True:
        r = number.getRandomRange(2, n)
        if math.gcd(r, n) == 1:
            break

    # Ciphertext: c = g^m * r^n mod n^2
    c = (pow(g, plaintext, n_squared) * pow(r, n, n_squared)) % n_squared
    return c


# --- RSA Encryption ---
# Note: Used here to secure the transmission of text data
def rsa_encrypt(plaintext, public_key):
    try:
        n, e = public_key
        rsa_pub = RSA.construct((n, e))
        cipher_rsa = PKCS1_OAEP.new(rsa_pub)
        ciphertext = cipher_rsa.encrypt(plaintext.encode('utf-8'))
        return ciphertext
    except Exception as e:
        return f"[ENCRYPTION FAILED: {e}]".encode('utf-8')


# --- Data Handling ---

def parse_report_file(filename):
    """Reads and parses the multi-record report file."""
    try:
        with open(filename, 'r') as f:
            content = f.read()
    except FileNotFoundError:
        print(f"[ERROR] Input file '{filename}' not found. Create it with sample data.")
        return []

    reports = content.strip().split('--- Doctor\'s Daily Report ---')
    parsed_data = []

    for report in reports:
        report = report.strip()
        if not report:
            continue

        data = {}
        for line in report.split('\n'):
            if ':' in line:
                key, value = line.split(':', 1)
                data[key.strip()] = value.strip()

        # Validate required fields
        if all(k in data for k in ['Doctor', 'Branch', 'Timestamp', 'Budget Request']):
            try:
                data['Budget Request'] = int(data['Budget Request'].replace(',', ''))
                parsed_data.append(data)
            except ValueError:
                print(f"[WARNING] Skipping report due to non-numeric budget: {data.get('Budget Request')}")

    return parsed_data


# --- Socket Communication Helpers ---
def recv_all(conn):
    # Receive the length of the data first (e.g., 8 bytes for length)
    length_bytes = conn.recv(8)
    if not length_bytes:
        return None

    data_len = int.from_bytes(length_bytes, 'big')

    # Receive the actual data
    chunks = []
    bytes_recd = 0
    while bytes_recd < data_len:
        chunk = conn.recv(min(data_len - bytes_recd, 2048))
        if not chunk:
            raise ConnectionResetError("Connection lost before receiving full payload.")
        chunks.append(chunk)
        bytes_recd += len(chunk)

    return pickle.loads(b"".join(chunks))


def send_data(conn, data):
    # Serialize the data
    serialized_data = pickle.dumps(data)
    # Send the length of the serialized data
    conn.sendall(len(serialized_data).to_bytes(8, 'big'))
    # Send the serialized data
    conn.sendall(serialized_data)


# --- Client Logic ---

def upload_report(elgamal_keys):
    # --- 1. Load and Parse Report Data ---
    reports = parse_report_file(INPUT_FILE)
    if not reports:
        print(f"[ERROR] Could not process any valid records from {INPUT_FILE}.")
        return

    # --- 2. Generate ElGamal Signing Keys ---
    elgamal_pub, elgamal_priv = elgamal_keys
    p, g, y_a = elgamal_pub

    # --- 3. Connect to Auditor ---
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.connect((HOST, PORT))
            print(f"[Client] Connected to Auditor at {HOST}:{PORT}")

            # --- 4. Send Signing Public Key (p, g) ---
            # Auditor needs p, g to know the parameters for the subsequent message hash
            p_bytes = p.to_bytes(KEY_BYTE_LENGTH, 'big')
            g_bytes = g.to_bytes(KEY_BYTE_LENGTH, 'big')
            s.sendall(p_bytes + g_bytes)

            # --- 5. Receive Auditor's Public Keys (Paillier, RSA) ---
            received_keys = recv_all(s)

            if not received_keys:
                print("[ERROR] Failed to receive keys from Auditor.")
                return

            paillier_pub = received_keys['paillier_pub']
            rsa_pub = received_keys['rsa_pub']
            n, _ = paillier_pub  # Paillier modulus needed for check
            print("[Client] Received Auditor's Paillier and RSA Public Keys.")

            # --- 6. Process, Encrypt, and Sign Data ---
            encrypted_records = []

            # The entire report text for RSA encryption (non-homomorphic)
            full_report_text = open(INPUT_FILE, 'r').read()
            encrypted_text = rsa_encrypt(full_report_text, rsa_pub)

            # The data that will be hashed and signed (metadata and integrity check)
            data_to_sign_components = []

            for i, report in enumerate(reports):
                budget = report['Budget Request']

                # a) Paillier Encryption of Budget (Homomorphic)
                encrypted_budget = paillier_encrypt(budget, paillier_pub)

                if encrypted_budget == 0:
                    print(f"[ERROR] Skipping report {i + 1} due to Paillier failure.")
                    continue

                # b) MD5 Hash of Branch (for Searchable Index)
                branch_hash = hash_message(report['Branch'].encode('utf-8'))

                # c) Build the record for the payload
                record = {
                    'branch_hash': branch_hash,  # Search Key
                    'encrypted_budget': encrypted_budget,  # Homomorphic Additive Data
                    'doctor': report['Doctor'],  # Included in final hash (metadata)
                    'timestamp': report['Timestamp'],  # Included in final hash (metadata)
                }
                encrypted_records.append(record)

                # Add components to the data to be signed
                data_to_sign_components.append(f"{report['Doctor']}|{branch_hash}|{encrypted_budget}")

            # --- 7. Generate Signature on ALL Critical Data ---

            # Stringify the critical data (metadata, encrypted budget, search keys)
            critical_data_str = "|".join(data_to_sign_components)
            # Hash the string (MD5 required)
            msg_hash = hash_message(critical_data_str.encode('utf-8'))

            # ElGamal Sign the Hash
            signature = elgamal_sign(msg_hash, elgamal_priv, p, g)

            print(f"[Client] Report signed using ElGamal. Hash: {msg_hash:#x}")

            # --- 8. Build and Send Final Payload ---
            final_payload = {
                'encrypted_text': encrypted_text,  # RSA Encrypted File Content
                'encrypted_records': encrypted_records,  # Paillier Encrypted Budgets + Search Keys
                'signature': signature,  # ElGamal Signature (r, s)
                'msg_hash': msg_hash,  # The Hash that was signed
                'elgamal_pub': elgamal_pub,  # Full ElGamal Public Key (p, g, y_a)
            }
            send_data(s, final_payload)
            print("[Client] Final payload sent to Auditor. Auditor will now process.")

    except ConnectionRefusedError:
        print("\n[ERROR] Connection refused. Make sure the Auditor Server is running!")
    except Exception as e:
        print(f"\n[CRITICAL ERROR] Failed to complete transaction: {e}")


def start_menu(elgamal_keys):
    while True:
        print("\n============================================================")
        print("           DOCTOR CLIENT MENU")
        print("============================================================")
        print(f"Input file: {INPUT_FILE}")
        print("1. Upload and Encrypt Report to Auditor")
        print("2. Exit")

        choice = input("Enter your choice (1-2): ")

        if choice == '1':
            upload_report(elgamal_keys)
        elif choice == '2':
            print("Doctor client shutting down.")
            break
        else:
            print("Invalid choice. Please try again.")


# --- Initialization ---
if __name__ == "__main__":
    import math
    from Crypto.Util import number

    # Generate ElGamal Signing Keys once
    ELGAMAL_SIGN_KEYS = elgamal_sign_key_generation(KEY_BITS)

    start_menu(ELGAMAL_SIGN_KEYS)