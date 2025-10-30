#This file contains the Paillier Decryptor, ElGamal Verifier, and the menu-driven logic for the Auditor.

import socket
import threading
import pickle
import hashlib
from Crypto.Util.number import getPrime, bytes_to_long, inverse, long_to_bytes
from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP

# --- Global Configurations ---
HOST = "127.0.0.1"
PORT = 65432
KEY_BITS = 2048
KEY_BYTE_LENGTH = KEY_BITS // 8

# Stored Encrypted Data (for search and addition)
# Format: {md5_of_branch_name: [(encrypted_budget, doctor_name, timestamp), ...]}
ENCRYPTED_RECORDS = {}
# Stores a single record to be added (used for demonstration)
BUDGET_TO_ADD = None


# --- Paillier Cryptography (Homomorphic Addition) ---

# Paillier Key Generation
def paillier_key_generation(n_length=KEY_BITS):
    p, q = getPrime(n_length // 2), getPrime(n_length // 2)
    n = p * q
    g = n + 1
    # Lambda = lcm(p-1, q-1)
    lambda_val = (p - 1) * (q - 1) // math.gcd(p - 1, q - 1)

    # L(x) = (x - 1) / n
    def L(x):
        return (x - 1) // n

    # mu = (L(g^lambda mod n^2))^-1 mod n
    n_squared = n * n
    g_lambda = pow(g, lambda_val, n_squared)
    mu = inverse(L(g_lambda), n)

    return ((n, g), (lambda_val, mu))


# Paillier Decryption
def paillier_decrypt(ciphertext, private_key, n):
    lambda_val, mu = private_key
    n_squared = n * n

    def L(x):
        return (x - 1) // n

    m = (L(pow(ciphertext, lambda_val, n_squared)) * mu) % n
    return m


# --- ElGamal Signature Verification ---

# Hashing (MD5 required by the prompt)
def hash_message(msg: bytes):
    return bytes_to_long(hashlib.md5(msg).digest())


def elgamal_verify(msg_hash, signature, public_key):
    p, g, y_a = public_key
    r, s = signature

    if not (0 < r < p) or not (0 < s < p - 1):
        return False

    # Verification check: (y_a^r * r^s) mod p == g^msg_hash mod p
    # Left side: (y_a^r * r^s) mod p
    # Right side: g^msg_hash mod p

    # We use pow(a, b, m) for modular exponentiation
    g_m = pow(g, msg_hash, p)
    y_r = pow(y_a, r, p)
    r_s = pow(r, s, p)

    left_side = (y_r * r_s) % p
    right_side = g_m

    return left_side == right_side


# --- RSA Encryption/Decryption ---
# Note: RSA is used here to secure the transmission of text data, not for homomorphism.
def rsa_decrypt(ciphertext, private_key):
    try:
        cipher_rsa = PKCS1_OAEP.new(private_key)
        plaintext = cipher_rsa.decrypt(ciphertext)
        return plaintext.decode('utf-8')
    except Exception as e:
        return f"[DECRYPTION FAILED: {e}]"


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


# --- Server Logic ---

def handle_client(conn, addr, paillier_keys, rsa_key_pair):
    global ENCRYPTED_RECORDS
    global BUDGET_TO_ADD

    print(f"\n[Gateway] Connection established with {addr}")

    try:
        # 1. Receive the Doctor's Public Key (ElGamal for verification)
        # Note: RSA key is sent as a tuple (n, e)
        doctor_public_key_raw = conn.recv(KEY_BYTE_LENGTH * 2)

        # Unpack the ElGamal keys (p, g, y_a) from the start of the bytes
        p_bytes = doctor_public_key_raw[:KEY_BYTE_LENGTH]
        g_bytes = doctor_public_key_raw[KEY_BYTE_LENGTH:KEY_BYTE_LENGTH * 2]

        doctor_elgamal_public_key_n_g = (
            int.from_bytes(p_bytes, 'big'),
            int.from_bytes(g_bytes, 'big')
        )

        # 2. Send the Auditor's Public Keys (Paillier for encryption, RSA for file encryption)
        paillier_public_key, _ = paillier_keys
        rsa_public_key, _ = rsa_key_pair

        response_keys = {
            'paillier_pub': paillier_public_key,
            'rsa_pub': (rsa_public_key.n, rsa_public_key.e)
        }
        send_data(conn, response_keys)
        print(f"[Gateway] Sent Paillier/RSA Public Keys to Doctor {addr}")

        # 3. Receive the Encrypted Payload
        payload = recv_all(conn)

        if payload is None:
            print(f"[Gateway] Doctor {addr} disconnected without sending payload.")
            return

        print(f"[Gateway] Received Encrypted Payload from Doctor {addr}")

        # Unpack payload
        encrypted_text = payload['encrypted_text']
        encrypted_records = payload['encrypted_records']
        signature = payload['signature']
        msg_hash = payload['msg_hash']

        # --- Store Encrypted Records for Auditing ---
        # The payload contains the full public key (p, g, y_a) used for signing
        elgamal_pub_key_full = payload['elgamal_pub']

        # Store records by MD5 hash of branch name for search function
        for record in encrypted_records:
            branch_hash = record['branch_hash']
            record['doctor_elgamal_pub'] = elgamal_pub_key_full

            if branch_hash not in ENCRYPTED_RECORDS:
                ENCRYPTED_RECORDS[branch_hash] = []
            ENCRYPTED_RECORDS[branch_hash].append(record)

            # Store the budget for addition function demonstration
            BUDGET_TO_ADD = record['encrypted_budget']

        # --- Menu-based Program Entry Point ---
        start_menu(paillier_keys, rsa_key_pair)

    except ConnectionResetError:
        print(f"[Gateway] Doctor {addr} forcefully disconnected.")
    except Exception as e:
        print(f"[Gateway] An unexpected error occurred with {addr}: {e}")
    finally:
        conn.close()


def start_server(paillier_keys, rsa_key_pair):
    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server.bind((HOST, PORT))
    server.listen(5)
    print(f"============================================================")
    print(f"       AUDITOR SERVER (Paillier, ElGamal, RSA)              ")
    print(f"============================================================")
    print(f"Paillier Modulus N (for addition): {paillier_keys[0][0]:#x}")
    print(f"RSA Private Key D (for decryption): {rsa_key_pair[1].d:#x}")
    print(f"Listening on {HOST}:{PORT}...")

    # Accept one client connection (Doctor) and proceed to the menu
    try:
        conn, addr = server.accept()
        client_thread = threading.Thread(target=handle_client, args=(conn, addr, paillier_keys, rsa_key_pair))
        client_thread.start()
        # Wait for the client thread to finish processing the payload
        client_thread.join()
    except Exception as e:
        print(f"[Server Error] Failed to accept connection: {e}")
    finally:
        server.close()


# --- Auditor Menu Functions ---

def menu_verify_signature(elgamal_pub_full, signature, msg_hash):
    """3) verify signature"""
    if not ENCRYPTED_RECORDS:
        print("\n[VERIFICATION] No records received to verify.")
        return False

    # Get the ElGamal Public Key (p, g, y_a)
    p, g, y_a = elgamal_pub_full
    r, s = signature

    is_valid = elgamal_verify(msg_hash, (r, s), (p, g, y_a))

    print("\n------------------------------------------------------------")
    print("         SIGNATURE VERIFICATION RESULT")
    print("------------------------------------------------------------")
    print(f"Signature Status: {'VALID' if is_valid else 'INVALID'}")
    print(f"Message Hash (MD5): {msg_hash:#x}")

    # Decrypt and show the original text as proof of valid transaction
    rsa_priv = RSA_KEY_PAIR[1]

    first_record = list(ENCRYPTED_RECORDS.values())[0][0]
    decrypted_text = rsa_decrypt(first_record['encrypted_text'], rsa_priv)

    if is_valid:
        print(f"Decrypted Report Text (Proof): {decrypted_text[:50]}...")
    else:
        print("Cannot trust report. Decryption skipped.")

    print("------------------------------------------------------------")
    return is_valid


def menu_search_doctors():
    """1) search for doctors (using search key map) from different branches in text file without decrypting"""
    print("\n------------------------------------------------------------")
    print("         SEARCH FOR DOCTORS BY BRANCH (Encrypted Index)")
    print("------------------------------------------------------------")

    # Show available search keys
    if not ENCRYPTED_RECORDS:
        print("No records received yet.")
        return

    print("Available Encrypted Branch Keys (Hashes):")
    for key in ENCRYPTED_RECORDS.keys():
        print(f" - {key:#x}")

    branch_name = input("Enter Branch Name (e.g., Cardiology or Orthopedics): ").strip()

    # Auditor computes the same MD5 hash (the search key)
    search_key_hash = bytes_to_long(hashlib.md5(branch_name.encode('utf-8')).digest())

    print(f"\nSearching for Index: {search_key_hash:#x}")

    if search_key_hash in ENCRYPTED_RECORDS:
        print(f"Found {len(ENCRYPTED_RECORDS[search_key_hash])} records for {branch_name}!")
        for i, record in enumerate(ENCRYPTED_RECORDS[search_key_hash]):
            # The Auditor can see the encrypted budget and can't read the doctor/timestamp
            print(f"  Record {i + 1}: Budget: {record['encrypted_budget']:#x} (Encrypted)")
    else:
        print(f"No records found for branch: {branch_name}")

    print("------------------------------------------------------------")


def menu_add_budgets(paillier_keys):
    """2) add the budgets sent my doctor in text file without decrypting"""
    global BUDGET_TO_ADD

    if not BUDGET_TO_ADD or not ENCRYPTED_RECORDS:
        print("\n[ADDITION] No records received to add.")
        return

    # Get all budget ciphertexts from the first branch found
    all_budgets = [record['encrypted_budget'] for records in ENCRYPTED_RECORDS.values() for record in records]

    if len(all_budgets) < 2:
        print("\n[ADDITION] Need at least two budgets to demonstrate homomorphic addition.")
        return

    paillier_pub, paillier_priv = paillier_keys
    n, g = paillier_pub

    print("\n------------------------------------------------------------")
    print("         HOMOMORPHIC BUDGET ADDITION (Paillier)")
    print("------------------------------------------------------------")

    # 1. Homomorphic Addition (Multiplication of Ciphertexts)
    total_encrypted = 1
    for i, budget in enumerate(all_budgets):
        total_encrypted = (total_encrypted * budget) % (n * n)
        print(f"Budget {i + 1} Ciphertext: {budget:#x}")

    print(f"\nTotal Encrypted Budget (Homomorphic Product): {total_encrypted:#x}")

    # 2. Decryption
    total_decrypted = paillier_decrypt(total_encrypted, paillier_priv, n)

    # Check the expected total based on the sample file: 15000 + 8500 + 22000 = 45500
    print(f"Total Decrypted Budget (Actual Sum): {total_decrypted:,}")
    print("------------------------------------------------------------")


def start_menu(paillier_keys, rsa_key_pair):
    if not ENCRYPTED_RECORDS:
        print("\n[Auditor] Waiting for Doctor to send data before showing menu...")
        return

    # Extract single record for verification demo
    first_record = list(ENCRYPTED_RECORDS.values())[0][0]
    elgamal_pub_full = first_record.pop('doctor_elgamal_pub')

    while True:
        print("\n============================================================")
        print("          AUDITOR ACTION MENU (DATA RECEIVED)")
        print("============================================================")
        print("1. Search for Doctors by Branch (Encrypted Index)")
        print("2. Add Budgets Homomorphically (Paillier)")
        print("3. Verify Doctor's Signature (ElGamal)")
        print("4. Exit")

        choice = input("Enter your choice (1-4): ")

        if choice == '1':
            menu_search_doctors()
        elif choice == '2':
            menu_add_budgets(paillier_keys)
        elif choice == '3':
            menu_verify_signature(elgamal_pub_full, first_record['signature'], first_record['msg_hash'])
        elif choice == '4':
            print("Auditor shutting down.")
            break
        else:
            print("Invalid choice. Please try again.")


# --- Initialization ---
if __name__ == "__main__":
    import math
    from Crypto.Util import number

    # 1. Generate Global Keys
    PAILLIER_KEYS = paillier_key_generation(KEY_BITS)

    # RSA Key Pair (Used for main text file encryption)
    rsa_key = RSA.generate(KEY_BITS)
    RSA_KEY_PAIR = (rsa_key.publickey(), rsa_key)

    # 2. Start the Server
    start_server(PAILLIER_KEYS, RSA_KEY_PAIR)