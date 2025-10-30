import socket
import threading
import pickle
import json
import hashlib
import time
from Crypto.Util import number
from Crypto.Util.number import bytes_to_long, inverse, long_to_bytes
from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP
from Crypto.Hash import SHA256

# --- Global Configurations ---
HOST = "127.0.0.1"
PORT = 65432
KEY_BITS = 2048
KEY_BYTE_LENGTH = KEY_BITS // 8
STATE_FILE = "server_state.json"
MAX_CONNECTIONS = 5

# --- State Management ---
SERVER_STATE = {}
STATE_LOCK = threading.Lock()


def load_state():
    """Loads server state from JSON file."""
    global SERVER_STATE
    try:
        with open(STATE_FILE, 'r') as f:
            state = json.load(f)
            # Deserialize keys from hex strings if present
            if state.get('rsa_he_keys'):
                n = int(state['rsa_he_keys'][0], 16)
                e = int(state['rsa_he_keys'][1], 16)
                d = int(state['rsa_he_keys'][2], 16)
                state['rsa_he_keys'] = (n, e, d)
            if state.get('rsa_keys'):
                state['rsa_keys'] = RSA.import_key(state['rsa_keys'])
            if state.get('elgamal_keys'):
                state['elgamal_keys'] = (
                    int(state['elgamal_keys'][0], 16),
                    int(state['elgamal_keys'][1], 16),
                    int(state['elgamal_keys'][2], 16)
                )
            SERVER_STATE = state
    except FileNotFoundError:
        print("[INIT] State file not found. Creating default state.")
        SERVER_STATE = {
            "rsa_he_keys": None,  # RSA Homomorphic (Multiplicative) Keys
            "rsa_keys": None,  # RSA Key Transport Keys
            "elgamal_keys": None,  # ElGamal Signature Params (p, g)
            "doctors": {},  # {doctor_id: {dept_hash: ..., elgamal_pub: ...}}
            "records": []  # List of submitted encrypted reports
        }
    except Exception as e:
        print(f"[ERROR] Could not load state: {e}. Starting with default state.")
        SERVER_STATE = {
            "rsa_he_keys": None, "rsa_keys": None, "elgamal_keys": None, "doctors": {}, "records": []
        }


def save_state():
    """Saves server state to JSON file."""
    with STATE_LOCK:
        try:
            state_to_save = SERVER_STATE.copy()

            # Serialize keys to hex strings for storage
            if state_to_save['rsa_he_keys']:
                n, e, d = state_to_save['rsa_he_keys']
                state_to_save['rsa_he_keys'] = (hex(n), hex(e), hex(d))
            if state_to_save['rsa_keys']:
                state_to_save['rsa_keys'] = state_to_save['rsa_keys'].export_key("PEM").decode('utf-8')
            if state_to_save['elgamal_keys']:
                p, g, x = state_to_save['elgamal_keys']
                state_to_save['elgamal_keys'] = (hex(p), hex(g), hex(x))

            with open(STATE_FILE, 'w') as f:
                json.dump(state_to_save, f, indent=4)
        except Exception as e:
            print(f"[ERROR] Failed to save state: {e}")


# --- Key Generation and Setup ---

def generate_rsa_he_keys(bits=KEY_BITS):
    """Generates standard RSA keys for multiplicative homomorphism (demonstration)."""
    p, q = number.getPrime(bits // 2), number.getPrime(bits // 2)
    n = p * q
    phi = (p - 1) * (q - 1)
    e = 65537
    d = number.inverse(e, phi)
    return (n, e, d)  # (n, e, d)


def generate_elgamal_params(bits=KEY_BITS):
    """Generates public parameters (p, g) for ElGamal signing."""
    p = number.getPrime(bits)
    g = number.getRandomRange(2, p - 1)
    # The server doesn't need a private key, just the public parameters
    return (p, g, number.getRandomRange(2, p - 1))  # (p, g, random_x)


def setup_initial_keys():
    """Initializes keys if not present in the state."""
    global SERVER_STATE

    if not SERVER_STATE.get('rsa_he_keys'):
        SERVER_STATE['rsa_he_keys'] = generate_rsa_he_keys()

    if not SERVER_STATE.get('rsa_keys'):
        rsa_key = RSA.generate(KEY_BITS)
        SERVER_STATE['rsa_keys'] = rsa_key

    if not SERVER_STATE.get('elgamal_keys'):
        # Just need p, g, and a placeholder x for parameter size
        SERVER_STATE['elgamal_keys'] = generate_elgamal_params()

    save_state()


# --- Cryptographic Operations ---

def elgamal_verify(msg_hash, signature, public_key):
    """Verifies an ElGamal signature."""
    p, g, y_a = public_key
    r, s = signature

    if not (0 < r < p) or not (0 < s < p - 1):
        return False

    # Verification check: (y_a^r * r^s) mod p == g^msg_hash mod p
    g_m = pow(g, msg_hash, p)
    y_r = pow(y_a, r, p)
    r_s = pow(r, s, p)

    left_side = (y_r * r_s) % p
    right_side = g_m

    return left_side == right_side


def rsa_he_decrypt(ciphertext, private_key):
    """Deciphers the result of the RSA HE operation (Multiplicative)."""
    n, e, d = private_key

    # Decryption: m = c^d mod n
    return pow(ciphertext, d, n)


# --- Server Logic and Handlers ---

def hash_message(msg: bytes):
    """Generates SHA-256 hash (used for indexing and signing)."""
    return bytes_to_long(SHA256.new(msg).digest())


def handle_client(conn, addr):
    """Handles a single client connection and report submission."""
    global SERVER_STATE

    # Load keys for communication
    rsa_he_pub = SERVER_STATE['rsa_he_keys'][:2]  # (n, e)
    rsa_key_pub = SERVER_STATE['rsa_keys'].publickey()
    elgamal_params = SERVER_STATE['elgamal_keys'][:2]  # (p, g)

    print(f"\n[Gateway] Connection established with {addr}")

    try:
        # 1. Send Auditor's Public Keys
        response_keys = {
            'rsa_he_pub': rsa_he_pub,
            'rsa_pub_n': rsa_key_pub.n,
            'rsa_pub_e': rsa_key_pub.e,
            'elgamal_params': elgamal_params,
        }
        send_data(conn, response_keys)
        print(f"[Gateway] Sent Public Keys to Doctor {addr}")

        # 2. Receive the Encrypted Payload
        payload = recv_all(conn)

        if payload is None:
            print(f"[Gateway] Doctor {addr} disconnected without payload.")
            return

        # --- Report Validation and Storage ---

        # 3. Verify Signature
        elgamal_pub_key = payload['elgamal_pub']
        signature = payload['signature']
        msg_hash = payload['msg_hash']
        timestamp = payload['timestamp']
        doctor_id = payload['doctor_id']
        dept_hash = payload['dept_hash']

        is_valid = elgamal_verify(msg_hash, signature, elgamal_pub_key)

        if not is_valid:
            print(f"[WARNING] Signature INVALID for Doctor {doctor_id}. Rejecting report.")
            send_data(conn, {"status": "FAILED", "message": "Signature verification failed."})
            return

        print(f"[SUCCESS] Signature VALID for Doctor {doctor_id}.")
        send_data(conn, {"status": "SUCCESS", "message": "Report received and verified."})

        # 4. Thread-safe State Update
        with STATE_LOCK:
            # Register Doctor if new
            if doctor_id not in SERVER_STATE['doctors']:
                SERVER_STATE['doctors'][doctor_id] = {
                    'dept_hash': dept_hash,
                    'elgamal_pub': elgamal_pub_key,
                    'registration_ts': time.time()
                }

            # Store Record
            SERVER_STATE['records'].append({
                'record_id': time.time(),  # Simple unique ID
                'doctor_id': doctor_id,
                'dept_hash': dept_hash,  # Searchable index
                'encrypted_expense': payload['encrypted_expense'],  # HE data (Multiplicative)
                'encrypted_aes_key': payload['encrypted_aes_key'],  # RSA Encrypted AES Key
                'encrypted_report': payload['encrypted_report'],  # AES-256 GCM Encrypted Report
                'signature_ts': timestamp,
                'status': 'VERIFIED'
            })
            save_state()

    except ConnectionResetError:
        print(f"[Gateway] Doctor {addr} disconnected.")
    except Exception as e:
        print(f"[Gateway] An unexpected error occurred: {e}")
    finally:
        conn.close()


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


# --- Auditor Menu Functions ---

def menu_search_doctors():
    """Search doctors by department keyword without decrypting data (using SHA-256 index)."""
    print("\n--- 1. SEARCH DOCTORS BY DEPARTMENT (Privacy-Preserving Index) ---")

    if not SERVER_STATE['doctors']:
        print("No doctors registered yet.")
        return

    department = input("Enter Department Name to Search (e.g., Cardiology): ").strip()

    # Auditor computes the search key (hash of the department name)
    search_key_hash = hash_message(department.encode('utf-8'))

    print(f"\nSearching for Index: {hex(search_key_hash)}")
    found_doctors = []

    for doc_id, doc_data in SERVER_STATE['doctors'].items():
        if doc_data['dept_hash'] == search_key_hash:
            found_doctors.append(doc_id)

    print("--------------------------------------------------")
    if found_doctors:
        print(f"Found {len(found_doctors)} Doctors in {department} (Encrypted Match):")
        for doc_id in found_doctors:
            print(f"- Doctor ID: {doc_id}")
    else:
        print(f"No doctors found for department: {department}")
    print("--------------------------------------------------")


def menu_sum_expenses():
    """Sum all expenses homomorphically (Multiplicative RSA HE)."""
    print("\n--- 2. HOMOMORPHIC EXPENSE AGGREGATION (RSA Multiplicative) ---")

    rsa_he_keys = SERVER_STATE['rsa_he_keys']
    if not rsa_he_keys or not SERVER_STATE['records']:
        print("No records or keys available for aggregation.")
        return

    records = SERVER_STATE['records']
    n = rsa_he_keys[0]  # Modulus for HE

    print(f"Total Records to Aggregate: {len(records)}")

    # 1. Homomorphic Aggregation (Multiplication of Ciphertexts)
    total_encrypted_product = 1

    for record in records:
        cipher_expense = record['encrypted_expense']
        # Product operation: c_total = c1 * c2 * ... * cn mod n
        total_encrypted_product = (total_encrypted_product * cipher_expense) % n

    print(f"Total Encrypted Product (Aggregated): {hex(total_encrypted_product)}")

    # 2. Decryption (m = c^d mod n)
    try:
        total_decrypted_product = rsa_he_decrypt(total_encrypted_product, rsa_he_keys)
        print(f"Total Decrypted Product (Actual): {total_decrypted_product:,}")
    except Exception as e:
        print(f"[ERROR] Decryption failed (Product too large?): {e}")

    print("--------------------------------------------------")


def menu_audit_records():
    """List and audit all stored records."""
    print("\n--- 3. AUDIT ALL STORED RECORDS ---")

    if not SERVER_STATE['records']:
        print("No records stored.")
        return

    print(f"Total Records: {len(SERVER_STATE['records'])}")
    print("--------------------------------------------------")
    for i, record in enumerate(SERVER_STATE['records']):
        print(f"Record #{i + 1} | Doctor: {record['doctor_id']} | Status: {record['status']}")
        print(f"  Dept Hash: {hex(record['dept_hash'])}")
        print(f"  Expense Cipher: {hex(record['encrypted_expense'])[:20]}...")
        print(f"  Signed TS: {time.strftime('%Y-%m-%d %H:%M:%S', time.localtime(record['signature_ts']))}")
    print("--------------------------------------------------")


def start_menu():
    """Interactive menu for the Auditor."""

    # Wait for initial data submission from Doctor
    while not SERVER_STATE['records']:
        print("\n[Auditor Menu] Waiting for at least one report submission from a Doctor before enabling analysis...")
        time.sleep(5)
        load_state()  # Reload state in case data was saved by a thread

    while True:
        print("\n============================================================")
        print("              AUDITOR ACTION MENU")
        print("============================================================")
        print("1. Search Doctors by Department (Privacy-Preserving)")
        print("2. Sum All Expenses Homomorphically (Multiplicative Product)")
        print("3. Audit and List All Stored Records")
        print("4. Shutdown Server")

        choice = input("Enter your choice (1-4): ")

        if choice == '1':
            menu_search_doctors()
        elif choice == '2':
            menu_sum_expenses()
        elif choice == '3':
            menu_audit_records()
        elif choice == '4':
            print("Auditor shutting down.")
            break
        else:
            print("Invalid choice. Please try again.")


def main():
    load_state()
    setup_initial_keys()

    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server.bind((HOST, PORT))
    server.listen(MAX_CONNECTIONS)

    print(f"============================================================")
    print(f"       AUDITOR SERVER (Privacy-Preserving System)           ")
    print(f"============================================================")
    print(f"Listening on {HOST}:{PORT}...")
    print("Waiting for Doctor Clients to connect...")

    # Start the menu thread
    menu_thread = threading.Thread(target=start_menu)
    menu_thread.daemon = True  # Allows menu thread to exit when main thread exits
    menu_thread.start()

    # Accept client connections in the main thread
    try:
        while True:
            conn, addr = server.accept()
            client_thread = threading.Thread(target=handle_client, args=(conn, addr))
            client_thread.start()
    except KeyboardInterrupt:
        print("\n[Server] Shutdown requested.")
    finally:
        server.close()
        print("[Server] Server closed.")


if __name__ == "__main__":
    main()