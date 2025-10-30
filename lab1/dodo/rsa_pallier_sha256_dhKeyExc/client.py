import socket
import hashlib
import json
from Crypto.Util.number import getPrime, inverse, bytes_to_long, long_to_bytes, getRandomRange
from Crypto.Cipher import AES
from Crypto.Util import Counter
from typing import Dict, Any, Tuple, List
import os

# --- NETWORK CONFIGURATION ---
HOST = "127.0.0.1"
PORT = 65433
# DH parameters (public and known to both parties)
DH_G = 2
DH_P = 0xFFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD129024E088A67CC74020BBEA63B139B22514A08798E3404DDEF9519B3CD3A431B302B0A6DF25F14374FE1356D6D51C245E485B576625E7EC6F44C42E9A637ED6B0BFF5CB6F406B7EDEE386BFB5A899FA5AEF9BAEBC3AADBCD1AE49D6A95B518E6490605B8ACBABFE0B6E36E2313DAA62DC3E3A1C20EE4D6922A236C6580DC48CEE054DCA7B804918E8B62DAF0F7732F680D9C40B8C8EEA68B012DA9501377484DDC56E70C58380F92B82F3B660205AE2C015FDFB1238C5AA71C98EDEE7417F6A24470DC00EE1B52B75A5AEC318CE44E7AD010882774C37A35ED8AEFF770732A78FDE557CBBC2A31A76F40E91910602A9DE3A7E56BC99A814EEA0E0767A99B97FEE34F5C4A003108B7B76F02888602283E2A449F30ED717CB94921EAE4F2818A89A6EE010E000000000000000000092E
DH_KEY_SIZE = 256  # 256-bit hash key for AES
DH_BYTE_LENGTH = (DH_P.bit_length() + 7) // 8  # 256

# Globals to be set after receiving public key from server
PAILLIER_N = None
PAILLIER_G = None
PAILLIER_N_SQUARED = None
PAILLIER_PUB = None


# --- SYMMETRIC ENCRYPTION UTILS ---

def pad(data: bytes) -> bytes:
    """Applies PKCS#7 padding."""
    block_size = AES.block_size
    padding_len = block_size - (len(data) % block_size)
    padding = bytes([padding_len] * padding_len)
    return data + padding


def encrypt_aes(plaintext: bytes, key: bytes, iv: bytes) -> bytes:
    """Encrypts data using AES-256 CBC mode."""
    cipher = AES.new(key, AES.MODE_CBC, iv)
    return cipher.encrypt(pad(plaintext))


# --- DH KEY EXCHANGE ---

def dh_key_exchange(s: socket.socket) -> bytes:
    """Performs Diffie-Hellman Key Exchange and returns the shared secret K."""
    print("[Client] Starting Diffie-Hellman Key Exchange...")

    # 1. Client generates its private key (a) and public key (A)
    a_private = getRandomRange(1, DH_P - 1)
    A_public = pow(DH_G, a_private, DH_P)

    # 2. Client sends its public key (A) using the fixed DH_BYTE_LENGTH
    s.sendall(A_public.to_bytes(DH_BYTE_LENGTH, 'big'))

    # 3. Client receives server's public key (B) using the fixed DH_BYTE_LENGTH
    B_public_bytes = s.recv(DH_BYTE_LENGTH)
    B_public = int.from_bytes(B_public_bytes, 'big')

    # 4. Client computes the shared secret K = B^a mod p
    K_shared_int = pow(B_public, a_private, DH_P)

    # 5. Hash K to get the final 256-bit key for AES
    K_shared_hash = hashlib.sha256(K_shared_int.to_bytes(DH_BYTE_LENGTH, 'big')).digest()

    print("[Client] DH Key Exchange complete. Shared Secret established.")
    return K_shared_hash


# --- CRYPTOGRAPHY UTILS (Client Side) ---

def encrypt(m: int, n: int, g: int, n_squared: int) -> int:
    """Encrypts a plaintext message m using the Paillier public key (N, G)."""

    if not (0 <= m < n):
        raise ValueError(f"Paillier plaintext must be in range [0, n). Max m is {n - 1}, got {m}.")

    # Use a deterministic r for simulation simplicity and reproducible results
    r = (m % 1000 + 7) * 1000 + 1
    if r <= 0 or r >= n:
        r = (m + 1) * 3 % n
        if r == 0: r = 1

    # Ciphertext c = (g^m * r^n) mod n^2
    c = (pow(g, m, n_squared) * pow(r, n, n_squared)) % n_squared
    return c


def add_homomorphically(c1: int, c2: int, n_squared: int) -> int:
    """Homomorphically adds two ciphertexts: c1 * c2 mod n^2."""
    c_sum = (c1 * c2) % n_squared
    return c_sum


def _hash_message_to_int(msg: str):
    """Hashes a string message using SHA-256 and converts the digest to a large integer."""
    return bytes_to_long(hashlib.sha256(msg.encode('utf-8')).digest())


def generate_rsa_keys(bits=2048):
    """Generates an RSA key pair."""
    p, q = getPrime(bits // 2), getPrime(bits // 2)
    n = p * q
    phi = (p - 1) * (q - 1)
    e = 65537
    d = inverse(e, phi)
    return ((n, e), (n, d))  # (public_key, private_key)


def sign_summary(summary_str: str, private_key: Tuple[int, int]) -> int:
    """Signs the SHA-256 hash of the transaction summary string (RSA)."""
    n, d = private_key
    msg_hash = _hash_message_to_int(summary_str)
    # Signature = H(M)^d mod n
    signature = pow(msg_hash, d, n)
    return signature


# --- SELLER DATA ---
SELLER_DATA = [
    {
        "name": "Seller Alpha (Retail)",
        "transactions": [1500, 320, 450],
        "rsa_keys": generate_rsa_keys()
    },
    {
        "name": "Seller Beta (Service)",
        "transactions": [50, 120, 25, 300],
        "rsa_keys": generate_rsa_keys()
    }
]


def generate_transaction_summary(seller: Dict[str, Any]) -> Dict[str, Any]:
    """Encrypts transactions, computes the homomorphic total, and signs the summary."""

    # Paillier Encrypt individual transactions
    encrypted_amounts = [encrypt(tx, PAILLIER_N, PAILLIER_G, PAILLIER_N_SQUARED)
                         for tx in seller["transactions"]]

    # Homomorphic Summation
    total_encrypted_amount = encrypted_amounts[0]
    for c_tx in encrypted_amounts[1:]:
        total_encrypted_amount = add_homomorphically(total_encrypted_amount, c_tx, PAILLIER_N_SQUARED)

    # Build the initial summary for display
    summary = {
        "Seller Name": seller["name"],
        "Individual Transaction Amounts": seller["transactions"],
        "Encrypted Transaction Amounts": encrypted_amounts,
        "Total Encrypted Transaction Amount": total_encrypted_amount,
        "Total Decrypted Transaction Amount": "Pending",
        "Digital Signature Status": "Signed (Client)",
        "Signature Verification Result": "Pending"
    }

    # --- Digital Signature ---
    # Data to be signed (core data that must be authenticated)
    data_to_sign = {
        "Name": summary["Seller Name"],
        "Encrypted Total": hex(total_encrypted_amount)
    }
    signed_data_str = json.dumps(data_to_sign)

    # Sign the data
    _, private_key = seller["rsa_keys"]
    digital_signature = sign_summary(signed_data_str, private_key)

    # Prepare payload for server
    payload = {
        "seller_name": summary["Seller Name"],
        "summary_str": signed_data_str,
        "signature": hex(digital_signature),
        "public_key_n": hex(seller["rsa_keys"][0][0]),
        "public_key_e": hex(seller["rsa_keys"][0][1]),
        "encrypted_total": hex(total_encrypted_amount)
    }

    return summary, payload


def display_final_summary(summary: Dict[str, Any], initial_transactions: List[int]):
    """Prints the final, updated transaction summary."""

    # Determine the status and color for the final output
    status = summary.get('Signature Verification Result', 'UNKNOWN')

    print("\n" + "=" * 95)
    print(f"                            FINAL TRANSACTION REPORT FOR {summary['Seller Name']}")
    print("=" * 95)

    # 1. Individual Transactions Section
    print("\n--- 1. Individual Transactions (Paillier Encryption & Homomorphic Sum) ---")

    for i, (p_amt, c_amt) in enumerate(zip(
            initial_transactions,
            summary["Encrypted Transaction Amounts"]
    )):
        # Display Encrypted Amount as a short hex string
        print(f"  TX {i + 1}: Amount: {p_amt:,} | Encrypted: {hex(c_amt)[:12]}...")

    # 2. Total Section
    print("\n--- 2. Total Computation ---")
    print(f"  Total Plain Amount (Expected):     {sum(initial_transactions):,}")
    print(f"  Total Encrypted (Homomorphic Sum): {hex(summary['Total Encrypted Transaction Amount'])[:20]}...")
    decrypted_amount = summary['Total Decrypted Transaction Amount']
    print(
        f"  Total Decrypted (Gateway Result):  {decrypted_amount if isinstance(decrypted_amount, str) else int(decrypted_amount):,}")

    # 3. Signature Section
    print("\n--- 3. Digital Signature (RSA & SHA-256) ---")
    print(f"  Digital Signature Status:          {summary['Digital Signature Status']}")
    print(f"  Verification Result:               {status}")

    print("=" * 95 + "\n")


def process_seller_transaction(seller: Dict[str, Any]):
    """Connects to server, performs DH exchange, sends payload, and processes response."""

    global PAILLIER_N, PAILLIER_G, PAILLIER_N_SQUARED, PAILLIER_PUB

    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.connect((HOST, PORT))
            print(f"\n[Client] Connected to Gateway for {seller['name']}.")

            # --- 1. Diffie-Hellman Key Exchange ---
            shared_secret = dh_key_exchange(s)

            # 2. Receive Paillier Public Key (N, G) from server (sent as raw bytes)

            # Receive server's public Paillier key (N, G)
            # The length of N and G depends on the Paillier KEY_LENGTH (1024 bits)
            # 1024 bits is 128 bytes. The +1 and +2 are padding for a safe receive buffer.
            n_bytes_len = 128 + 1
            g_bytes_len = 128 + 2

            # The server sends its public key after the DH exchange
            n_bytes = s.recv(n_bytes_len)
            g_bytes = s.recv(g_bytes_len)

            if not n_bytes or not g_bytes:
                print("[Client] ERROR: Failed to receive Paillier Public Key from server.")
                return

            PAILLIER_N = int.from_bytes(n_bytes, 'big')
            PAILLIER_G = int.from_bytes(g_bytes, 'big')
            PAILLIER_N_SQUARED = PAILLIER_N * PAILLIER_N
            PAILLIER_PUB = (PAILLIER_N, PAILLIER_G)

            # 3. Generate Encrypted Summary and Signed Payload
            initial_transactions = seller["transactions"]
            summary, payload = generate_transaction_summary(seller)

            # 4. Encrypt the entire payload using the DH shared secret
            payload_str = json.dumps(payload)
            iv = os.urandom(AES.block_size)
            encrypted_payload = encrypt_aes(payload_str.encode('utf-8'), shared_secret, iv)

            # 5. Send IV + encrypted payload
            s.sendall(iv)
            s.sendall(encrypted_payload)
            print(f"[Client] Sent encrypted transaction payload for {seller['name']}.")

            # 6. Receive Response length
            len_bytes = s.recv(4)
            if not len_bytes:
                raise ConnectionError("Server closed connection before response.")
            response_len = int.from_bytes(len_bytes, 'big')

            # 7. Receive Response
            response_str = s.recv(response_len).decode('utf-8')
            response = json.loads(response_str)

            # 8. Update Summary
            summary["Total Decrypted Transaction Amount"] = response.get("decrypted_total", "ERROR")
            summary["Signature Verification Result"] = response.get("verification_result", "ERROR")
            summary["Digital Signature Status"] = "Verified (Server)"

            # 9. Display final summary
            display_final_summary(summary, initial_transactions)

    except ConnectionRefusedError:
        print(
            f"\n[FATAL ERROR] Connection refused. Ensure the Payment Gateway Server ({HOST}:{PORT}) is running first.")
    except Exception as e:
        print(f"\n[ERROR] An unexpected error occurred: {e}")


if __name__ == '__main__':
    for seller in SELLER_DATA:
        process_seller_transaction(seller)
