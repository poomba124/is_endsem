import socket
import hashlib
import json
from Crypto.Util.number import getPrime, inverse, bytes_to_long, long_to_bytes
from typing import Dict, Any, Tuple, List

# --- NETWORK CONFIGURATION ---
HOST = "127.0.0.1"
PORT = 65433

# --- CRYPTOGRAPHY UTILS (Client Side) ---
KEY_LENGTH = 1024

# Globals to be set after receiving public key from server
PAILLIER_N = None
PAILLIER_G = None
PAILLIER_N_SQUARED = None
PAILLIER_PUB = None


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
    # The homomorphic property: D(c1 * c2 mod n^2) = m1 + m2 mod n
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
    print(
        f"  Total Decrypted (Gateway Result):  {summary['Total Decrypted Transaction Amount'] if isinstance(summary['Total Decrypted Transaction Amount'], str) else int(summary['Total Decrypted Transaction Amount']):,}")

    # 3. Signature Section
    print("\n--- 3. Digital Signature (RSA & SHA-256) ---")
    print(f"  Digital Signature Status:          {summary['Digital Signature Status']}")
    print(f"  Verification Result:               {status}")

    print("=" * 95 + "\n")


def process_seller_transaction(seller: Dict[str, Any]):
    """Connects to server, sends payload, and processes response."""

    global PAILLIER_N, PAILLIER_G, PAILLIER_N_SQUARED, PAILLIER_PUB

    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.connect((HOST, PORT))
            print(f"\n[Client] Connected to Gateway for {seller['name']}.")

            # 1. Receive Paillier Public Key (N, G) from server
            n_bytes = s.recv(KEY_LENGTH // 8)
            g_bytes = s.recv(KEY_LENGTH // 8 + 1)

            if not n_bytes or not g_bytes:
                print("[Client] ERROR: Failed to receive Paillier Public Key from server.")
                return

            PAILLIER_N = int.from_bytes(n_bytes, 'big')
            PAILLIER_G = int.from_bytes(g_bytes, 'big')
            PAILLIER_N_SQUARED = PAILLIER_N * PAILLIER_N
            PAILLIER_PUB = (PAILLIER_N, PAILLIER_G)

            # 2. Generate Encrypted Summary and Signed Payload
            initial_transactions = seller["transactions"]
            summary, payload = generate_transaction_summary(seller)
            payload_str = json.dumps(payload)

            # 3. Send payload
            s.sendall(len(payload_str).to_bytes(4, 'big'))  # Send length first
            s.sendall(payload_str.encode('utf-8'))
            print(f"[Client] Sent signed transaction for {seller['name']}.")

            # 4. Receive Response length
            len_bytes = s.recv(4)
            if not len_bytes:
                raise ConnectionError("Server closed connection before response.")
            response_len = int.from_bytes(len_bytes, 'big')

            # 5. Receive Response
            response_str = s.recv(response_len).decode('utf-8')
            response = json.loads(response_str)

            # 6. Update Summary
            summary["Total Decrypted Transaction Amount"] = response.get("decrypted_total", "ERROR")
            summary["Signature Verification Result"] = response.get("verification_result", "ERROR")
            summary["Digital Signature Status"] = "Verified (Server)"

            # 7. Display final summary
            display_final_summary(summary, initial_transactions)

    except ConnectionRefusedError:
        print(
            f"\n[FATAL ERROR] Connection refused. Ensure the Payment Gateway Server ({HOST}:{PORT}) is running first.")
    except Exception as e:
        print(f"\n[ERROR] An unexpected error occurred: {e}")


if __name__ == '__main__':
    for seller in SELLER_DATA:
        process_seller_transaction(seller)
