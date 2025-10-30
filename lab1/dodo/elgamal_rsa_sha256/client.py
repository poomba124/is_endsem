import socket
import hashlib
import json
from Crypto.Util.number import getPrime, inverse, bytes_to_long, getRandomRange
from typing import Dict, Any, Tuple, List
import os
import sys

# --- NETWORK CONFIGURATION ---
HOST = "127.0.0.1"
PORT = 65433
KEY_BYTE_LENGTH = 2048 // 8  # 256 bytes

# Globals to be set after receiving public key from server
ELGAMAL_P = None
ELGAMAL_G = None
ELGAMAL_Y = None
ELGAMAL_PUB: Tuple[int, int, int] = (0, 0, 0)  # (p, g, y)


# --- CRYPTOGRAPHY UTILS (Client Side) ---

def encrypt(m: int, p: int, g: int, y: int) -> Tuple[int, int]:
    """Encrypts a plaintext message m using the ElGamal public key (p, g, y)."""

    # Check if plaintext m is smaller than the prime p (crucial for ElGamal)
    if not (0 <= m < p):
        # This should never happen now that p is 2048-bit, but safety first
        print(f"[Client] ERROR: ElGamal plaintext must be less than p. Max m is {p - 1}, got {m}.")
        return (0, 0)

    # Ephemeral private key k (1 < k < p-1)
    k = getRandomRange(2, p - 2)

    # Ciphertext component 1: c1 = g^k mod p
    c1 = pow(g, k, p)

    # Ciphertext component 2: c2 = m * y^k mod p
    # y^k is the shared secret s
    s = pow(y, k, p)
    c2 = (m * s) % p

    return (c1, c2)


def multiply_homomorphically(c_pair_a: Tuple[int, int], c_pair_b: Tuple[int, int], p: int) -> Tuple[int, int]:
    """Homomorphically multiplies two ElGamal ciphertexts (Multiplicative Homomorphism).

    E(m_a) * E(m_b) = E(m_a * m_b)
    """
    c1a, c2a = c_pair_a
    c1b, c2b = c_pair_b

    # [c1a * c1b mod p] and [c2a * c2b mod p]
    c1_prod = (c1a * c1b) % p
    c2_prod = (c2a * c2b) % p

    return (c1_prod, c2_prod)


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
    """Encrypts transactions, computes the homomorphic total (multiplication), and signs the summary."""

    # Calculate the plaintext product for verification
    plaintext_product = 1
    for tx in seller["transactions"]:
        plaintext_product *= tx

    # Encrypt individual transactions
    encrypted_amounts = [encrypt(tx, ELGAMAL_P, ELGAMAL_G, ELGAMAL_Y)
                         for tx in seller["transactions"]]

    # Homomorphic Multiplication (E(m1) * E(m2) * ... = E(m1 * m2 * ...))
    total_encrypted_c1 = encrypted_amounts[0][0]
    total_encrypted_c2 = encrypted_amounts[0][1]

    for c_pair in encrypted_amounts[1:]:
        total_encrypted_c1, total_encrypted_c2 = multiply_homomorphically(
            (total_encrypted_c1, total_encrypted_c2),
            c_pair,
            ELGAMAL_P
        )

    total_encrypted_amount = (total_encrypted_c1, total_encrypted_c2)

    # Build the initial summary for display
    summary = {
        "Seller Name": seller["name"],
        "Individual Transaction Amounts": seller["transactions"],
        "Encrypted Transaction Components (C1, C2)": encrypted_amounts,
        "Total Encrypted Transaction (C1, C2)": total_encrypted_amount,
        "Total Decrypted Amount (Product)": "Pending",
        "Digital Signature Status": "Signed (Client)",
        "Signature Verification Result": "Pending",
        "Plaintext Product (Expected)": plaintext_product
    }

    # --- Digital Signature ---
    data_to_sign = {
        "Name": summary["Seller Name"],
        "Encrypted C1": hex(total_encrypted_c1),
        "Encrypted C2": hex(total_encrypted_c2)
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
        "encrypted_total_c1": hex(total_encrypted_c1),
        "encrypted_total_c2": hex(total_encrypted_c2)
    }

    return summary, payload


def display_final_summary(summary: Dict[str, Any], initial_transactions: List[int]):
    """Prints the final, updated transaction summary."""

    status = summary.get('Signature Verification Result', 'UNKNOWN')

    print("\n" + "=" * 110)
    print(f"                                   FINAL TRANSACTION REPORT FOR {summary['Seller Name']}")
    print("=" * 110)

    # 1. Individual Transactions Section
    print("\n--- 1. Individual Transactions (ElGamal Encryption & Homomorphic MULTIPLICATION) ---")

    for i, (p_amt, c_pair) in enumerate(zip(
            initial_transactions,
            summary["Encrypted Transaction Components (C1, C2)"]
    )):
        # Display Encrypted Amount as a short hex string
        print(
            f"  TX {i + 1}: Amount: {p_amt:,} | Encrypted C1: {hex(c_pair[0])[:12]}... | Encrypted C2: {hex(c_pair[1])[:12]}...")

    # 2. Total Section
    print("\n--- 2. Total Computation (ElGamal Multiplicative Property) ---")
    print(f"  Total Plain Amount (Product Expected):  {summary['Plaintext Product (Expected)']:,}")
    c1, c2 = summary['Total Encrypted Transaction (C1, C2)']
    print(f"  Total Encrypted C1 (Homomorphic Product): {hex(c1)[:20]}...")
    print(f"  Total Encrypted C2 (Homomorphic Product): {hex(c2)[:20]}...")

    # FIX: Safely convert decrypted_amount to int for formatting.
    decrypted_amount = summary['Total Decrypted Amount (Product)']

    try:
        # Check if the result is a number string (like "216000000") and format it
        if isinstance(decrypted_amount, str) and decrypted_amount.isdigit():
            display_amount = f"{int(decrypted_amount):,}"
        else:
            # Display as-is for error strings ("ERROR", "DECRYPTION_ERROR")
            display_amount = decrypted_amount
    except ValueError:
        display_amount = "PARSE_ERROR"

    print(f"  Total Decrypted (Gateway Product Result): {display_amount}")

    # 3. Signature Section
    print("\n--- 3. Digital Signature (RSA & SHA-256) ---")
    print(f"  Digital Signature Status:          {summary['Digital Signature Status']}")
    print(f"  Verification Result:               {status}")

    print("=" * 110 + "\n")


def receive_data(s: socket.socket, length: int) -> bytes:
    """Utility function to reliably receive a fixed number of bytes from the socket."""
    data = b''
    while len(data) < length:
        packet = s.recv(length - len(data))
        if not packet:
            raise ConnectionError("Connection closed unexpectedly before full data received.")
        data += packet
    return data


def process_seller_transaction(seller: Dict[str, Any]):
    """Connects to server, receives public keys, sends payload, and processes response."""

    global ELGAMAL_P, ELGAMAL_G, ELGAMAL_Y, ELGAMAL_PUB

    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.connect((HOST, PORT))
            print(f"\n[Client] Connected to Gateway for {seller['name']}.")

            # 1. Receive ElGamal Public Key (p, g, y) from server (sent as raw bytes)
            # Use the robust receiver to ensure exactly KEY_BYTE_LENGTH bytes are read for each component
            p_bytes = receive_data(s, KEY_BYTE_LENGTH)
            g_bytes = receive_data(s, KEY_BYTE_LENGTH)
            y_bytes = receive_data(s, KEY_BYTE_LENGTH)

            if not p_bytes or not g_bytes or not y_bytes:
                print("[Client] ERROR: Failed to receive complete ElGamal Public Key from server.")
                return

            ELGAMAL_P = int.from_bytes(p_bytes, 'big')
            ELGAMAL_G = int.from_bytes(g_bytes, 'big')
            ELGAMAL_Y = int.from_bytes(y_bytes, 'big')
            ELGAMAL_PUB = (ELGAMAL_P, ELGAMAL_G, ELGAMAL_Y)
            print("[Client] Received ElGamal Public Key from Gateway.")

            # 2. Generate Encrypted Summary and Signed Payload
            initial_transactions = seller["transactions"]
            summary, payload = generate_transaction_summary(seller)

            # 3. Prepare payload for transmission
            payload_str = json.dumps(payload)

            # 4. Send Payload length (4 bytes)
            s.sendall(len(payload_str).to_bytes(4, 'big'))

            # 5. Send Payload
            s.sendall(payload_str.encode('utf-8'))
            print(f"[Client] Sent transaction payload for {seller['name']}.")

            # 6. Receive Response length (4 bytes)
            len_bytes = receive_data(s, 4)
            response_len = int.from_bytes(len_bytes, 'big')

            # 7. Receive Response
            response_data = receive_data(s, response_len)

            response_str = response_data.decode('utf-8')
            response = json.loads(response_str)

            # 8. Update Summary
            summary["Total Decrypted Amount (Product)"] = response.get("decrypted_total", "ERROR")
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
