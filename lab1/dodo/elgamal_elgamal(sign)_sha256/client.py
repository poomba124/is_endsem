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

    if not (0 <= m < p):
        print(f"[Client] ERROR: ElGamal plaintext must be less than p. Max m is {p - 1}, got {m}.")
        return (0, 0)

    # Ephemeral private key k (1 < k < p-1)
    k = getRandomRange(2, p - 2)

    # Ciphertext component 1: c1 = g^k mod p
    c1 = pow(g, k, p)

    # Ciphertext component 2: c2 = m * y^k mod p
    s = pow(y, k, p)
    c2 = (m * s) % p

    return (c1, c2)


def multiply_homomorphically(c_pair_a: Tuple[int, int], c_pair_b: Tuple[int, int], p: int) -> Tuple[int, int]:
    """Homomorphically multiplies two ElGamal ciphertexts (Multiplicative Homomorphism)."""
    c1a, c2a = c_pair_a
    c1b, c2b = c_pair_b

    c1_prod = (c1a * c1b) % p
    c2_prod = (c2a * c2b) % p

    return (c1_prod, c2_prod)


def _hash_message_to_int(msg: str, p: int):
    """Hashes a string message using SHA-256 and converts the digest to an integer m < p."""
    msg_hash = bytes_to_long(hashlib.sha256(msg.encode('utf-8')).digest())

    # Hash is reduced modulo (p-1) for signature calculation
    return msg_hash % (p - 1)


def generate_elgamal_signing_keys(p: int, g: int) -> Tuple[int, int]:
    """Generates ElGamal signing keys: Private key 'a' and Public key 'y_a'."""
    q = (p - 1)  # Order of the group

    # Private key 'a': 1 < a < p-1
    a = getRandomRange(2, p - 2)

    # Public key 'y_a' = g^a mod p
    y_a = pow(g, a, p)

    return (a, y_a)  # (private_key_a, public_key_y_a)


def sign_elgamal(summary_str: str, private_key_a: int, p: int, g: int) -> Tuple[int, int]:
    """Signs the SHA-256 hash of the transaction summary string (ElGamal Signature)."""

    # 1. Calculate message hash m
    m = _hash_message_to_int(summary_str, p)

    q = (p - 1)

    # Loop to find a valid 'k' (ephemeral signing key) and ensure gcd(k, p-1) == 1
    while True:
        # 2. Choose random ephemeral key 'k' (1 < k < p-1)
        k = getRandomRange(2, p - 2)

        # Check that k is coprime to (p-1)
        try:
            k_inv = inverse(k, q)
            break
        except ValueError:
            # k is not coprime to (p-1), try again
            continue

    # 3. Signature component r = g^k mod p
    r = pow(g, k, p)

    # 4. Signature component s = k^-1 * (m - a*r) mod (p-1)

    # m - a*r mod (p-1)
    m_minus_ar = (m - (private_key_a * r)) % q

    # s = k_inv * m_minus_ar mod (p-1)
    s = (k_inv * m_minus_ar) % q

    return (r, s)


# --- SELLER DATA ---
# Note: RSA keys were replaced with ElGamal signature keys
SELLER_DATA = [
    {
        "name": "Seller Alpha (Retail)",
        "transactions": [1500, 320, 450],
        # ElGamal signature keys will be generated inside process_seller_transaction
    },
    {
        "name": "Seller Beta (Service)",
        "transactions": [50, 120, 25, 300],
        # ElGamal signature keys will be generated inside process_seller_transaction
    }
]


def generate_transaction_summary(seller: Dict[str, Any], signing_keys: Tuple[int, int]) -> Dict[str, Any]:
    """Encrypts transactions, computes homomorphic total, and signs the summary."""

    private_key_a, public_key_y_a = signing_keys

    plaintext_product = 1
    for tx in seller["transactions"]:
        plaintext_product *= tx

    encrypted_amounts = [encrypt(tx, ELGAMAL_P, ELGAMAL_G, ELGAMAL_Y)
                         for tx in seller["transactions"]]

    total_encrypted_c1 = encrypted_amounts[0][0]
    total_encrypted_c2 = encrypted_amounts[0][1]

    for c_pair in encrypted_amounts[1:]:
        total_encrypted_c1, total_encrypted_c2 = multiply_homomorphically(
            (total_encrypted_c1, total_encrypted_c2),
            c_pair,
            ELGAMAL_P
        )

    total_encrypted_amount = (total_encrypted_c1, total_encrypted_c2)

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

    # --- ElGamal Digital Signature ---
    data_to_sign = {
        "Name": summary["Seller Name"],
        "Encrypted C1": hex(total_encrypted_c1),
        "Encrypted C2": hex(total_encrypted_c2)
    }
    signed_data_str = json.dumps(data_to_sign)

    # Sign the data
    signature_r, signature_s = sign_elgamal(signed_data_str, private_key_a, ELGAMAL_P, ELGAMAL_G)

    # Prepare payload for server
    payload = {
        "seller_name": summary["Seller Name"],
        "summary_str": signed_data_str,
        # Signature is now two components
        "signature_r": hex(signature_r),
        "signature_s": hex(signature_s),
        # Public key for signing
        "signing_pub_y_a": hex(public_key_y_a),
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
        print(
            f"  TX {i + 1}: Amount: {p_amt:,} | Encrypted C1: {hex(c_pair[0])[:12]}... | Encrypted C2: {hex(c_pair[1])[:12]}...")

    # 2. Total Section
    print("\n--- 2. Total Computation (ElGamal Multiplicative Property) ---")
    print(f"  Total Plain Amount (Product Expected):  {summary['Plaintext Product (Expected)']:,}")
    c1, c2 = summary['Total Encrypted Transaction (C1, C2)']
    print(f"  Total Encrypted C1 (Homomorphic Product): {hex(c1)[:20]}...")
    print(f"  Total Encrypted C2 (Homomorphic Product): {hex(c2)[:20]}...")

    decrypted_amount = summary['Total Decrypted Amount (Product)']

    try:
        if isinstance(decrypted_amount, str) and decrypted_amount.isdigit():
            display_amount = f"{int(decrypted_amount):,}"
        else:
            display_amount = decrypted_amount
    except ValueError:
        display_amount = "PARSE_ERROR"

    print(f"  Total Decrypted (Gateway Product Result): {display_amount}")

    # 3. Signature Section
    print("\n--- 3. Digital Signature (ElGamal Signature & SHA-256) ---")
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

            # 1. Receive ElGamal Public Key (p, g, y) from server
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

            # --- Generate ElGamal Signing Keys using received p and g ---
            signing_keys = generate_elgamal_signing_keys(ELGAMAL_P, ELGAMAL_G)

            # 2. Generate Encrypted Summary and Signed Payload
            initial_transactions = seller["transactions"]
            summary, payload = generate_transaction_summary(seller, signing_keys)

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
