import socket
import hashlib
import json
import threading
import sys
from typing import Tuple, Dict, Any
from Crypto.Util.number import getPrime, inverse, bytes_to_long, isPrime, getRandomRange

# --- NETWORK CONFIGURATION ---
HOST = "127.0.0.1"
PORT = 65433

# ElGamal key size (2048 bits for prime p)
ELGAMAL_KEY_LENGTH = 2048
KEY_BYTE_LENGTH = ELGAMAL_KEY_LENGTH // 8  # 256 bytes

# Global ElGamal Keys
ELGAMAL_PUB: Tuple[int, int, int] = (0, 0, 0)  # (p, g, y)
ELGAMAL_PRIV: int = 0  # (x)


# --- CRYPTOGRAPHY UTILS & ELGAMAL KEY GENERATION (Server Side) ---

def _elgamal_key_generation(n_length=ELGAMAL_KEY_LENGTH) -> Tuple[Tuple[int, int, int], int]:
    """Generates ElGamal keys (Public: p, g, y, Private: x)."""

    print(f"[Gateway] Generating new secure random prime p of {n_length} bits...")

    # 1. Generate large prime p
    p = getPrime(n_length)

    # 2. Find a generator g (using a simple, working method)
    q = (p - 1) // 2
    g = 2
    # Ensure g is a generator of the large subgroup (g^q mod p != 1)
    while pow(g, q, p) == 1:
        g += 1

        # 3. Private key x (a random integer: 1 < x < p-1)
    x = getRandomRange(2, p - 2)

    # 4. Public key y = g^x mod p
    y = pow(g, x, p)

    public_key = (p, g, y)
    private_key = x

    print(f"[Gateway] ElGamal Prime p ({p.bit_length()} bits) generated.")

    return public_key, private_key


def decrypt_elgamal(c_pair: Tuple[int, int]) -> int:
    """Decrypts an ElGamal ciphertext pair (c1, c2) using the private key x."""
    p, _, _ = ELGAMAL_PUB
    x = ELGAMAL_PRIV
    c1, c2 = c_pair

    # 1. Calculate s = c1^x mod p (Shared secret for this ciphertext)
    s = pow(c1, x, p)

    # 2. Calculate s_inv = s^-1 mod p (Modular inverse)
    # The plaintext m is recovered by multiplying c2 by the inverse of s
    s_inv = inverse(s, p)

    # 3. Plaintext m = c2 * s_inv mod p
    m = (c2 * s_inv) % p
    return m


def _hash_message_to_int(msg: str):
    """Hashes a string message using SHA-256 and converts the digest to a large integer."""
    return bytes_to_long(hashlib.sha256(msg.encode('utf-8')).digest())


def verify_summary(summary_str: str, signature: int, public_key: Tuple[int, int]) -> bool:
    """Verifies a signature against the SHA-256 hash of the transaction summary string (RSA)."""
    n, e = public_key

    expected_hash = _hash_message_to_int(summary_str)
    # Hash_from_signature = Signature^e mod n
    hash_from_signature = pow(signature, e, n)

    return expected_hash == hash_from_signature


def format_key_output(key: Tuple[int, ...]) -> str:
    """Formats a key tuple for cleaner printing."""
    if len(key) == 3:
        return f"(p: {hex(key[0])[:12]}..., g: {hex(key[1])[:8]}..., y: {hex(key[2])[:12]}...)"
    return str(key)


def send_key_component(conn: socket.socket, value: int, length: int):
    """Utility to ensure large key components are sent with fixed length."""
    conn.sendall(value.to_bytes(length, 'big'))


# --- GLOBAL KEY GENERATION ---
try:
    ELGAMAL_PUB, ELGAMAL_PRIV = _elgamal_key_generation()
    ELGAMAL_P, ELGAMAL_G, ELGAMAL_Y = ELGAMAL_PUB
except Exception as e:
    print(f"\n[FATAL ERROR] Cannot generate ElGamal keys: {e}")
    sys.exit(1)


def receive_data(conn: socket.socket, length: int) -> bytes:
    """Utility function to reliably receive a fixed number of bytes from the socket."""
    data = b''
    while len(data) < length:
        packet = conn.recv(length - len(data))
        if not packet:
            # If no more data and we haven't reached the expected length, raise an error
            raise ConnectionError("Connection closed unexpectedly before full payload received.")
        data += packet
    return data


def handle_client(conn: socket.socket, addr: tuple):
    """Handles a single connection (transaction) from a seller."""
    print(f"\n[Gateway] Connection established with {addr}")

    try:
        # --- 1. SEND ELGAMAL PUBLIC KEY (p, g, y) ---
        send_key_component(conn, ELGAMAL_P, KEY_BYTE_LENGTH)
        send_key_component(conn, ELGAMAL_G, KEY_BYTE_LENGTH)
        send_key_component(conn, ELGAMAL_Y, KEY_BYTE_LENGTH)
        print("[Gateway] Sent ElGamal Public Key (p, g, y) to client.")

        # --- 2. RECEIVE PAYLOAD ---
        # Receive the length of the incoming data (main transaction payload)
        len_bytes = receive_data(conn, 4)
        payload_len = int.from_bytes(len_bytes, 'big')

        # Receive the full payload data
        data = receive_data(conn, payload_len)

        payload = json.loads(data.decode('utf-8'))

        # 3. Deserialize and extract data
        encrypted_total_c1 = int(payload["encrypted_total_c1"], 16)
        encrypted_total_c2 = int(payload["encrypted_total_c2"], 16)
        encrypted_total = (encrypted_total_c1, encrypted_total_c2)

        signature = int(payload["signature"], 16)
        rsa_pub_key = (int(payload["public_key_n"], 16), int(payload["public_key_e"], 16))
        summary_str = payload["summary_str"]
        seller_name = payload["seller_name"]

        print(f"[Gateway] Received transaction payload from {seller_name}.")

        # 4. Digital Signature Verification
        is_valid = verify_summary(summary_str, signature, rsa_pub_key)
        verification_result = "SUCCESS: Signature VALID" if is_valid else "FAILURE: Signature INVALID"

        # 5. ElGamal Decryption
        decrypted_total = "N/A"
        if is_valid:
            try:
                decrypted_total = decrypt_elgamal(encrypted_total)
                print(f"[Gateway] Decrypted Product for {seller_name}: {decrypted_total:,}")
            except Exception as e:
                decrypted_total = "DECRYPTION_ERROR"
                print(f"[Gateway] Decryption failed for {seller_name}: {e}")

        # --- 6. Prepare and Send Response ---
        response = {
            "verification_result": verification_result,
            # Ensure decrypted total is serializable
            "decrypted_total": decrypted_total if isinstance(decrypted_total, str) else str(decrypted_total)
        }

        response_str = json.dumps(response)
        conn.sendall(len(response_str).to_bytes(4, 'big'))
        conn.sendall(response_str.encode('utf-8'))

    except ConnectionError as ce:
        print(f"[Gateway] Connection error with {addr}: {ce}")
    except Exception as e:
        print(f"[Gateway] An unexpected error occurred while handling client {addr}: {e}")
    finally:
        conn.close()
        print(f"[Gateway] Connection with {addr} closed.")


def start_server():
    """Initializes and runs the multi-threaded server."""
    print("=" * 75)
    print("                PAYMENT GATEWAY SERVER (ElGamal Decryptor & RSA Verifier)")
    print("=" * 75)
    print(f"ElGamal Public Key (p, g, y): {format_key_output(ELGAMAL_PUB)}")
    print(f"Listening on {HOST}:{PORT}...")

    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        s.bind((HOST, PORT))
        s.listen(5)

        try:
            while True:
                conn, addr = s.accept()
                client_thread = threading.Thread(target=handle_client, args=(conn, addr))
                client_thread.start()
        except KeyboardInterrupt:
            print("\n[Gateway] Server shutting down.")
            s.close()


if __name__ == '__main__':
    start_server()
