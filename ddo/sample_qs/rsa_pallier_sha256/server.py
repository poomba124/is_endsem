import socket
import hashlib
import json
from Crypto.Util.number import getPrime, inverse, bytes_to_long
from typing import Tuple, Dict, Any
import threading

# --- NETWORK CONFIGURATION ---
HOST = "127.0.0.1"
PORT = 65433

# --- CRYPTOGRAPHY UTILS & PAILLIER KEY GENERATION (Server Side) ---
KEY_LENGTH = 1024


def gcd(a, b):
    """Computes the greatest common divisor of a and b."""
    while b:
        a, b = b, a % b
    return a


def _paillier_key_generation(n_length=KEY_LENGTH, p_input=None, q_input=None) -> Tuple[
    Tuple[int, int], Tuple[int, int]]:
    """Generates Paillier keys (Public, Private). If p_input or q_input are provided, they are used."""

    # 1. Get Primes p and q (using user input or secure random generation)
    if p_input and q_input:
        p = p_input
        q = q_input
        print(f"[Gateway] Using user-provided primes p and q for key generation.")
    else:
        print(f"[Gateway] Generating new secure random primes...")

    while True:
        if not (p_input and q_input):
            # Original secure random generation (default)
            p = getPrime(n_length // 2)
            q = getPrime(n_length // 2)

        n = p * q
        # Calculate lambda = lcm(p-1, q-1)
        _lambda = (p - 1) * (q - 1) // gcd(p - 1, q - 1)

        # Check that n is coprime to lambda
        if gcd(n, _lambda) == 1:
            g = n + 1
            break

        # If user input primes failed the check, we cannot proceed with them.
        if p_input and q_input:
            print(
                "[Gateway] ERROR: User-provided primes failed the security check (gcd(n, lambda) != 1). Please restart and try different primes.")
            # Set to None to force exiting the loop if not in interactive mode,
            # or handle failure gracefully. For simplicity, we just stop the attempt.
            raise ValueError("User-provided primes failed security check.")

    n_squared = n * n

    # Pre-calculate mu = L(g^lambda mod n^2)^-1 mod n
    try:
        # L(u) = (u - 1) // n
        L_g_lambda = (pow(g, _lambda, n_squared) - 1) // n
        mu = inverse(L_g_lambda, n)
    except ValueError:
        # If inverse fails, retry (only if using secure random primes)
        if not (p_input and q_input):
            return _paillier_key_generation(n_length)
        else:
            raise ValueError("Inverse calculation failed for user-provided primes.")

    public_key = (n, g)
    private_key = (_lambda, mu)
    return public_key, private_key


def decrypt(c: int) -> int:
    """Decrypts a ciphertext c using the Paillier private key."""
    n, _ = PAILLIER_PUB
    _lambda, mu = PAILLIER_PRIV
    n_squared = n * n

    # L(u) = (u - 1) // n
    L = lambda u: (u - 1) // n

    # Plaintext m = L(c^lambda mod n^2) * mu mod n
    m = (L(pow(c, _lambda, n_squared)) * mu) % n
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


def format_key_output(key: Tuple[int, int]) -> str:
    """Formats a key tuple for cleaner printing."""
    if len(key) == 2:
        return f"(N: {hex(key[0])[:12]}..., Component: {hex(key[1])[:12]}...)"
    return str(key)


def get_user_primes():
    """Prompts the user for two large prime numbers for Paillier key generation."""
    print("\n--- Paillier Key Setup ---")

    p = None
    q = None

    # In a real environment, you would validate the input numbers are actually prime and large.
    # For this simulation, we'll rely on the internal checks and assume the user inputs large integers.
    try:
        p_str = input("Enter the first large prime number (p) or leave blank for secure random generation: ")
        if p_str:
            p = int(p_str)

        q_str = input("Enter the second large prime number (q) or leave blank for secure random generation: ")
        if q_str:
            q = int(q_str)

    except ValueError:
        print("[Gateway] Invalid input. Falling back to secure random generation.")
        p = None
        q = None

    return p, q


# Generate the global Paillier keys
USER_P, USER_Q = get_user_primes()

try:
    PAILLIER_PUB, PAILLIER_PRIV = _paillier_key_generation(p_input=USER_P, q_input=USER_Q)
    PAILLIER_N, _ = PAILLIER_PUB
    PAILLIER_LAMBDA, PAILLIER_MU = PAILLIER_PRIV
    PAILLIER_N_SQUARED = PAILLIER_N * PAILLIER_N
except ValueError as e:
    print(f"\n[FATAL ERROR] Cannot start server. {e}")
    # Exit if user input failed the cryptographic checks
    import sys

    sys.exit(1)


def handle_client(conn: socket.socket, addr: tuple):
    """Handles a single connection (transaction) from a seller."""
    print(f"\n[Gateway] Connection established with {addr}")

    try:
        # 1. Send Paillier Public Key (N, G)
        n, g = PAILLIER_PUB
        conn.sendall(n.to_bytes(KEY_LENGTH // 8, 'big'))
        conn.sendall(g.to_bytes(KEY_LENGTH // 8 + 1, 'big'))  # G = N+1, slightly larger
        print(f"[Gateway] Sent Paillier Public Key to {addr}.")

        # 2. Receive the length of the incoming data
        len_bytes = conn.recv(4)
        if not len_bytes:
            print("[Gateway] Client disconnected unexpectedly.")
            return
        payload_len = int.from_bytes(len_bytes, 'big')

        # 3. Receive the payload data
        data = b''
        while len(data) < payload_len:
            packet = conn.recv(payload_len - len(data))
            if not packet:
                break
            data += packet

        if len(data) != payload_len:
            print("[Gateway] Failed to receive full payload.")
            return

        payload = json.loads(data.decode('utf-8'))

        # 4. Deserialize and extract data
        encrypted_total = int(payload["encrypted_total"], 16)
        signature = int(payload["signature"], 16)
        rsa_pub_key = (int(payload["public_key_n"], 16), int(payload["public_key_e"], 16))
        summary_str = payload["summary_str"]
        seller_name = payload["seller_name"]

        print(f"[Gateway] Received transaction from {seller_name}.")

        # 5. Digital Signature Verification
        is_valid = verify_summary(summary_str, signature, rsa_pub_key)
        verification_result = "SUCCESS: Signature VALID" if is_valid else "FAILURE: Signature INVALID"

        # 6. Paillier Decryption
        decrypted_total = -1
        if is_valid:
            try:
                decrypted_total = decrypt(encrypted_total)
                print(f"[Gateway] Decrypted Total for {seller_name}: {decrypted_total:,}")
            except Exception as e:
                decrypted_total = f"DECRYPTION_ERROR"
                print(f"[Gateway] Decryption failed for {seller_name}: {e}")

        # --- Prepare Response ---
        response = {
            "verification_result": verification_result,
            "decrypted_total": decrypted_total
        }

        # Send response back to client
        response_str = json.dumps(response)
        conn.sendall(len(response_str).to_bytes(4, 'big'))
        conn.sendall(response_str.encode('utf-8'))

    except Exception as e:
        print(f"[Gateway] An error occurred while handling client {addr}: {e}")
    finally:
        conn.close()
        print(f"[Gateway] Connection with {addr} closed.")


def start_server():
    """Initializes and runs the multi-threaded server."""
    print("=" * 60)
    print("           PAYMENT GATEWAY SERVER (Paillier Decryptor & RSA Verifier)")
    print("=" * 60)
    print(f"Paillier Public Key (N, G): {format_key_output(PAILLIER_PUB)}")
    print(f"Paillier Private Key (Lambda, Mu): {format_key_output(PAILLIER_PRIV)}")
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
