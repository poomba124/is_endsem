import socket
import hashlib
import json
from Crypto.Util.number import getPrime, inverse, bytes_to_long, isPrime, getRandomRange
from Crypto.Cipher import AES
from Crypto.Util import Counter
from typing import Tuple, Dict, Any
import threading
import sys
import os

# --- NETWORK CONFIGURATION ---
HOST = "127.0.0.1"
PORT = 65433
# DH parameters (public and known to both parties)
DH_G = 2
DH_P = 0xFFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD129024E088A67CC74020BBEA63B139B22514A08798E3404DDEF9519B3CD3A431B302B0A6DF25F14374FE1356D6D51C245E485B576625E7EC6F44C42E9A637ED6B0BFF5CB6F406B7EDEE386BFB5A899FA5AEF9BAEBC3AADBCD1AE49D6A95B518E6490605B8ACBABFE0B6E36E2313DAA62DC3E3A1C20EE4D6922A236C6580DC48CEE054DCA7B804918E8B62DAF0F7732F680D9C40B8C8EEA68B012DA9501377484DDC56E70C58380F92B82F3B660205AE2C015FDFB1238C5AA71C98EDEE7417F6A24470DC00EE1B52B75A5AEC318CE44E7AD010882774C37A35ED8AEFF770732A78FDE557CBBC2A31A76F40E91910602A9DE3A7E56BC99A814EEA0E0767A99B97FEE34F5C4A003108B7B76F02888602283E2A449F30ED717CB94921EAE4F2818A89A6EE010E000000000000000000092E
DH_KEY_SIZE = 256  # 256-bit hash key for AES

# Calculate the precise byte length required for DH_P (2048-bit prime)
# It should be 256 bytes, ensuring consistency.
DH_BYTE_LENGTH = (DH_P.bit_length() + 7) // 8  # 256
# --- CRYPTOGRAPHY UTILS & PAILLIER KEY GENERATION (Server Side) ---
KEY_LENGTH = 1024

# Global variables for the shared secret and AES
SHARED_SECRET = None


def dh_key_exchange(conn: socket.socket) -> bytes:
    """Performs Diffie-Hellman Key Exchange and returns the shared secret K."""
    print("[Gateway] Starting Diffie-Hellman Key Exchange...")

    # 1. Server generates its private key (b) and public key (B)
    b_private = getRandomRange(1, DH_P - 1)
    B_public = pow(DH_G, b_private, DH_P)

    # 2. Server sends its public key (B) using the fixed DH_BYTE_LENGTH
    conn.sendall(B_public.to_bytes(DH_BYTE_LENGTH, 'big'))

    # 3. Server receives client's public key (A) using the fixed DH_BYTE_LENGTH
    A_public_bytes = conn.recv(DH_BYTE_LENGTH)
    A_public = int.from_bytes(A_public_bytes, 'big')

    # 4. Server computes the shared secret K = A^b mod p
    K_shared_int = pow(A_public, b_private, DH_P)

    # 5. Hash K to get the final 256-bit key for AES
    K_shared_hash = hashlib.sha256(K_shared_int.to_bytes(DH_BYTE_LENGTH, 'big')).digest()

    print("[Gateway] DH Key Exchange complete. Shared Secret established.")
    return K_shared_hash


def decrypt_aes(ciphertext: bytes, key: bytes, iv: bytes) -> bytes:
    """Decrypts data using AES-256 CBC mode."""
    cipher = AES.new(key, AES.MODE_CBC, iv)
    decrypted_padded = cipher.decrypt(ciphertext)
    # Remove simple PKCS#7 padding
    padding_len = decrypted_padded[-1]
    return decrypted_padded[:-padding_len]


def gcd(a, b):
    """Computes the greatest common divisor of a and b."""
    while b:
        a, b = b, a % b
    return a


# --- FIX APPLIED HERE ---
def is_probable_prime(n: int) -> bool:
    """Checks if a number is likely prime using Miller-Rabin (wrapper for isPrime)."""
    # FIX: Removed 'rounds' argument as it causes TypeError in some PyCryptodome versions.
    return isPrime(n)


def _paillier_key_generation(n_length=KEY_LENGTH, p_input=None, q_input=None) -> Tuple[
    Tuple[int, int], Tuple[int, int]]:
    """Generates Paillier keys (Public, Private). If p_input or q_input are provided, they are used."""

    # 1. Get Primes p and q (using user input or secure random generation)
    if p_input and q_input:
        p = p_input
        q = q_input
        print(f"[Gateway] Using user-provided primes p and q for key generation.")
    else:
        print(f"[Gateway] Generating new secure random primes of {n_length // 2} bits...")

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
            print("[Gateway] ERROR: User-provided primes failed the security check (gcd(n, lambda) != 1).")
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

    # Final check on modulus size relative to transaction amounts.
    if n < 2000 and not (p_input and q_input):
        print(
            f"[Gateway] Warning: Generated modulus N is small ({n}). Retrying key generation to ensure adequate size.")
        return _paillier_key_generation(n_length)

    print(f"[Gateway] Paillier Modulus N ({n.bit_length()} bits) is: {n}")

    return public_key, private_key


def decrypt_paillier(c: int) -> int:
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

    try:
        p_str = input("Enter the first large prime number (p) or leave blank for secure random generation: ")
        if p_str:
            p = int(p_str)
            if not is_probable_prime(p):
                print("[Gateway] WARNING: p is not a probable prime. Using secure random generation instead.")
                p = None

        q_str = input("Enter the second large prime number (q) or leave blank for secure random generation: ")
        if q_str:
            q = int(q_str)
            if not is_probable_prime(q):
                print("[Gateway] WARNING: q is not a probable prime. Using secure random generation instead.")
                q = None

    except ValueError:
        print("[Gateway] Invalid input (must be an integer). Falling back to secure random generation.")
        p = None
        q = None

    # Only return both if both passed or were blank
    if p and q:
        return p, q
    elif p_str or q_str:  # If one was entered but failed/was missing
        return None, None  # Fallback to secure generation
    else:
        return None, None  # Fallback to secure generation (both blank)


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
    sys.exit(1)


def handle_client(conn: socket.socket, addr: tuple):
    """Handles a single connection (transaction) from a seller."""
    print(f"\n[Gateway] Connection established with {addr}")

    # --- 1. Diffie-Hellman Key Exchange ---
    try:
        shared_secret = dh_key_exchange(conn)
    except Exception as e:
        print(f"[Gateway] DH Key Exchange failed with {addr}: {e}")
        conn.close()
        return

    try:
        # 2. Receive AES Encrypted Paillier Public Key (IV + Ciphertext)
        # We've simplified this logic in the client, but the server still needs
        # to proceed to receiving the main transaction payload.

        # 3. Receive the length of the incoming data (main transaction payload)
        len_bytes = conn.recv(4)
        if not len_bytes:
            print("[Gateway] Client disconnected unexpectedly.")
            return
        payload_len = int.from_bytes(len_bytes, 'big')

        # 4. Receive the payload data
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

        # 5. Deserialize and extract data
        encrypted_total = int(payload["encrypted_total"], 16)
        signature = int(payload["signature"], 16)
        rsa_pub_key = (int(payload["public_key_n"], 16), int(payload["public_key_e"], 16))
        summary_str = payload["summary_str"]
        seller_name = payload["seller_name"]

        print(f"[Gateway] Received transaction from {seller_name}.")

        # 6. Digital Signature Verification
        is_valid = verify_summary(summary_str, signature, rsa_pub_key)
        verification_result = "SUCCESS: Signature VALID" if is_valid else "FAILURE: Signature INVALID"

        # 7. Paillier Decryption
        decrypted_total = -1
        if is_valid:
            try:
                decrypted_total = decrypt_paillier(encrypted_total)
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
