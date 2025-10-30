import os
import time
import csv
from pathlib import Path
from Crypto.PublicKey import RSA, ECC
from Crypto.Cipher import PKCS1_OAEP, AES
from Crypto.Random import get_random_bytes
from Crypto.Protocol.KDF import PBKDF2
from Crypto.Hash import SHA256

# ---------- UTILITY FUNCTIONS ----------
# Generates a file of a specified size in megabytes if it doesn't exist.
def gen_file(path: str, mb: int):
    size = mb * 1024 * 1024
    p = Path(path)
    if not p.exists() or p.stat().st_size != size:
        print(f"Generating {path} ({mb} MB)...")
        with open(path, "wb") as f:
            f.write(get_random_bytes(size))

# A helper to get the current high-precision time.
def now(): return time.perf_counter()

# Saves the final benchmark results to a CSV file.
def save_results_csv(results, fname="results.csv"):
    keys = ["algorithm","metric","1MB","10MB","KeyGen Time"]
    rows = []
    for alg, metrics in results.items():
        rows.append([alg, "Key Generation", "", "", f"{metrics['keygen']:.6f}"])
        rows.append([alg, "Encryption", f"{metrics['enc_1MB']:.6f}", f"{metrics['enc_10MB']:.6f}", ""])
        rows.append([alg, "Decryption", f"{metrics['dec_1MB']:.6f}", f"{metrics['dec_10MB']:.6f}", ""])
    with open(fname, "w", newline="") as csvf:
        w = csv.writer(csvf)
        w.writerow(keys)
        w.writerows(rows)
    print(f"\nSaved results to {fname}")

# ---------- HYBRID ENCRYPTION HELPERS ----------
# Helper to encrypt data using AES-GCM, a secure symmetric cipher mode.
def aes_encrypt(plaintext: bytes, key: bytes):
    nonce = get_random_bytes(12)
    cipher = AES.new(key, AES.MODE_GCM, nonce=nonce)
    ct, tag = cipher.encrypt_and_digest(plaintext)
    return nonce, ct, tag

# Helper to decrypt AES-GCM data, verifying its authenticity.
def aes_decrypt(nonce: bytes, ct: bytes, tag: bytes, key: bytes):
    cipher = AES.new(key, AES.MODE_GCM, nonce=nonce)
    return cipher.decrypt_and_verify(ct, tag)

# ---------- RSA HYBRID IMPLEMENTATION ----------
# Generates an RSA key pair.
def rsa_generate(bits=2048):
    return RSA.generate(bits)

# Uses the RSA public key to encrypt a symmetric AES key ("key wrapping").
def rsa_wrap_key(aes_key: bytes, pubkey):
    cipher = PKCS1_OAEP.new(pubkey, hashAlgo=SHA256)
    return cipher.encrypt(aes_key)

# Uses the RSA private key to decrypt a symmetric AES key.
def rsa_unwrap_key(enc_key: bytes, privkey):
    cipher = PKCS1_OAEP.new(privkey, hashAlgo=SHA256)
    return cipher.decrypt(enc_key)

# Encrypts a whole file using an RSA hybrid scheme.
def rsa_encrypt_file(filepath: str, pubkey):
    data = open(filepath, "rb").read()
    # 1. Generate a new, random AES key for this file only.
    aes_key = get_random_bytes(32)
    # 2. Encrypt the actual file data with the fast AES key.
    nonce, ct, tag = aes_encrypt(data, aes_key)
    # 3. Encrypt the slow-but-small AES key with the RSA public key.
    wrapped_key = rsa_wrap_key(aes_key, pubkey)
    # 4. Package everything together: [wrapped_key_len | wrapped_key | nonce | ciphertext | tag]
    wk_len = len(wrapped_key).to_bytes(2, "big")
    return wk_len + wrapped_key + nonce + ct + tag

# Decrypts a file encrypted with the RSA hybrid scheme.
def rsa_decrypt_file(payload: bytes, privkey):
    # 1. Unpack the payload to separate the wrapped key, nonce, etc.
    wk_len = int.from_bytes(payload[:2], "big")
    wrapped_key = payload[2:2+wk_len]
    offset = 2 + wk_len
    nonce, tag, ct = payload[offset:offset+12], payload[-16:], payload[offset+12:-16]
    # 2. Use the RSA private key to decrypt the wrapped AES key.
    aes_key = rsa_unwrap_key(wrapped_key, privkey)
    # 3. Use the now-decrypted AES key to decrypt the actual file data.
    return aes_decrypt(nonce, ct, tag, aes_key)

# ---------- ECC HYBRID IMPLEMENTATION (ECIES) ----------
# Generates an ECC key pair.
def ecc_generate():
    return ECC.generate(curve="secp256r1")

# Derives a shared AES key from an ECC key exchange (part of ECIES).
def ecc_derive_key_shared(ephemeral_priv, receiver_pub_point, salt):
    # Perform scalar multiplication to get a shared point.
    ss_point = ephemeral_priv.d * receiver_pub_point
    ss_x = int(ss_point.x).to_bytes(32, "big")
    # Use PBKDF2 to turn the shared point into a strong AES key.
    return PBKDF2(ss_x, salt, dkLen=32, count=100_000, hmac_hash_module=SHA256)

# Encrypts a file using an ECC hybrid scheme.
def ecc_encrypt_file(filepath: str, receiver_pub_point):
    data = open(filepath, "rb").read()
    # 1. Generate a new, temporary ECC key pair for this file only ("ephemeral key").
    eph_priv = ECC.generate(curve="secp256r1")
    salt = get_random_bytes(16)
    # 2. Use the ephemeral private key and the receiver's public key to derive a shared AES key.
    aes_key = ecc_derive_key_shared(eph_priv, receiver_pub_point, salt)
    # 3. Encrypt the file data with the fast, derived AES key.
    nonce, ct, tag = aes_encrypt(data, aes_key)
    # 4. Package everything: [salt | ephemeral_public_key | nonce | ciphertext | tag]
    epk = int(eph_priv.public_key().pointQ.x).to_bytes(32,"big") + int(eph_priv.public_key().pointQ.y).to_bytes(32,"big")
    return salt + epk + nonce + ct + tag

# Decrypts a file encrypted with the ECC hybrid scheme.
def ecc_decrypt_file(payload: bytes, receiver_privkey):
    # 1. Unpack the payload.
    salt, epk = payload[:16], payload[16:80]
    offset = 80
    nonce, tag, ct = payload[offset:offset+12], payload[-16:], payload[offset+12:-16]
    # 2. Recreate the ephemeral public point from the payload.
    peer_point = ECC.EccPoint(int.from_bytes(epk[:32],"big"), int.from_bytes(epk[32:],"big"), curve="secp256r1")
    # 3. Use your private key and the ephemeral public key to re-derive the same shared AES key.
    aes_key = ecc_derive_key_shared(receiver_privkey, peer_point, salt)
    # 4. Use the AES key to decrypt the file data.
    return aes_decrypt(nonce, ct, tag, aes_key)

# ---------- BENCHMARK RUNNER ----------
def run_bench():
    # Setup files and results dictionary
    gen_file("1MB.bin", 1)
    gen_file("10MB.bin", 10)
    results = {"RSA":{}, "ECC":{}}
    
    print("\n--- RSA (2048) benchmark ---")
    # Time key generation
    t0 = now(); rsa_priv = rsa_generate(2048); t1 = now()
    results["RSA"]["keygen"] = t1 - t0
    # Time encryption/decryption for 1MB and 10MB files
    t0 = now(); r1_payload = rsa_encrypt_file("1MB.bin", rsa_priv.publickey()); t1 = now()
    results["RSA"]["enc_1MB"] = t1 - t0
    t0 = now(); r1_plain = rsa_decrypt_file(r1_payload, rsa_priv); t1 = now()
    results["RSA"]["dec_1MB"] = t1 - t0
    t0 = now(); r10_payload = rsa_encrypt_file("10MB.bin", rsa_priv.publickey()); t1 = now()
    results["RSA"]["enc_10MB"] = t1 - t0
    t0 = now(); r10_plain = rsa_decrypt_file(r10_payload, rsa_priv); t1 = now()
    results["RSA"]["dec_10MB"] = t1 - t0
    assert open("1MB.bin", "rb").read() == r1_plain

    print("\n--- ECC (secp256r1) benchmark ---")
    # Time key generation
    t0 = now(); ecc_priv = ecc_generate(); t1 = now()
    results["ECC"]["keygen"] = t1 - t0
    # Time encryption/decryption for 1MB and 10MB files
    t0 = now(); e1_payload = ecc_encrypt_file("1MB.bin", ecc_priv.public_key().pointQ); t1 = now()
    results["ECC"]["enc_1MB"] = t1 - t0
    t0 = now(); e1_plain = ecc_decrypt_file(e1_payload, ecc_priv); t1 = now()
    results["ECC"]["dec_1MB"] = t1 - t0
    t0 = now(); e10_payload = ecc_encrypt_file("10MB.bin", ecc_priv.public_key().pointQ); t1 = now()
    results["ECC"]["enc_10MB"] = t1 - t0
    t0 = now(); e10_plain = ecc_decrypt_file(e10_payload, ecc_priv); t1 = now()
    results["ECC"]["dec_10MB"] = t1 - t0
    assert open("10MB.bin", "rb").read() == e10_plain

    # Print results to console and save to CSV
    print("\n--- Performance Results (seconds) ---")
    # ... (printing logic)
    save_results_csv(results)

if __name__ == "__main__":
    run_bench()