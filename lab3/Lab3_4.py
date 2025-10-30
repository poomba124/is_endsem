import os
import time
import csv
from pathlib import Path
from Crypto.PublicKey import RSA, ECC
from Crypto.Cipher import PKCS1_OAEP, AES
from Crypto.Random import get_random_bytes
from Crypto.Protocol.KDF import PBKDF2
from Crypto.Hash import SHA256

# ---------- Utilities ----------
def gen_file(path: str, mb: int):
    size = mb * 1024 * 1024
    p = Path(path)
    if not p.exists() or p.stat().st_size != size:
        print(f"Generating {path} ({mb} MB)...")
        with open(path, "wb") as f:
            f.write(get_random_bytes(size))

def now(): return time.perf_counter()

def save_results_csv(results, fname="results.csv"):
    keys = ["algorithm","metric","1MB","10MB"]
    rows = []
    for alg, metrics in results.items():
        rows.append([alg, "keygen", f"{metrics['keygen']:.6f}", ""])
        rows.append([alg, "encrypt_1MB", f"{metrics['enc_1MB']:.6f}", ""])
        rows.append([alg, "decrypt_1MB", f"{metrics['dec_1MB']:.6f}", ""])
        rows.append([alg, "encrypt_10MB", f"{metrics['enc_10MB']:.6f}", ""])
        rows.append([alg, "decrypt_10MB", f"{metrics['dec_10MB']:.6f}", ""])
    with open(fname, "w", newline="") as csvf:
        w = csv.writer(csvf)
        w.writerow(keys)
        w.writerows(rows)
    print(f"Saved results to {fname}")

# ---------- AES-GCM helpers ----------
def aes_encrypt(plaintext: bytes, key: bytes):
    nonce = get_random_bytes(12)
    cipher = AES.new(key, AES.MODE_GCM, nonce=nonce)
    ct, tag = cipher.encrypt_and_digest(plaintext)
    return nonce, ct, tag

def aes_decrypt(nonce: bytes, ct: bytes, tag: bytes, key: bytes):
    cipher = AES.new(key, AES.MODE_GCM, nonce=nonce)
    return cipher.decrypt_and_verify(ct, tag)

# ---------- RSA hybrid ----------
def rsa_generate(bits=2048):
    return RSA.generate(bits)

def rsa_wrap_key(aes_key: bytes, pubkey):
    cipher = PKCS1_OAEP.new(pubkey, hashAlgo=SHA256)
    return cipher.encrypt(aes_key)

def rsa_unwrap_key(enc_key: bytes, privkey):
    cipher = PKCS1_OAEP.new(privkey, hashAlgo=SHA256)
    return cipher.decrypt(enc_key)

def rsa_encrypt_file(filepath: str, pubkey):
    data = open(filepath, "rb").read()
    aes_key = get_random_bytes(32)
    nonce, ct, tag = aes_encrypt(data, aes_key)
    wrapped = rsa_wrap_key(aes_key, pubkey)
    wk_len = len(wrapped).to_bytes(2, "big")
    payload = wk_len + wrapped + nonce + ct + tag
    return payload

def rsa_decrypt_file(payload: bytes, privkey):
    wk_len = int.from_bytes(payload[:2], "big")
    wrapped = payload[2:2+wk_len]
    offset = 2 + wk_len
    nonce = payload[offset:offset+12]; offset += 12
    tag = payload[-16:]
    ct = payload[offset:-16]
    aes_key = rsa_unwrap_key(wrapped, privkey)
    pt = aes_decrypt(nonce, ct, tag, aes_key)
    return pt

# ---------- ECC hybrid ----------
def ecc_generate():
    return ECC.generate(curve="secp256r1")

def ecc_derive_key_shared(ephemeral_priv, receiver_pub_point, salt):
    ss_point = ephemeral_priv.d * receiver_pub_point
    ss_x = int(ss_point.x).to_bytes(32, "big")
    return PBKDF2(ss_x, salt, dkLen=32, count=100_000, hmac_hash_module=SHA256)

def ecc_encrypt_file(filepath: str, receiver_pub_point):
    data = open(filepath, "rb").read()
    eph = ECC.generate(curve="secp256r1")
    salt = get_random_bytes(16)
    aes_key = ecc_derive_key_shared(eph, receiver_pub_point, salt)
    nonce, ct, tag = aes_encrypt(data, aes_key)
    x = int(eph.public_key().pointQ.x).to_bytes(32, "big")
    y = int(eph.public_key().pointQ.y).to_bytes(32, "big")
    epk = x + y
    payload = salt + epk + nonce + ct + tag
    return payload

def ecc_decrypt_file(payload: bytes, receiver_privkey):
    salt = payload[:16]
    epk = payload[16:16+64]
    x = int.from_bytes(epk[:32], "big")
    y = int.from_bytes(epk[32:], "big")
    peer_point = ECC.EccPoint(x, y, curve="secp256r1")
    offset = 16 + 64
    nonce = payload[offset:offset+12]; offset += 12
    tag = payload[-16:]
    ct = payload[offset:-16]
    aes_key = ecc_derive_key_shared(receiver_privkey, peer_point, salt)
    pt = aes_decrypt(nonce, ct, tag, aes_key)
    return pt

# ---------- Benchmark runner ----------
def run_bench():
    sf = "1MB.bin"
    lf = "10MB.bin"
    gen_file(sf, 1)
    gen_file(lf, 10)
    results = {"RSA":{}, "ECC":{}}

    print("\n--- RSA (2048) benchmark ---")
    t0 = now(); rsa_priv = rsa_generate(2048); t1 = now()
    results["RSA"]["keygen"] = t1 - t0
    t0 = now(); r1_payload = rsa_encrypt_file(sf, rsa_priv.publickey()); t1 = now()
    results["RSA"]["enc_1MB"] = t1 - t0
    t0 = now(); r1_plain = rsa_decrypt_file(r1_payload, rsa_priv); t1 = now()
    results["RSA"]["dec_1MB"] = t1 - t0
    assert open(sf, "rb").read() == r1_plain, "RSA 1MB roundtrip mismatch!"
    t0 = now(); r10_payload = rsa_encrypt_file(lf, rsa_priv.publickey()); t1 = now()
    results["RSA"]["enc_10MB"] = t1 - t0
    t0 = now(); r10_plain = rsa_decrypt_file(r10_payload, rsa_priv); t1 = now()
    results["RSA"]["dec_10MB"] = t1 - t0
    assert open(lf, "rb").read() == r10_plain, "RSA 10MB roundtrip mismatch!"

    print("\n--- ECC (secp256r1) benchmark ---")
    t0 = now(); ecc_priv = ecc_generate(); t1 = now()
    results["ECC"]["keygen"] = t1 - t0
    t0 = now(); e1_payload = ecc_encrypt_file(sf, ecc_priv.public_key().pointQ); t1 = now()
    results["ECC"]["enc_1MB"] = t1 - t0
    t0 = now(); e1_plain = ecc_decrypt_file(e1_payload, ecc_priv); t1 = now()
    results["ECC"]["dec_1MB"] = t1 - t0
    assert open(sf, "rb").read() == e1_plain, "ECC 1MB roundtrip mismatch!"
    t0 = now(); e10_payload = ecc_encrypt_file(lf, ecc_priv.public_key().pointQ); t1 = now()
    results["ECC"]["enc_10MB"] = t1 - t0
    t0 = now(); e10_plain = ecc_decrypt_file(e10_payload, ecc_priv); t1 = now()
    results["ECC"]["dec_10MB"] = t1 - t0
    assert open(lf, "rb").read() == e10_plain, "ECC 10MB roundtrip mismatch!"

    print("\n--- Performance Results (seconds) ---")
    hdr = f"{'Metric':<20} | {'RSA':<12} | {'ECC':<12}"
    print(hdr)
    print("-" * len(hdr))
    rows = [
        ("Key Generation", results["RSA"]["keygen"], results["ECC"]["keygen"]),
        ("Encrypt 1MB", results["RSA"]["enc_1MB"], results["ECC"]["enc_1MB"]),
        ("Decrypt 1MB", results["RSA"]["dec_1MB"], results["ECC"]["dec_1MB"]),
        ("Encrypt 10MB", results["RSA"]["enc_10MB"], results["ECC"]["enc_10MB"]),
        ("Decrypt 10MB", results["RSA"]["dec_10MB"], results["ECC"]["dec_10MB"]),
    ]
    for name, r, e in rows:
        print(f"{name:<20} | {r:<12.6f} | {e:<12.6f}")

    save_results_csv(results)
    return results

if __name__ == "__main__":
    results = run_bench()
    print("\nDone.")
