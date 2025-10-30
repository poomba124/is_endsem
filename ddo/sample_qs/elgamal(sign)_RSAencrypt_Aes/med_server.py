# med_server.py
# Privacy-preserving Medical Record System (RSA Multiplicative version)
# ---------------------------------------------------------
# Features:
#  - AES-256-GCM for encrypted report content
#  - RSA-OAEP for AES key encapsulation
#  - ElGamal signatures with timestamps
#  - RSA (raw modular) for multiplicative homomorphic aggregation
#  - Persistent JSON storage and threaded TCP server
#
# Usage:  python med_server.py
#
import socket, threading, json, os, time
from Crypto.PublicKey import RSA
from Crypto.Cipher import AES, PKCS1_OAEP
from Crypto.Random import get_random_bytes
from Crypto.Hash import SHA256
from Crypto.Util.number import bytes_to_long, long_to_bytes, getPrime, inverse
import math

STORE_FILE = "med_store.json"
HOST, PORT = "127.0.0.1", 65432
store_lock = threading.Lock()

# --------------------------------------------------------------------
# JSON persistence
# --------------------------------------------------------------------
def load_store():
    if not os.path.exists(STORE_FILE):
        return {"doctors": {}, "reports": {}}
    with open(STORE_FILE, "r") as f:
        return json.load(f)

def save_store(store):
    with store_lock:
        with open(STORE_FILE, "w") as f:
            json.dump(store, f, indent=2, default=str)

store = load_store()

# --------------------------------------------------------------------
# RSA Keypairs
# --------------------------------------------------------------------
# RSA for AES key encapsulation (secure)
if "server_rsa_priv" not in store or not store["server_rsa_priv"]:
    rsa_key = RSA.generate(2048)
    store["server_rsa_priv"] = rsa_key.export_key().decode()
    store["server_rsa_pub"] = rsa_key.publickey().export_key().decode()
    save_store(store)
else:
    rsa_key = RSA.import_key(store["server_rsa_priv"].encode())

# RSA for multiplicative homomorphism (raw modular)
if "homo_rsa_priv" not in store or not store["homo_rsa_priv"]:
    homo_rsa = RSA.generate(2048)
    store["homo_rsa_priv"] = homo_rsa.export_key().decode()
    store["homo_rsa_pub"] = homo_rsa.publickey().export_key().decode()
    save_store(store)
else:
    homo_rsa = RSA.import_key(store["homo_rsa_priv"].encode())
homo_rsa_pub = homo_rsa.publickey()

# --------------------------------------------------------------------
# AES helpers (GCM)
# --------------------------------------------------------------------
def aes_encrypt(pt: bytes, key: bytes):
    cipher = AES.new(key, AES.MODE_GCM)
    ct, tag = cipher.encrypt_and_digest(pt)
    return {"nonce": cipher.nonce.hex(), "ct": ct.hex(), "tag": tag.hex()}

def aes_decrypt(enc, key: bytes):
    cipher = AES.new(key, AES.MODE_GCM, nonce=bytes.fromhex(enc["nonce"]))
    return cipher.decrypt_and_verify(bytes.fromhex(enc["ct"]), bytes.fromhex(enc["tag"]))

# --------------------------------------------------------------------
# ElGamal signature helpers
# --------------------------------------------------------------------
def elgamal_keygen(bits=512):
    p = getPrime(bits)
    g = 2
    x = bytes_to_long(get_random_bytes(32)) % (p - 2) + 1
    y = pow(g, x, p)
    return {"p": p, "g": g, "x": x, "y": y}

def elgamal_verify(msg, sig, pub):
    a, b = sig
    p, g, y = pub["p"], pub["g"], pub["y"]
    H = bytes_to_long(SHA256.new(msg).digest())
    lhs = (pow(y, a, p) * pow(a, b, p)) % p
    rhs = pow(g, H, p)
    return lhs == rhs

# --------------------------------------------------------------------
# Raw RSA multiplicative homomorphic helpers
# --------------------------------------------------------------------
def rsa_homo_encrypt(m_int, pubkey: RSA.RsaKey):
    return pow(m_int, pubkey.e, pubkey.n)

def rsa_homo_decrypt(c_int, privkey: RSA.RsaKey):
    return pow(c_int, privkey.d, privkey.n)

def rsa_homo_multiply(c1, c2, pubkey: RSA.RsaKey):
    return (c1 * c2) % pubkey.n

# --------------------------------------------------------------------
# Message Handlers
# --------------------------------------------------------------------
def handle_register(msg, conn):
    did = msg["doctor_id"]
    with store_lock:
        s = load_store()
        if did in s["doctors"]:
            conn.sendall(json.dumps({"status": "error", "reason": "doctor_exists"}).encode())
            return
        s["doctors"][did] = {
            "rsa_pub": msg["pub_rsa"],
            "elgamal_pub": msg["pub_elgamal"],
            "dept_cipher": msg["dept_cipher"],
            "expenses": [],
            "reports": []
        }
        save_store(s)
    conn.sendall(json.dumps({"status": "ok"}).encode())

def handle_submit_report(msg, conn):
    did = msg["doctor_id"]
    with store_lock:
        s = load_store()
        if did not in s["doctors"]:
            conn.sendall(json.dumps({"status": "error", "reason": "unknown_doctor"}).encode())
            return
        try:
            aes_key = PKCS1_OAEP.new(rsa_key).decrypt(bytes.fromhex(msg["aes_key_rsa_enc"]))
            elg_pub = s["doctors"][did]["elgamal_pub"]
            meta_bytes = json.dumps(msg["report_meta"], sort_keys=True).encode()
            verify_bytes = SHA256.new(meta_bytes + bytes.fromhex(msg["report_enc"]["ct"])).digest()
            if not elgamal_verify(verify_bytes, tuple(msg["elgamal_sig"]), elg_pub):
                conn.sendall(json.dumps({"status": "error", "reason": "invalid_signature"}).encode())
                return
            rid = f"R{int(time.time()*1000)}"
            s["reports"][rid] = {
                "doctor_id": did,
                "report_meta": msg["report_meta"],
                "report_enc": msg["report_enc"],
                "aes_key_enc": msg["aes_key_rsa_enc"],
                "elgamal_sig": msg["elgamal_sig"]
            }
            s["doctors"][did]["reports"].append(rid)
            save_store(s)
            conn.sendall(json.dumps({"status": "ok", "report_id": rid}).encode())
        except Exception as e:
            conn.sendall(json.dumps({"status": "error", "reason": str(e)}).encode())

def handle_add_expense(msg, conn):
    did = msg["doctor_id"]
    with store_lock:
        s = load_store()
        if did not in s["doctors"]:
            conn.sendall(json.dumps({"status": "error", "reason": "unknown_doctor"}).encode())
            return
        s["doctors"][did]["expenses"].append(msg["expense_cipher"])
        save_store(s)
    conn.sendall(json.dumps({"status": "ok"}).encode())

def handle_sum_expenses(msg, conn):
    n = homo_rsa_pub.n
    with store_lock:
        s = load_store()
        if msg.get("scope") == "all":
            agg, any_found = 1, False
            for d, info in s["doctors"].items():
                for c in info["expenses"]:
                    c = int(c)
                    agg = (agg * c) % n if any_found else c
                    any_found = True
            conn.sendall(json.dumps({"status": "ok", "agg_cipher": str(agg) if any_found else None}).encode())
        elif msg.get("scope") == "doctor":
            did = msg["doctor_id"]
            if did not in s["doctors"]:
                conn.sendall(json.dumps({"status": "error", "reason": "unknown_doctor"}).encode())
                return
            expenses = [int(c) for c in s["doctors"][did]["expenses"]]
            if not expenses:
                conn.sendall(json.dumps({"status": "ok", "agg_cipher": None}).encode())
                return
            agg = 1
            for c in expenses:
                agg = (agg * c) % n
            conn.sendall(json.dumps({"status": "ok", "agg_cipher": str(agg)}).encode())
        else:
            conn.sendall(json.dumps({"status": "error", "reason": "invalid_scope"}).encode())

def handle_list_reports(msg, conn):
    with store_lock:
        s = load_store()
        reports = {rid: {
            "doctor_id": r["doctor_id"],
            "report_meta": r["report_meta"],
            "elgamal_sig": r["elgamal_sig"]
        } for rid, r in s["reports"].items()}
    conn.sendall(json.dumps({"status": "ok", "reports": reports}).encode())

handlers = {
    "register": handle_register,
    "submit_report": handle_submit_report,
    "add_expense": handle_add_expense,
    "sum_expenses": handle_sum_expenses,
    "list_reports": handle_list_reports,
}

# --------------------------------------------------------------------
# Server loop
# --------------------------------------------------------------------
def client_thread(conn, addr):
    try:
        data = conn.recv(65536)
        if not data:
            conn.close(); return
        msg = json.loads(data.decode())
        t = msg.get("type")
        if t in handlers:
            handlers[t](msg, conn)
        else:
            conn.sendall(json.dumps({"status": "error", "reason": "unknown_type"}).encode())
    except Exception as e:
        try: conn.sendall(json.dumps({"status":"error","reason":str(e)}).encode())
        except: pass
    finally:
        conn.close()

def main():
    print(f"[Server] Listening on {HOST}:{PORT}")
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.bind((HOST, PORT)); s.listen()
    while True:
        conn, addr = s.accept()
        threading.Thread(target=client_thread, args=(conn, addr), daemon=True).start()

if __name__ == "__main__":
    main()
