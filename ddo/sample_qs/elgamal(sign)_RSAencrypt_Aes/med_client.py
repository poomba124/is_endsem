# med_client.py
# ---------------------------------------------------------
# Client for doctors and auditors
#  - RSA-OAEP for AES key encryption
#  - ElGamal for signatures
#  - RSA multiplicative encryption for expenses/departments
# ---------------------------------------------------------
import socket, json, os, time
from Crypto.PublicKey import RSA
from Crypto.Cipher import AES, PKCS1_OAEP
from Crypto.Random import get_random_bytes
from Crypto.Hash import SHA256
from Crypto.Util.number import bytes_to_long, long_to_bytes, getPrime, inverse

HOST, PORT = "127.0.0.1", 65432
KEYDIR = "client_keys"
os.makedirs(KEYDIR, exist_ok=True)

# ------------------- Network -------------------
def send_recv(payload):
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.connect((HOST, PORT))
    s.sendall(json.dumps(payload).encode())
    data = s.recv(65536)
    s.close()
    return json.loads(data.decode())

# ------------------- ElGamal -------------------
def elgamal_keygen(bits=512):
    p = getPrime(bits)
    g = 2
    x = bytes_to_long(get_random_bytes(32)) % (p - 2) + 1
    y = pow(g, x, p)
    return {"p": p, "g": g, "x": x, "y": y}

def elgamal_sign(msg, priv):
    p, g, x = priv["p"], priv["g"], priv["x"]
    H = bytes_to_long(SHA256.new(msg).digest())
    while True:
        k = bytes_to_long(get_random_bytes(32)) % (p - 2) + 1
        if math.gcd(k, p-1) == 1: break
    a = pow(g, k, p)
    kinv = inverse(k, p-1)
    b = ((H - x*a)*kinv) % (p-1)
    return (a, b)

# ------------------- RSA homomorphic -------------------
def rsa_homo_encrypt(m_int, pub):
    n, e = pub["n"], pub["e"]
    return pow(m_int, e, n)

# ------------------- Doctor workflow -------------------
def register_doctor(did, dept_id, server_homo_pub, server_rsa_pub):
    rsa_key = RSA.generate(2048)
    elg = elgamal_keygen()
    dept_cipher = rsa_homo_encrypt(dept_id, server_homo_pub)
    payload = {
        "type": "register",
        "doctor_id": did,
        "pub_rsa": rsa_key.publickey().export_key().decode(),
        "pub_elgamal": {"p": elg["p"], "g": elg["g"], "y": elg["y"]},
        "dept_cipher": str(dept_cipher)
    }
    resp = send_recv(payload)
    if resp["status"] == "ok":
        with open(f"{KEYDIR}/{did}_rsa.pem", "wb") as f: f.write(rsa_key.export_key())
        with open(f"{KEYDIR}/{did}_elg.json", "w") as f: json.dump(elg, f)
        print("[+] Registered successfully.")
    else:
        print(resp)

def submit_report(did, text, pid, server_rsa_pub):
    rsa_pem = f"{KEYDIR}/{did}_rsa.pem"
    elg_j = f"{KEYDIR}/{did}_elg.json"
    if not os.path.exists(rsa_pem):
        print("Register first."); return
    rsa_key = RSA.import_key(open(rsa_pem,"rb").read())
    elg = json.load(open(elg_j))
    aes_key = get_random_bytes(32)
    cipher = AES.new(aes_key, AES.MODE_GCM)
    ct, tag = cipher.encrypt_and_digest(text.encode())
    enc = {"nonce":cipher.nonce.hex(),"ct":ct.hex(),"tag":tag.hex()}
    server_pub = RSA.import_key(server_rsa_pub.encode())
    enc_key = PKCS1_OAEP.new(server_pub).encrypt(aes_key).hex()
    meta = {"timestamp":time.time(),"patient_id":pid,"description":"report"}
    meta_bytes = json.dumps(meta,sort_keys=True).encode()
    msg_to_sign = SHA256.new(meta_bytes + ct).digest()
    sig = elgamal_sign(msg_to_sign, elg)
    payload = {
        "type":"submit_report",
        "doctor_id":did,
        "aes_key_rsa_enc":enc_key,
        "report_enc":enc,
        "report_meta":meta,
        "elgamal_sig":[sig[0],sig[1]]
    }
    print(send_recv(payload))

def add_expense(did, amount, server_homo_pub):
    c = rsa_homo_encrypt(amount, server_homo_pub)
    payload = {"type":"add_expense","doctor_id":did,"expense_cipher":str(c)}
    print(send_recv(payload))

# ------------------- Auditor -------------------
def auditor_sum(scope, did=None):
    payload = {"type":"sum_expenses","scope":scope}
    if did: payload["doctor_id"]=did
    resp = send_recv(payload)
    if resp.get("agg_cipher"):
        agg = int(resp["agg_cipher"])
        server_store=json.load(open("med_store.json"))
        priv=RSA.import_key(server_store["homo_rsa_priv"].encode())
        result=pow(agg,priv.d,priv.n)
        print(f"Decrypted multiplicative result: {result}")
    print(resp)

def auditor_list():
    print(send_recv({"type":"list_reports"}))

# ------------------- Menu -------------------
def main():
    if not os.path.exists("med_store.json"):
        print("Run server first."); return
    sstore=json.load(open("med_store.json"))
    server_rsa_pub=sstore["server_rsa_pub"]
    hpub=RSA.import_key(sstore["homo_rsa_pub"].encode())
    server_homo_pub={"n":hpub.n,"e":hpub.e}
    print("1) Register doctor\n2) Submit report\n3) Add expense\n4) Auditor sum(all)\n5) Auditor sum(doctor)\n6) List reports\n0) Exit")
    while True:
        op=input("choice> ").strip()
        if op=="1":
            d=input("doctor_id> "); dept=int(input("dept_id(int)> "))
            register_doctor(d,dept,server_homo_pub,server_rsa_pub)
        elif op=="2":
            d=input("doctor_id> "); txt=input("text> "); pid=input("patient_id> ")
            submit_report(d,txt,pid,server_rsa_pub)
        elif op=="3":
            d=input("doctor_id> "); amt=int(input("amount(int)> "))
            add_expense(d,amt,server_homo_pub)
        elif op=="4":
            auditor_sum("all")
        elif op=="5":
            d=input("doctor_id> "); auditor_sum("doctor",d)
        elif op=="6":
            auditor_list()
        elif op=="0": break
        else: print("unknown")

if __name__=="__main__":
    main()
