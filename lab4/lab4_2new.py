from Crypto.Util.number import getPrime, inverse, GCD, bytes_to_long, long_to_bytes
import time

class KeyManagementService:
    def __init__(self, keysize=1024):
        self.keysize = keysize
        # Dictionary to securely store all keys, mapped by entity name.
        self.keys = {}
        # List to maintain a log of all actions for auditing.
        self.logs = []

    # Logs a message with a timestamp.
    def log(self, msg):
        entry = f"[{time.ctime()}] {msg}"
        self.logs.append(entry)
        print(entry)

    # (Key Generation) Generates a public/private key pair for a named entity.
    def gen_keys(self, name):
        # Rabin requires primes p and q such that p ≡ 3 (mod 4) and q ≡ 3 (mod 4).
        p = getPrime(self.keysize // 2)
        q = getPrime(self.keysize // 2)
        while p % 4 != 3 or q % 4 != 3:
            p = getPrime(self.keysize // 2)
            q = getPrime(self.keysize // 2)
        
        # The public key is n = p * q. The private key is the pair (p, q).
        n = p * q
        self.keys[name] = {'n': n, 'p': p, 'q': q, 'revoked': False}
        self.log(f"Generated keys for {name} (n starts with {str(n)[:10]}...)")
        return {'n': n}  # Only distribute the public part (n).

    # (Key Distribution) Retrieves the public key for an entity.
    def get_pubkey(self, name):
        if name in self.keys and not self.keys[name]['revoked']:
            return self.keys[name]['n']
        self.log(f"Failed attempt to get key for {name}. Key revoked or not found.")
        raise Exception("Keys revoked or not found")

    # (Key Revocation) Revokes the key for a given entity.
    def revoke_key(self, name):
        if name in self.keys:
            self.keys[name]['revoked'] = True
            self.log(f"Revoked keys for {name}")

    # (Key Renewal) Generates a new key pair for an existing entity.
    def renew_key(self, name):
        if name not in self.keys:
            raise Exception("Entity not registered")
        self.log(f"Renewing keys for {name}")
        # Renewal is simply a fresh key generation.
        return self.gen_keys(name)

    # (Encryption) Encrypts a message for an entity using their public key.
    def encrypt(self, name, msg: bytes):
        n = self.get_pubkey(name)
        m = bytes_to_long(msg)
        # Encryption is squaring the message modulo n: c = m^2 mod n.
        c = pow(m, 2, n)
        self.log(f"Encrypted message for {name}")
        return c

    # (Decryption) Decrypts a ciphertext using an entity's private key.
    def decrypt(self, name, c: int):
        if name not in self.keys or self.keys[name]['revoked']:
            raise Exception("Keys revoked or missing")

        # Retrieve the private key (p, q) and public key n from secure storage.
        p, q, n = self.keys[name]['p'], self.keys[name]['q'], self.keys[name]['n']
        
        # 1. Find the four square roots of c modulo p and q.
        mp = pow(c, (p + 1) // 4, p)
        mq = pow(c, (q + 1) // 4, q)
        
        # 2. Use the Extended Euclidean Algorithm (via CRT) to find the four possible plaintexts.
        yp = inverse(p, q)
        yq = inverse(q, p)
        r1 = (yp * p * mq + yq * q * mp) % n
        r2 = n - r1
        r3 = (yp * p * mq - yq * q * mp) % n
        r4 = n - r3

        # 3. Check the four candidates to find the original, meaningful message.
        candidates = [r1, r2, r3, r4]
        for cand in candidates:
            try:
                # Attempt to convert the number back to bytes. The correct one won't error out.
                msg = long_to_bytes(cand)
                # Further check if the message makes sense (e.g., is valid text).
                if b"Patient record" in msg or msg.isascii():
                    self.log(f"Decryption successful for {name}")
                    return msg
            except Exception:
                continue
        self.log(f"Decryption failed for {name}, no valid plaintext found.")
        return None

    # (Auditing) Displays the contents of the audit log.
    def show_logs(self):
        print("\n=== Audit Log ===")
        for entry in self.logs:
            print(entry)

if __name__ == "__main__":
    kms = KeyManagementService()

    # Key Generation for two entities.
    print("--- Key Generation ---")
    pubA = kms.gen_keys("Hospital-A")
    pubB = kms.gen_keys("Clinic-B")

    # Demonstrate encryption and decryption.
    print("\n--- Encryption/Decryption Demo ---")
    message = b"Patient record: Blood Test OK"
    ct = kms.encrypt("Hospital-A", message)
    pt = kms.decrypt("Hospital-A", ct)
    print(f"Original: {message.decode()}")
    print(f"Decrypted: {pt.decode() if pt else 'Failed'}")
    assert pt == message

    # Demonstrate key revocation.
    print("\n--- Key Revocation ---")
    kms.revoke_key("Clinic-B")
    try:
        kms.get_pubkey("Clinic-B")
    except Exception as e:
        print(f"Attempt to use revoked key failed as expected: {e}")

    # Demonstrate key renewal.
    print("\n--- Key Renewal ---")
    kms.renew_key("Hospital-A")

    # Display the final audit log.
    kms.show_logs()