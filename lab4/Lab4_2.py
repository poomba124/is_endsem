from Crypto.Util.number import getPrime, inverse, GCD, bytes_to_long, long_to_bytes
import time

class KeyManagementService:
    def __init__(self, keysize=1024):
        self.keysize = keysize
        self.keys = {}       # hospital/clinic -> keys
        self.logs = []       # audit logs

    def log(self, msg):
        entry = f"[{time.ctime()}] {msg}"
        self.logs.append(entry)
        print(entry)

    # Key Generation
    def gen_keys(self, name):
        p = getPrime(self.keysize // 2)
        q = getPrime(self.keysize // 2)
        while p % 4 != 3 or q % 4 != 3:  # Rabin primes must be 3 mod 4
            p = getPrime(self.keysize // 2)
            q = getPrime(self.keysize // 2)
        n = p * q
        self.keys[name] = {'n': n, 'p': p, 'q': q, 'revoked': False}
        self.log(f"Generated keys for {name} (n={n})")
        return {'n': n}  # only public part distributed

    # Key Distribution
    def get_pubkey(self, name):
        if name in self.keys and not self.keys[name]['revoked']:
            return self.keys[name]['n']
        raise Exception("Keys revoked or not found")

    # Key Revocation
    def revoke_key(self, name):
        if name in self.keys:
            self.keys[name]['revoked'] = True
            self.log(f"Revoked keys for {name}")

    # Key Renewal
    def renew_key(self, name):
        if name not in self.keys:
            raise Exception("Entity not registered")
        self.log(f"Renewing keys for {name}")
        return self.gen_keys(name)

    # Rabin Encryption
    def encrypt(self, name, msg: bytes):
        n = self.get_pubkey(name)
        m = bytes_to_long(msg)
        c = pow(m, 2, n)
        self.log(f"Encrypted message for {name}")
        return c

    # Rabin Decryption
    def decrypt(self, name, c: int):
        if name not in self.keys or self.keys[name]['revoked']:
            raise Exception("Keys revoked or missing")

        p, q, n = self.keys[name]['p'], self.keys[name]['q'], self.keys[name]['n']
        mp = pow(c, (p + 1) // 4, p)
        mq = pow(c, (q + 1) // 4, q)

        # Chinese Remainder Theorem
        yp = inverse(p, q)
        yq = inverse(q, p)
        r1 = (yp * p * mq + yq * q * mp) % n
        r2 = n - r1
        r3 = (yp * p * mq - yq * q * mp) % n
        r4 = n - r3

        candidates = [r1, r2, r3, r4]
        for cand in candidates:
            try:
                msg = long_to_bytes(cand)
                if msg.isascii():
                    self.log(f"Decryption successful for {name}")
                    return msg
            except:
                continue
        return None

    def show_logs(self):
        print("\n=== Audit Log ===")
        for entry in self.logs:
            print(entry)


if __name__ == "__main__":
    kms = KeyManagementService()

    # Register hospitals
    pubA = kms.gen_keys("Hospital-A")
    pubB = kms.gen_keys("Clinic-B")

    # Encrypt/Decrypt demo
    ct = kms.encrypt("Hospital-A", b"Patient record: Blood Test OK")
    pt = kms.decrypt("Hospital-A", ct)
    print("Decrypted:", pt)

    # Revocation
    kms.revoke_key("Clinic-B")

    # Renewal
    kms.renew_key("Hospital-A")

    # Show logs
    kms.show_logs()