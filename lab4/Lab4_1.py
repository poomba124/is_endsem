from Crypto.Util.number import  *

class Company:
    keys = {}
    # Key Management
    def gen_keys(self, system):
        x, p, q = getPrime(256), getPrime(1024), getPrime(1024)
        params = {
            'p' : p,
            'q' : q,
            'x' : x,
            'e': 0x10001
        }
        self.keys[system] = { 'n' : p * q, 'e' : 0x10001 }
        return params

    def revoke_key(self, system):
        self.keys[system] = { 'n' : 'revoked', 'e' : 'revoked' }

    def get_pubkey(self, system):
        return self.keys[system]['n'], self.keys[system]['e']

    # Secure Comms
    def send(self, src , dst , msg : bytes):
        g, p = 2, getPrime(256)
        dst.set_dh_params(g, p)
        src.set_dh_params(g, p)

        A = src.get_dh_pubkey()
        B = dst.get_dh_pubkey()

        dst_shared_secret = dst.compute_shared(A)
        src_shared_secret = src.compute_shared(B)

        assert dst_shared_secret == src_shared_secret, "DH authentication failed"
        print("DH authentified")

        # RSA encryption
        m = bytes_to_long(msg)
        n, e = self.get_pubkey(dst.system_name)
        c = long_to_bytes(pow(m, e, n))

        dst.receive(c)
        print("success")

# Scalable
class System:
    secrets = None
    company = None
    system_name = None
    g, p = None, None
    def __init__(self, company, system_name):
        self.company = company
        self.secrets = company.gen_keys(system_name)
        self.system_name = system_name

    def set_dh_params(self, g, p):
        self.g, self.p = g, p

    def get_dh_pubkey(self):
        return pow(self.g, self.secrets['x'], self.p)

    def compute_shared(self, X):
        return pow(X, self.secrets['x'], self.p)

    def receive(self, c):
        p, q = self.secrets['p'], self.secrets['q']
        n, e = p*q, self.secrets['e']
        d = inverse(e, (p-1)*(q-1))
        m = pow(bytes_to_long(c), d, n)
        print(f'recieved message : {long_to_bytes(m)}')

if __name__ == "__main__":
    SecureCorp = Company()
    A = System(SecureCorp, 'A')
    B = System(SecureCorp, 'B')

    SecureCorp.send(A, B, b'secret')