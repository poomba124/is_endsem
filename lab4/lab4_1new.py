from Crypto.Util.number import getPrime, inverse, bytes_to_long, long_to_bytes

# The central authority responsible for key management.
class Company:
    # A dictionary to store the public keys of all registered systems.
    keys = {}

    # --- KEY MANAGEMENT ---
    # Generates RSA keys and a secret 'x' for Diffie-Hellman for a given system.
    def gen_keys(self, system_name):
        # Generate components for RSA (p, q, e) and DH (x).
        x = getPrime(256)        # Private secret for DH
        p = getPrime(1024)       # First prime for RSA
        q = getPrime(1024)       # Second prime for RSA
        e = 0x10001              # Standard public exponent for RSA
        
        # Store the public RSA key (n, e) in the company's central key store.
        self.keys[system_name] = {'n': p * q, 'e': e}
        
        # Return all generated parameters (public and private) to the system itself.
        params = {'p': p, 'q': q, 'x': x, 'e': e}
        return params

    # Revokes the public key of a system.
    def revoke_key(self, system_name):
        # Overwrite the stored public key to invalidate it.
        self.keys[system_name] = {'n': 'revoked', 'e': 'revoked'}
        print(f"Revoked keys for {system_name}")

    # Retrieves the public key for a given system.
    def get_pubkey(self, system_name):
        return self.keys[system_name]['n'], self.keys[system_name]['e']

    # --- SECURE COMMUNICATION ---
    # Manages the secure sending of a message from a source system to a destination system.
    def send(self, src_system, dst_system, msg: bytes):
        # 1. Establish common DH parameters (g, p) for the secure channel.
        g, p = 2, getPrime(256)
        dst_system.set_dh_params(g, p)
        src_system.set_dh_params(g, p)

        # 2. Exchange DH public keys.
        A = src_system.get_dh_pubkey()
        B = dst_system.get_dh_pubkey()

        # 3. Both systems compute the shared secret independently.
        dst_shared_secret = dst_system.compute_shared(A)
        src_shared_secret = src_system.compute_shared(B)

        # 4. Verify that both computed the same secret, authenticating the channel.
        assert dst_shared_secret == src_shared_secret, "DH authentication failed"
        print("Diffie-Hellman key exchange successful. Secure channel established.")

        # 5. Encrypt the message using the destination's public RSA key.
        m = bytes_to_long(msg)
        n, e = self.get_pubkey(dst_system.system_name)
        c = long_to_bytes(pow(m, e, n))

        # 6. Send the RSA-encrypted ciphertext to the destination.
        print(f"Message encrypted with {dst_system.system_name}'s public RSA key.")
        dst_system.receive(c)
        print("Message sent and received successfully.")

# Represents an individual subsystem (e.g., Finance, HR).
class System:
    def __init__(self, company, system_name):
        self.company = company
        self.system_name = system_name
        # When a system is created, it registers with the company to get its keys.
        self.secrets = company.gen_keys(system_name)
        # DH parameters are not set initially.
        self.g, self.p = None, None

    # Sets the DH parameters for a communication session.
    def set_dh_params(self, g, p):
        self.g, self.p = g, p

    # Computes the DH public key (g^x mod p).
    def get_dh_pubkey(self):
        return pow(self.g, self.secrets['x'], self.p)

    # Computes the shared secret using the other party's public key (X^x mod p).
    def compute_shared(self, X):
        return pow(X, self.secrets['x'], self.p)

    # Receives and decrypts an RSA-encrypted message.
    def receive(self, c):
        # Retrieve its own private RSA key components from its secrets.
        p, q = self.secrets['p'], self.secrets['q']
        e = self.secrets['e']
        # Calculate the private exponent 'd'.
        d = inverse(e, (p-1)*(q-1))
        # Decrypt the message.
        m = pow(bytes_to_long(c), d, p*q)
        print(f'[{self.system_name}] Received and decrypted message: {long_to_bytes(m).decode()}')

if __name__ == "__main__":
    # Create the central company.
    SecureCorp = Company()
    
    # Create two subsystems, which automatically generate and store their keys.
    FinanceSystem = System(SecureCorp, 'Finance-A')
    HRSystem = System(SecureCorp, 'HR-B')
    
    # Simulate the Finance system sending a secret message to the HR system.
    SecureCorp.send(FinanceSystem, HRSystem, b'Employee bonus approved.')
    
    # Demonstrate key revocation.
    print("\nRevoking HR-B's keys...")
    SecureCorp.revoke_key('HR-B')