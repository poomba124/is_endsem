from Crypto.Util.number import *
import random
import time

def gen_public_params():
    p = getPrime(256)
    g = random.randrange(2, p-1)
    return g, p

def gen_params(g, p):
    x = random.randrange(2, p-2)
    G = pow(g, x, p)
    return x, G

class Alice:
    def __init__(self, g, p):
        self.g, self.p = g, p
        self.a, self.A = gen_params(g, p)
        self.shared_secret = None

    def compute_shared_secret(self, B):
        self.shared_secret = pow(B, self.a, self.p)
        return self.shared_secret

class Bob:
    def __init__(self, g, p):
        self.g, self.p = g, p
        self.b, self.B = gen_params(g, p)
        self.shared_secret = None

    def compute_shared_secret(self, A):
        self.shared_secret = pow(A, self.b, self.p)
        return self.shared_secret

if __name__ == "__main__":
    t0 = time.time()
    g, p = gen_public_params()
    t1 = time.time()

    t2 = time.time()
    alice = Alice(g, p)
    bob = Bob(g, p)
    t3 = time.time()

    t4 = time.time()
    s_alice = alice.compute_shared_secret(bob.B)
    s_bob = bob.compute_shared_secret(alice.A)
    t5 = time.time()

    print("Public parameters:")
    print(f"  p bit-length: {p.bit_length()}")
    print(f"  g: {g}\n")

    print("Timings (using time.time()):")
    print(f"  public param generation: {t1 - t0:.6f} seconds")
    print(f"  keypair generation (Alice + Bob): {t3 - t2:.6f} seconds")
    print(f"  shared secret computation: {t5 - t4:.6f} seconds\n")

    print("Values:")
    print(f"  Alice public A: {alice.A}")
    print(f"  Bob public   B: {bob.B}")
    print(f"  Alice shared : {s_alice}")
    print(f"  Bob shared   : {s_bob}")
    print(f"  Shared equal?: {s_alice == s_bob}")