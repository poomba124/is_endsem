import time
import random  # <<--- Make sure this is here
from phe import paillier
from Crypto.Util import number
import random as crypto_random  # if using ElGamal

# Generate Paillier key pair
public_key, private_key = paillier.generate_paillier_keypair()

# Sample data for benchmarking
messages = [random.randint(1,100) for _ in range(100)]

# Paillier Benchmark
start = time.time()
for m in messages:
    c = public_key.encrypt(m)
end = time.time()
print("Paillier Encryption Time for 100 messages:", round(end-start,4), "s")
