# -----------------------------------------------
# Paillier Secure Data Sharing Demo
# -----------------------------------------------
from phe import paillier

# ----------------- Key Generation -----------------
public_key, private_key = paillier.generate_paillier_keypair()

# ----------------- Encrypt Data -----------------
data_party1 = 10
data_party2 = 20
enc1 = public_key.encrypt(data_party1)
enc2 = public_key.encrypt(data_party2)

# ----------------- Homomorphic Computation -----------------
# Sum without decrypting individual data
enc_sum = enc1 + enc2

# Decrypt result
dec_sum = private_key.decrypt(enc_sum)
print("\nPaillier Secure Data Sharing Demo")
print("Party1:", data_party1, "Party2:", data_party2)
print("Decrypted Sum:", dec_sum)  # Should be 30
