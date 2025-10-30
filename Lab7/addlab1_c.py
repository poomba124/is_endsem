from phe import paillier

# ----------------- Key Generation -----------------
public_key, private_key = paillier.generate_paillier_keypair()

# ----------------- Encrypt Data -----------------
data_party1 = 10
data_party2 = 20

enc1 = public_key.encrypt(data_party1)
enc2 = public_key.encrypt(data_party2)

# Homomorphic sum
enc_sum = enc1 + enc2
dec_sum = private_key.decrypt(enc_sum)

print("Decrypted Sum:", dec_sum)  # Should be 30
