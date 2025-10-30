from Crypto.Cipher import AES, DES
from Crypto.Util.Padding import pad
import os
import time

# --- SETUP ---
# Generate a random 32-byte (256-bit) key for AES-256
key = os.urandom(32)
# Prepare the message and pad it to be a multiple of 16 bytes (for AES)
msg = pad(b"Performance Testing of Encryption Algorithms", 16)

# Create cipher objects for AES and DES
# AES uses the full 32-byte key
aes = AES.new(key, AES.MODE_ECB)
# DES only uses an 8-byte key, so we take the first 8 bytes of our generated key
des = DES.new(key[:8], DES.MODE_ECB)

# --- ENCRYPTION TIMING ---
print("--- ENCRYPTION ---")
# Time AES encryption
start_time = time.time()
ct_aes = aes.encrypt(msg)
aes_time_enc = time.time() - start_time
print(f'AES encryption time : {aes_time_enc * 1000:.4f} ms')

# Time DES encryption
start_time = time.time()
ct_des = des.encrypt(msg)
des_time_enc = time.time() - start_time
print(f'DES encryption time : {des_time_enc * 1000:.4f} ms')

# Determine which was faster
alg = "AES" if aes_time_enc <= des_time_enc else "DES"
print(f"-> {alg} was faster at encrypting\n")

# --- DECRYPTION TIMING ---
print("--- DECRYPTION ---")
# Time AES decryption
start_time = time.time()
pt_aes = aes.decrypt(ct_aes)
aes_time_dec = time.time() - start_time
print(f'AES decryption time : {aes_time_dec * 1000:.4f} ms')

# Time DES decryption
start_time = time.time()
pt_des = des.decrypt(ct_des)
des_time_dec = time.time() - start_time
print(f'DES decryption time : {des_time_dec * 1000:.4f} ms')

# Determine which was faster
alg = "AES" if aes_time_dec <= des_time_dec else "DES"
print(f"-> {alg} was faster at decrypting\n")