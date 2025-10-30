from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad

# --- SETUP ---
# The plaintext message and 24-byte (192-bit) key from the question
pt = "Top Secret Data"
k = "FEDCBA9876543210FEDCBA9876543210FEDCBA9876543210"
# Convert the hex string key into a byte string that the library can use
key = bytes.fromhex(k)

print(f"Plaintext: {pt}")
print(f"Key (hex): {k}")
print(f"AES Mode: AES-192")

# Create a new AES cipher object using the key and ECB mode
cipher = AES.new(key, AES.MODE_ECB)

# Pad the plaintext to be a multiple of 16 bytes (AES block size)
p = pad(pt.encode(), AES.block_size)
print(f"\nPadded Message (bytes): {p}")
print(f"Padded length: {len(p)} bytes")

# --- DESCRIPTION OF STEPS ---
# These print statements describe the conceptual steps of AES-192 encryption.
print(f"\nENCRYPTION PROCESS")
print(f"1. Key Expansion: The 192-bit key is expanded into 13 separate 128-bit round keys.")
print(f"2. Initial Round: The data is XORed with the first round key (AddRoundKey).")
print(f"3. Main Rounds: The algorithm loops 11 times. Each round consists of four steps: SubBytes, ShiftRows, MixColumns, and AddRoundKey.")
print(f"4. Final Round: A final 13th round is performed, but it skips the MixColumns step (only SubBytes, ShiftRows, AddRoundKey).")

# --- EXECUTION AND VERIFICATION ---
# Perform the actual encryption using the library
ct = cipher.encrypt(p)
print(f"\nCiphertext (hex): {ct.hex()}")
print(f"Ciphertext length: {len(ct)} bytes")

# Decrypt the ciphertext to verify it works
print(f"\nDECRYPTION VERIFICATION")
mes = unpad(cipher.decrypt(ct), AES.block_size).decode()
print(f"Decrypted Message: {mes}")

# Check if the decrypted message matches the original plaintext
print(f"\nVerification: {pt == mes}")