from Crypto.Cipher import DES3
from Crypto.Util.Padding import pad, unpad

# 24-byte key for 3DES
key = b"1234567890ABCDEF12345678"

# Create 3DES cipher (ECB mode for simplicity)
cipher = DES3.new(key, DES3.MODE_ECB)

# Message to encrypt
message = b"Classified Text"

# Encrypt
ciphertext = cipher.encrypt(pad(message, DES3.block_size))
print("Ciphertext (hex):", ciphertext.hex())

# Decrypt
decrypted = unpad(cipher.decrypt(ciphertext), DES3.block_size)
print("Decrypted message:", decrypted.decode())


#---------------------##---------------------#

from Crypto.Cipher import DES3
from Crypto.Util.Padding import pad, unpad

# Take user input
key_input = input("Enter 16 or 24-character key: ")
if len(key_input) not in (16, 24):
    raise ValueError("3DES key must be exactly 16 or 24 characters long!")

message_input = input("Enter message: ")

# Convert to bytes
key = key_input.encode()
message = message_input.encode()

# Create 3DES cipher
cipher = DES3.new(key, DES3.MODE_ECB)

# Encrypt
ciphertext = cipher.encrypt(pad(message, DES3.block_size))
print("\nCiphertext (hex):", ciphertext.hex())

# Decrypt
decrypted = unpad(cipher.decrypt(ciphertext), DES3.block_size)
print("Decrypted message:", decrypted.decode())

