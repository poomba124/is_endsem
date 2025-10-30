from Crypto.Cipher import DES
from Crypto.Util.Padding import pad, unpad

# Key must be 8 bytes long
key = b"A1B2C3D4"


# Create DES cipher in ECB mode
cipher = DES.new(key, DES.MODE_ECB)

# Message to encrypt
message = b"Confidential Data"

# Encrypt (pad message to multiple of 8 bytes)
ciphertext = cipher.encrypt(pad(message, DES.block_size))
print("Ciphertext (hex):", ciphertext.hex())

# Decrypt
decrypted = unpad(cipher.decrypt(ciphertext), DES.block_size)
print("Decrypted message:", decrypted.decode())

#---------------------##----------------------#

from Crypto.Cipher import DES
from Crypto.Util.Padding import pad, unpad

# Take user input
key_input = input("Enter 8-character key: ")   # DES key must be 8 bytes
if len(key_input) != 8:
    raise ValueError("Key must be exactly 8 characters long!")

message_input = input("Enter message: ")

# Convert to bytes
key = key_input.encode()
message = message_input.encode()

# Create DES cipher
cipher = DES.new(key, DES.MODE_ECB)

# Encrypt
ciphertext = cipher.encrypt(pad(message, DES.block_size))
print("\nCiphertext (hex):", ciphertext.hex())

# Decrypt
decrypted = unpad(cipher.decrypt(ciphertext), DES.block_size)
print("Decrypted message:", decrypted.decode())
