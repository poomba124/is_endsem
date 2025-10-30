from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad

# AES key must be 16 bytes (128 bits)
key = b"0123456789ABCDEF"

# AES key must be 32 bytes for AES-256
#key = b"0123456789ABCDEF0123456789ABCDEF"

# Create AES cipher (ECB mode for simplicity)
cipher = AES.new(key, AES.MODE_ECB)

# Message to encrypt
message = b"Sensitive Information"

# Encrypt
ciphertext = cipher.encrypt(pad(message, AES.block_size))
print("Ciphertext (hex):", ciphertext.hex())

# Decrypt
decrypted = unpad(cipher.decrypt(ciphertext), AES.block_size)
print("Decrypted message:", decrypted.decode())



#-------------------##-------------------#



from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad

# Take user input
key_input = input("Enter 16-character key: ")  # AES-128 requires 16 bytes
if len(key_input) != 16:
    raise ValueError("Key must be exactly 16 characters long!")

message_input = input("Enter message: ")

# Convert to bytes
key = key_input.encode()
message = message_input.encode()

# Create AES cipher
cipher = AES.new(key, AES.MODE_ECB)

# Encrypt
ciphertext = cipher.encrypt(pad(message, AES.block_size))
print("\nCiphertext (hex):", ciphertext.hex())

# Decrypt
decrypted = unpad(cipher.decrypt(ciphertext), AES.block_size)
print("Decrypted message:", decrypted.decode())

