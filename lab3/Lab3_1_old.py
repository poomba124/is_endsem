from Crypto.Util.number import *

p = getPrime(1024)
q = getPrime(1024)
n = p * q
phi = (p - 1) * (q - 1)

e = 65537
d = pow(e, -1, phi)

message = "Asymmetric Encryption"
print("Original Message:", message)

message_int = int.from_bytes(message.encode('utf-8'), byteorder='big')

cipher_int = pow(message_int, e, n)
cipher_hex = hex(cipher_int)[2:]
print("Ciphertext (hex):", cipher_hex)

decrypted_int = pow(cipher_int, d, n)
byte_length = (decrypted_int.bit_length() + 7) // 8
decrypted_message = decrypted_int.to_bytes(byte_length, byteorder='big').decode('utf-8')

print("Decrypted Message:", decrypted_message)
