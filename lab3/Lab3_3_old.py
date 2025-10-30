from Crypto.Util.number import getPrime, getRandomRange, inverse
import random

p = getPrime(256)
g = random.randint(2, p - 2)
x = random.randint(2, p - 2)
h = pow(g, x, p)

message = "Confidential Data"
print("Original Message:", message)

m = int.from_bytes(message.encode('utf-8'), 'big')

y = random.randint(2, p - 2)
c1 = pow(g, y, p)
s = pow(h, y, p)
c2 = (m * s) % p

print("Ciphertext (c1, c2) in hex:")
print(hex(c1)[2:], hex(c2)[2:])

s_dec = pow(c1, x, p)
s_inv = inverse(s_dec, p)
m_dec = (c2 * s_inv) % p

byte_len = (m_dec.bit_length() + 7) // 8
decrypted_msg = m_dec.to_bytes(byte_len, 'big').decode('utf-8')

print("Decrypted Message:", decrypted_msg)
