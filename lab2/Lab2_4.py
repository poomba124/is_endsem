from Lab2_1 import *

m = b"Classified Text"
k = bytes.fromhex("1234567890ABCDEF1234567890ABCDEF1234567890ABCDEF")

def derive_keys(key):
    return [k[i:i+8] for i in range(0, 24, 8)]

def des_encrypt(msg : bytes, key : bytes):
    ks = derive_keys(key)
    msg = pad(msg)

    enc = encrypt(decrypt(encrypt(msg, ks[0]), ks[1]), ks[2])
    return enc

def des_decrypt(msg : bytes, key : bytes):
    ks = derive_keys(key)
    msg = pad(msg)

    dec = decrypt(encrypt(decrypt(msg, ks[2]), ks[1]), ks[0])
    return dec

ct = des_encrypt(m, k)
print(f"{ct = }")
pt = des_decrypt(ct, k)
print(f"{pt = }")