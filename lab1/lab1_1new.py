import string

# Define the character set to be the uppercase English alphabet
charset = string.ascii_uppercase

# Class for the Additive (Caesar) Cipher
class A:
    # Initializes the cipher object with a message and a key
    def __init__(self, msg, key):
        self.pt = msg # pt stands for plaintext (original message)
        self.key = key
        self.ct = ""   # ct stands for ciphertext (encrypted message)

    # Encrypts the plaintext using the additive cipher formula
    def encrypt(self):
        self.ct = "" # Reset the ciphertext
        # Loop through each character in the plaintext
        for i in self.pt:
            # Check if the character is in the alphabet
            if i.upper() in charset:
                # Find the numerical position of the character (A=0, B=1, ...)
                char_index = charset.index(i.upper())
                # Apply the encryption formula: C = (P + K) mod 26
                encrypted_index = (char_index + self.key) % 26
                encrypted_char = charset[encrypted_index]
                # Keep the original case (upper or lower)
                if i.isupper():
                    self.ct += encrypted_char
                else:
                    self.ct += encrypted_char.lower()
            else:
                # If the character is not in the alphabet (like spaces), keep it as is
                self.ct += i
        return self.ct

    # Decrypts the ciphertext using the additive cipher formula
    def decrypt(self):
        self.pt = "" # Reset the plaintext
        # Loop through each character in the ciphertext
        for i in self.ct:
            # Check if the character is in the alphabet
            if i.upper() in charset:
                # Find the numerical position of the character
                char_index = charset.index(i.upper())
                # Apply the decryption formula: P = (C - K) mod 26
                decrypted_index = (char_index - self.key) % 26
                decrypted_char = charset[decrypted_index]
                # Keep the original case
                if i.isupper():
                    self.pt += decrypted_char
                else:
                    self.pt += decrypted_char.lower()
            else:
                # If not a letter, keep it as is
                self.pt += i
        return self.pt

# Class for the Multiplicative Cipher
class B:
    # Initializes the cipher object with a message and a key
    def __init__(self, msg, key):
        self.pt = msg
        self.key = key
        self.ct = ""

    # Encrypts the plaintext using the multiplicative cipher formula
    def encrypt(self):
        self.ct = "" # Reset ciphertext
        # Loop through each character
        for i in self.pt:
            if i.upper() in charset:
                # Find the numerical position of the character
                char_index = charset.index(i.upper())
                # Apply the encryption formula: C = (P * K) mod 26
                encrypted_index = (char_index * self.key) % 26
                encrypted_char = charset[encrypted_index]
                # Keep the original case
                if i.isupper():
                    self.ct += encrypted_char
                else:
                    self.ct += encrypted_char.lower()
            else:
                self.ct += i
        return self.ct

    # Decrypts the ciphertext using the multiplicative cipher formula
    def decrypt(self):
        self.pt = "" # Reset plaintext
        # To decrypt, we need the modular multiplicative inverse of the key
        keyinv = 1
        # Find the number `keyinv` such that (key * keyinv) mod 26 == 1
        while (keyinv * self.key) % 26 != 1:
            keyinv += 1

        # Loop through each character
        for i in self.ct:
            if i.upper() in charset:
                # Find the numerical position of the character
                char_index = charset.index(i.upper())
                # Apply the decryption formula: P = (C * K_inverse) mod 26
                decrypted_index = (char_index * keyinv) % 26
                decrypted_char = charset[decrypted_index]
                # Keep the original case
                if i.isupper():
                    self.pt += decrypted_char
                else:
                    self.pt += decrypted_char.lower()
            else:
                self.pt += i
        return self.pt

# Class for the Affine Cipher
class C:
    # Initializes the cipher with a message and a key pair (a, b)
    def __init__(self, msg, key):
        self.pt = msg
        self.a, self.b = key # The key has two parts: 'a' for multiplying and 'b' for adding
        self.ct = ""

    # Encrypts the plaintext using the affine cipher formula
    def encrypt(self):
        self.ct = "" # Reset ciphertext
        # Loop through each character
        for i in self.pt:
            if i.upper() in charset:
                # Find the numerical position of the character
                char_index = charset.index(i.upper())
                # Apply the encryption formula: C = (a*P + b) mod 26
                encrypted_index = ((self.a * char_index) + self.b) % 26
                encrypted_char = charset[encrypted_index]
                # Keep the original case
                if i.isupper():
                    self.ct += encrypted_char
                else:
                    self.ct += encrypted_char.lower()
            else:
                self.ct += i
        return self.ct

    # Decrypts the ciphertext using the affine cipher formula
    def decrypt(self):
        # Find the modular multiplicative inverse of 'a'
        a_inv = 1
        while (a_inv * self.a) % 26 != 1:
            a_inv += 1
        self.pt = "" # Reset plaintext
        # Loop through each character
        for i in self.ct:
            if i.upper() in charset:
                # Find the numerical position of the character
                char_index = charset.index(i.upper())
                # Apply the decryption formula: P = a_inv * (C - b) mod 26
                decrypted_index = (((char_index - self.b) % 26) * a_inv) % 26
                decrypted_char = charset[decrypted_index]
                # Keep the original case
                if i.isupper():
                    self.pt += decrypted_char
                else:
                    self.pt += decrypted_char.lower()
            else:
                self.pt += i
        return self.pt


# Main part of the script to run the ciphers
if __name__ == "__main__":
    # --- Part a) Additive Cipher ---
    print("--- Additive Cipher ---")
    m = "I am learning information security"
    a = A(m.replace(" ",""), 20)
    e = a.encrypt()
    d = a.decrypt()
    print(f"Plaintext: {m}\nEncrypted: {e}\nDecrypted: {d}")
    assert d == m.replace(" ","")

    print("\n" + "="*20 + "\n")

    # --- Part b) Multiplicative Cipher ---
    print("--- Multiplicative Cipher ---")
    m = "I am learning information security"
    b = B(m.replace(" ",""), 15)
    e = b.encrypt()
    d = b.decrypt()
    print(f"Plaintext: {m}\nEncrypted: {e}\nDecrypted: {d}")
    assert d == m.replace(" ","")
    
    print("\n" + "="*20 + "\n")

    # --- Part c) Affine Cipher ---
    print("--- Affine Cipher ---")
    m = "I am learning information security"
    c = C(m.replace(" ",""), (15, 20))
    e = c.encrypt()
    d = c.decrypt()
    print(f"Plaintext: {m}\nEncrypted: {e}\nDecrypted: {d}")
    assert d == m.replace(" ","")