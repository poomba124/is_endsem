import string
# Define the character set to be the uppercase English alphabet
charset = string.ascii_uppercase

# Class for the Vigenere Cipher
class A:
    # Initializes the cipher object with a message and a keyword
    def __init__(self, msg, key):
        self.pt = msg # Plaintext
        self.key = key # The keyword for encryption/decryption
        self.ct = ""   # Ciphertext

    # Encrypts the message using the Vigenere cipher
    def encrypt(self):
        self.ct = "" # Reset ciphertext
        # 'zip' pairs each message character with a key character.
        # The key is repeated to match the message length (e.g., "dollarsdollars...")
        for i, j in zip(self.pt, (self.key*50)[:len(self.pt)]):
            if i.upper() in charset:
                # Get the numerical position of the plaintext char and the key char
                pt_index = charset.index(i.upper())
                key_index = charset.index(j.upper())
                # Apply Vigenere encryption: C = (P + K) mod 26
                ok = charset[(pt_index + key_index) % 26]
                # Keep the original case
                if i.isupper(): self.ct += ok
                else: self.ct += ok.lower()
            else:
                # Keep non-alphabetic characters (like spaces) as they are
                self.ct += i
        return self.ct

    # Decrypts the message using the Vigenere cipher
    def decrypt(self):
        pt = "" # Reset plaintext
        # Pair each ciphertext character with a key character
        for i, j in zip(self.ct, (self.key*50)[:len(self.ct)]):
            if i.upper() in charset:
                # Get the numerical position of the ciphertext char and the key char
                ct_index = charset.index(i.upper())
                key_index = charset.index(j.upper())
                # Apply Vigenere decryption: P = (C - K) mod 26
                ok = charset[(ct_index - key_index) % 26]
                # Keep the original case
                if i.isupper(): pt += ok
                else: pt += ok.lower()
            else:
                # Keep non-alphabetic characters as they are
                pt += i
        self.pt = pt
        return self.pt

# Class for the Autokey Cipher
class B:
    # Initializes the cipher with a message and an initial key (a number)
    def __init__(self, msg, key):
        self.pt = msg
        self.key = str(key)
        self.ct = ""

    # Encrypts the message using the Autokey cipher
    def encrypt(self):
        self.ct = ""
        # The key stream starts with the initial key
        key_stream = [int(self.key)]
        # The rest of the key stream is generated from the plaintext itself
        for ch in self.pt:
            if ch.upper() in charset:
                key_stream.append(charset.index(ch.upper()))
        
        # Make the key stream the same length as the message
        key_stream = key_stream[:len(self.pt)]
        idx = 0
        # Loop through the plaintext characters
        for i in self.pt:
            if i.upper() in charset:
                # Get the next key from our generated key stream
                j = key_stream[idx]
                # Apply encryption formula: C = (P + K) mod 26
                ok = charset[(charset.index(i.upper()) + j) % 26]
                # Keep original case
                if i.isupper(): self.ct += ok
                else: self.ct += ok.lower()
                idx += 1
            else:
                self.ct += i
        return self.ct

    # Decrypts the message using the Autokey cipher
    def decrypt(self):
        self.pt = ""
        # The key stream starts with the initial key
        key_stream = [int(self.key)]
        idx = 0
        # Loop through the ciphertext characters
        for i in self.ct:
            if i.upper() in charset:
                # Get the next key from the stream
                j = key_stream[idx]
                # Apply decryption formula: P = (C - K) mod 26
                ok = charset[(charset.index(i.upper()) - j) % 26]
                # Keep original case
                if i.isupper(): self.pt += ok
                else: self.pt += ok.lower()
                # The decrypted character now becomes the next key in the stream
                key_stream.append(charset.index(ok.upper()))
                idx += 1
            else:
                self.pt += i
        return self.pt

# Main part of the script to run the ciphers
if __name__ == "__main__":
    msg = "the house is being sold tonight"
    msg_no_space = msg.replace(" ", "")

    # --- Part a) Vigenere Cipher ---
    print("--- Vigenere Cipher ---")
    a = A(msg_no_space, 'dollars')
    encrypted_a = a.encrypt()
    decrypted_a = a.decrypt()
    print(f"Plaintext: {msg}\nEncrypted: {encrypted_a}\nDecrypted: {decrypted_a}")
    
    print("\n" + "="*20 + "\n")

    # --- Part b) Autokey Cipher ---
    print("--- Autokey Cipher ---")
    b = B(msg_no_space, 7)
    encrypted_b = b.encrypt()
    decrypted_b = b.decrypt()
    print(f"Plaintext: {msg}\nEncrypted: {encrypted_b}\nDecrypted: {decrypted_b}")