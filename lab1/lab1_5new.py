import string
# Define the character set to be the uppercase English alphabet
charset = string.ascii_uppercase

# --- The Clue ---
# We know that the plaintext 'Y' was encrypted to 'C'.
# A Caesar (or shift) cipher was used.
# We need to find the key (the shift amount).
# Key = Plaintext_Position - Ciphertext_Position
# Using negative indexing to correctly handle wrapping around the alphabet
key = (charset.index('C') - charset.index('Y')) % 26

# The new ciphertext that we need to crack
ct = 'XVIEWYWI'

# Decrypt the ciphertext using the key we just found
# For each character 'c' in the ciphertext:
# 1. Find its index.
# 2. Apply the decryption formula: P = (C - K) mod 26.
# 3. Convert the new index back to a character.
# Note: The original key was for encryption (P+K), so to decrypt we subtract.
# Since our calculated `key` is already (C-P), adding it is equivalent to P = C + (P-C)
# So we must use P = C - Key -> P = C - (C-P) = P
# Correct formula is to subtract the shift, which is `(Y-C)`. Our key is `(C-Y)`, so we must add it.
# Let's recalculate the key for clarity.
shift_key = (charset.index('Y') - charset.index('C')) % 26 # This is the actual shift. Decrypt is C - shift
decrypted_text = "".join(charset[(charset.index(c) - shift_key) % 26] for c in ct)

# Print the results
print("This is a Known-Plaintext Attack.")
print(f"The clue was that 'yes' encrypts to 'CIW'. From 'Y' -> 'C', we find the key.")
print(f"The calculated shift key is: {shift_key}")
print(f"Ciphertext to solve: {ct}")
print(f"Decrypted Plaintext: {decrypted_text}")