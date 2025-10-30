import string
# Define the character set to be the uppercase English alphabet
charset = string.ascii_uppercase

# The clue: we know the plaintext 'AB' encrypts to the ciphertext 'GL'
pt, ct = "AB", "GL"

# This function will find the correct key (a, b) using a brute-force attack
def get_params():
    # Try every possible value for 'a' (must be odd and not 13)
    for a in range(27):
        # Try every possible value for 'b'
        for b in range(27):
            # For the current (a,b), check if it correctly encrypts our clue ('AB' -> 'GL')
            # The list 'results' will store True if the encryption works for a character, False otherwise
            results = []
            for p_char, c_char in zip(pt, ct):
                # Get the numerical position of the plaintext and ciphertext characters
                p_index = charset.index(p_char)
                c_index = charset.index(c_char)
                # Check if the affine formula C = (a*P + b) % 26 holds true
                is_match = (a * p_index + b) % 26 == c_index
                results.append(is_match)
            
            # If the formula worked for ALL characters in our clue...
            if all(results):
                # ...then we have found the correct keys!
                print(f"Found the keys!\na = {a}\nb = {b}")
                return a, b
    # If no key is found after trying everything
    return  None

# Run the brute-force attack to find the keys 'a' and 'b'
a, b = get_params()

# The full ciphertext we need to decrypt
ciph = "XPALASXYFGFUKPXUSOGEUTKCDGEXANMGNVS"

# To decrypt, we need the modular multiplicative inverse of 'a'
a_inv = 1
# Find the number 'a_inv' such that (a * a_inv) mod 26 == 1
while (a * a_inv) % 26 != 1:
    a_inv += 1

# Decrypt the full message using the keys we found
pt_result = ""
for i in ciph:
    # Get the numerical position of the character
    char_index = charset.index(i)
    # Apply the affine decryption formula: P = a_inv * (C - b) mod 26
    decrypted_index = (((char_index - b) % 26) * a_inv) % 26
    # Convert the number back to a letter and add it to our result
    pt_result += charset[decrypted_index]

print(f"\nFull ciphertext: {ciph}")
print(f"Decrypted plaintext: {pt_result}")