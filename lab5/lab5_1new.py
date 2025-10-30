# Implements a custom hash function (djb2 algorithm).
def hash(input_string: str):
    # Start with an initial, non-zero "magic number". 5381 is the standard for djb2.
    hash_val = 5381
    
    # Iterate over each character in the input string.
    for char in input_string:
        # Get the ASCII numerical value of the character.
        ascii_val = ord(char)
        
        # The core of the algorithm:
        # 1. Multiply the current hash by 33 (a prime number that distributes bits well).
        # 2. Add the ASCII value of the current character.
        hash_val = (hash_val * 33) + ascii_val
        
        # Perform a bitwise XOR with the hash shifted right by 16 bits.
        # This adds more mixing and helps create a better "avalanche effect".
        hash_val ^= (hash_val >> 16)
        
        # Ensure the hash value stays within a 32-bit integer range
        # by applying a bitmask (AND with 0xFFFFFFFF).
        hash_val &= 0xFFFFFFFF
        
    return hash_val

# --- EXECUTION ---
# The message to be hashed.
msg = "pepperoni"
# Calculate and print the hash value in hexadecimal format for readability.
print("Input message:", msg)
print("Hash value (hex):", hex(hash(msg)))