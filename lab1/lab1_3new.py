# The keyword for the cipher
key = "GUIDANCE"
# The alphabet used in the cipher (I and J are treated as the same letter)
alphabet = "ABCDEFGHIKLMNOPQRSTUVWXYZ"

# --- Create the 5x5 Playfair matrix ---
# Start the matrix with the unique letters of the key
matrix_chars = []
for c in key:
    if c not in matrix_chars:
        matrix_chars.append(c)
# Fill the rest of the matrix with the remaining letters of the alphabet
for c in alphabet:
    if c not in matrix_chars:
        matrix_chars.append(c)

# Convert the list of characters into a 5x5 grid
matrix = [matrix_chars[0:5], matrix_chars[5:10], matrix_chars[10:15], matrix_chars[15:20], matrix_chars[20:25]]

# Finds the (row, column) position of a character in the matrix
def pos(c):
    # Treat 'J' as 'I'
    if c == "J": c = "I"
    # Search each row for the character
    for r, row in enumerate(matrix):
        if c in row:
            # Return the row and column index
            return r, row.index(c)

# Encrypts a digraph (a pair of letters) based on the Playfair rules
def encdig(a, b):
    # Get the positions of both letters
    ra, ca = pos(a)
    rb, cb = pos(b)

    # Rule 1: If the letters are in the same row
    if ra == rb:
        # Each letter is replaced by the letter to its right (wrapping around)
        return matrix[ra][(ca+1)%5] + matrix[rb][(cb+1)%5]
    # Rule 2: If the letters are in the same column
    elif ca == cb:
        # Each letter is replaced by the letter below it (wrapping around)
        return matrix[(ra+1)%5][ca] + matrix[(rb+1)%5][cb]
    # Rule 3: If the letters form a rectangle
    else:
        # Each letter is replaced by the letter in the same row but at the other corner of the rectangle
        return matrix[ra][cb] + matrix[rb][ca]

# Prepares the message for encryption according to Playfair rules
def prepare(msg):
    # Make the message uppercase, replace 'J' with 'I', and remove spaces
    msg = msg.upper().replace("J","I").replace(" ","")
    res = ""
    i = 0
    while i < len(msg):
        a = msg[i]
        # Check if there's a next letter, otherwise use 'X'
        b = msg[i+1] if i+1 < len(msg) else "X"
        # If two letters are the same, insert an 'X' between them
        if a == b:
            b = "X"
            i += 1 # Move forward by only one character
        else:
            i += 2 # Move forward by two characters
        res += a + b
    # If the final message has an odd number of letters, add an 'X' at the end
    if len(res) % 2 != 0:
        res += "X"
    return res

# The message to be encrypted
message = "The key is hidden under the door pad"
# Prepare the message into digraphs
digraphs = prepare(message)
ciphertext = ""
# Loop through the digraphs, taking two characters at a time
for i in range(0, len(digraphs), 2):
    # Encrypt each pair and add to the final ciphertext
    ciphertext += encdig(digraphs[i], digraphs[i+1])

# Print the final encrypted message
print(f"Plaintext: {message}")
print(f"Prepared:  {digraphs}")
print(f"Ciphertext: {ciphertext}")