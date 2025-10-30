# The 2x2 key matrix for the Hill cipher
K = [[3, 3], [2, 7]]

# Prepares the message for encryption
def prepare(msg):
    # Convert message to uppercase and remove spaces
    msg = msg.upper().replace(" ", "")
    # If the message has an odd number of letters, add an 'X' to make it even
    if len(msg) % 2 != 0:
        msg += "X"
    return msg

# Encrypts a digraph (a pair of letters) using the key matrix
def encdig(a, b):
    # Apply the matrix multiplication: C = P * K
    # First character of the encrypted pair
    x = (K[0][0]*a + K[0][1]*b) % 26
    # Second character of the encrypted pair
    y = (K[1][0]*a + K[1][1]*b) % 26
    return x, y

# The message to be encrypted
message = "We live in an insecure world"
# Prepare the message by cleaning it up and making its length even
msg = prepare(message)
ciphertext = ""

# Process the message in pairs of letters
for i in range(0, len(msg), 2):
    # Convert the pair of letters to numbers (A=0, B=1, ...)
    a = ord(msg[i]) - ord('A')
    b = ord(msg[i+1]) - ord('A')
    # Encrypt the pair of numbers using the matrix
    x, y = encdig(a, b)
    # Convert the resulting numbers back to letters and add to the ciphertext
    ciphertext += chr(x + ord('A')) + chr(y + ord('A'))

# Print the final encrypted message
print(f"Plaintext: {message}")
print(f"Prepared:  {msg}")
print(f"Ciphertext: {ciphertext}")