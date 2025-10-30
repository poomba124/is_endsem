S_BOXES = [
    # S1
    [
        [14, 4, 13, 1, 2, 15, 11, 8, 3, 10, 6, 12, 5, 9, 0, 7],
        [0, 15, 7, 4, 14, 2, 13, 1, 10, 6, 12, 11, 9, 5, 3, 8],
        [4, 1, 14, 8, 13, 6, 2, 11, 15, 12, 9, 7, 3, 10, 5, 0],
        [15, 12, 8, 2, 4, 9, 1, 7, 5, 11, 3, 14, 10, 0, 6, 13],
    ],
    # S2
    [
        [15, 1, 8, 14, 6, 11, 3, 4, 9, 7, 2, 13, 12, 0, 5, 10],
        [3, 13, 4, 7, 15, 2, 8, 14, 12, 0, 1, 10, 6, 9, 11, 5],
        [0, 14, 7, 11, 10, 4, 13, 1, 5, 8, 12, 6, 9, 3, 2, 15],
        [13, 8, 10, 1, 3, 15, 4, 2, 11, 6, 7, 12, 0, 5, 14, 9],
    ],
    # S3
    [
        [10, 0, 9, 14, 6, 3, 15, 5, 1, 13, 12, 7, 11, 4, 2, 8],
        [13, 7, 0, 9, 3, 4, 6, 10, 2, 8, 5, 14, 12, 11, 15, 1],
        [13, 6, 4, 9, 8, 15, 3, 0, 11, 1, 2, 12, 5, 10, 14, 7],
        [1, 10, 13, 0, 6, 9, 8, 7, 4, 15, 14, 3, 11, 5, 2, 12],
    ],
    # S4
    [
        [7, 13, 14, 3, 0, 6, 9, 10, 1, 2, 8, 5, 11, 12, 4, 15],
        [13, 8, 11, 5, 6, 15, 0, 3, 4, 7, 2, 12, 1, 10, 14, 9],
        [10, 6, 9, 0, 12, 11, 7, 13, 15, 1, 3, 14, 5, 2, 8, 4],
        [3, 15, 0, 6, 10, 1, 13, 8, 9, 4, 5, 11, 12, 7, 2, 14],
    ],
    # S5
    [
        [2, 12, 4, 1, 7, 10, 11, 6, 8, 5, 3, 15, 13, 0, 14, 9],
        [14, 11, 2, 12, 4, 7, 13, 1, 5, 0, 15, 10, 3, 9, 8, 6],
        [4, 2, 1, 11, 10, 13, 7, 8, 15, 9, 12, 5, 6, 3, 0, 14],
        [11, 8, 12, 7, 1, 14, 2, 13, 6, 15, 0, 9, 10, 4, 5, 3],
    ],
    # S6
    [
        [12, 1, 10, 15, 9, 2, 6, 8, 0, 13, 3, 4, 14, 7, 5, 11],
        [10, 15, 4, 2, 7, 12, 9, 5, 6, 1, 13, 14, 0, 11, 3, 8],
        [9, 14, 15, 5, 2, 8, 12, 3, 7, 0, 4, 10, 1, 13, 11, 6],
        [4, 3, 2, 12, 9, 5, 15, 10, 11, 14, 1, 7, 6, 0, 8, 13],
    ],
    # S7
    [
        [4, 11, 2, 14, 15, 0, 8, 13, 3, 12, 9, 7, 5, 10, 6, 1],
        [13, 0, 11, 7, 4, 9, 1, 10, 14, 3, 5, 12, 2, 15, 8, 6],
        [1, 4, 11, 13, 12, 3, 7, 14, 10, 15, 6, 8, 0, 5, 9, 2],
        [6, 11, 13, 8, 1, 4, 10, 7, 9, 5, 0, 15, 14, 2, 3, 12],
    ],
    # S8
    [
        [13, 2, 8, 4, 6, 15, 11, 1, 10, 9, 3, 14, 5, 0, 12, 7],
        [1, 15, 13, 8, 10, 3, 7, 4, 12, 5, 6, 11, 0, 14, 9, 2],
        [7, 11, 4, 1, 9, 12, 14, 2, 0, 6, 10, 13, 15, 3, 5, 8],
        [2, 1, 14, 7, 4, 10, 8, 13, 15, 12, 9, 0, 3, 5, 6, 11],
    ],
]

# --- HELPER FUNCTIONS ---

# Converts a large integer to a byte string.
def long_to_bytes(long: int, length=8):
    return int.to_bytes(long, length, 'big')

# Converts a byte string to a large integer.
def bytes_to_long(byts: bytes):
    return int.from_bytes(byts, 'big')

# Performs a bitwise XOR operation on two byte strings.
def xor(a: bytes, b: bytes):
    return bytes([x ^ y for x, y in zip(bytearray(a), bytearray(b))])

# Pads the plaintext to ensure its length is a multiple of 8 bytes.
def pad(pt):
    while len(pt) % 8 != 0:
        pt += b'\x00' # Adds null bytes for padding
    return pt

# Removes the padding from the decrypted data.
def unpad(data):
    return data.rstrip(b'\x00')

# --- DES CORE FUNCTIONS ---

# Performs the initial permutation on a 64-bit block of data.
def initial_permute(block):
    # Convert block to a 64-bit string
    block_bits = bin(bytes_to_long(block))[2:].zfill(64)
    # The standard initial permutation (IP) table for DES
    p_box = [
        58, 50, 42, 34, 26, 18, 10, 2, 60, 52, 44, 36, 28, 20, 12, 4,
        62, 54, 46, 38, 30, 22, 14, 6, 64, 56, 48, 40, 32, 24, 16, 8,
        57, 49, 41, 33, 25, 17, 9, 1, 59, 51, 43, 35, 27, 19, 11, 3,
        61, 53, 45, 37, 29, 21, 13, 5, 63, 55, 47, 39, 31, 23, 15, 7
    ]
    # Rearrange the bits according to the p_box and convert back to bytes
    return long_to_bytes(int(''.join(block_bits[p_box[i] - 1] for i in range(64)), 2))

# Performs the second permutation/compression (PC-2) in key generation.
def PC2(block):
    block_bits = bin(bytes_to_long(block))[2:].zfill(56)
    # The PC-2 table, which selects 48 bits from 56 to create a round key.
    p_box = [
        14, 17, 11, 24, 1, 5, 3, 28, 15, 6, 21, 10, 23, 19, 12, 4,
        26, 8, 16, 7, 27, 20, 13, 2, 41, 52, 31, 37, 47, 55, 30, 40,
        51, 45, 33, 48, 44, 49, 39, 56, 34, 53, 46, 42, 50, 36, 29, 32
    ]
    return long_to_bytes(int(''.join(block_bits[p_box[i] - 1] for i in range(48)), 2), 6)

# Performs the final permutation (IP-1), which is the inverse of the initial permutation.
def IP_1(block):
    block_bits = bin(bytes_to_long(block))[2:].zfill(64)
    # The standard inverse initial permutation (IP-1) table
    IP1 = [
        40, 8, 48, 16, 56, 24, 64, 32, 39, 7, 47, 15, 55, 23, 63, 31,
        38, 6, 46, 14, 54, 22, 62, 30, 37, 5, 45, 13, 53, 21, 61, 29,
        36, 4, 44, 12, 52, 20, 60, 28, 35, 3, 43, 11, 51, 19, 59, 27,
        34, 2, 42, 10, 50, 18, 58, 26, 33, 1, 41, 9, 49, 17, 57, 25
    ]
    return long_to_bytes(int(''.join(block_bits[IP1[i] - 1] for i in range(64)), 2))

# Generates the 16 round keys from the main 64-bit key.
def get_round_keys(key):
    # PC-1 table permutes and selects 56 bits from the 64-bit key
    PC1 = [
        57, 49, 41, 33, 25, 17, 9, 1, 58, 50, 42, 34, 26, 18, 10, 2,
        59, 51, 43, 35, 27, 19, 11, 3, 60, 52, 44, 36, 63, 55, 47, 39,
        31, 23, 15, 7, 62, 54, 46, 38, 30, 22, 14, 6, 61, 53, 45, 37,
        29, 21, 13, 5, 28, 20, 12, 4
    ]
    # Number of left shifts to perform for each round
    shifts = [1, 1, 2, 2, 2, 2, 2, 2, 1, 2, 2, 2, 2, 2, 2, 1]
    
    key_bits = bin(bytes_to_long(key))[2:].zfill(64)
    permuted = "".join(key_bits[i - 1] for i in PC1)
    
    # Split the 56-bit key into two 28-bit halves (c and d)
    c, d = permuted[:28], permuted[28:]
    round_keys = []
    
    # Loop 16 times to generate 16 round keys
    for i in range(16):
        # Perform circular left shift on c and d
        shift = shifts[i]
        c = c[shift:] + c[:shift]
        d = d[shift:] + d[:shift]
        # Combine c and d and apply PC-2 compression to get the 48-bit round key
        round_keys.append(PC2(long_to_bytes(int(c + d, 2), 7)))
    return round_keys

# Performs the S-Box substitution step.
def SBOX(chunks):
    res = ""
    # Process each of the 8 six-bit chunks
    for i, chunk in enumerate(chunks):
        # The first and last bits determine the row in the S-Box
        row = int(chunk[0] + chunk[-1], 2)
        # The middle four bits determine the column
        col = int(chunk[1:-1], 2)
        # Look up the 4-bit value in the corresponding S-Box
        res += bin(S_BOXES[i][row][col])[2:].zfill(4)
    return res

# The Feistel function (F-function), the core of a DES round.
def F(rpt, round_key):
    # E-box expands the 32-bit right half to 48 bits to match the round key size
    e_box = [
        32, 1, 2, 3, 4, 5, 4, 5, 6, 7, 8, 9, 8, 9, 10, 11, 12, 13,
        12, 13, 14, 15, 16, 17, 16, 17, 18, 19, 20, 21, 20, 21, 22, 23, 24, 25,
        24, 25, 26, 27, 28, 29, 28, 29, 30, 31, 32, 1
    ]
    rpt_bits = bin(bytes_to_long(rpt))[2:].zfill(32)
    expanded_block = long_to_bytes(int("".join(rpt_bits[e_box[i] - 1] for i in range(len(e_box))), 2), 6)
    
    # XOR the expanded block with the round key
    xored = xor(expanded_block, round_key)
    
    # Perform S-Box substitution
    b = bin(bytes_to_long(xored))[2:].zfill(48)
    six_bit_chunks = [b[i:i + 6] for i in range(0, 48, 6)]
    substituted = SBOX(six_bit_chunks)
    
    # Permute the result using the P-Box
    P_Box = [
        16, 7, 20, 21, 29, 12, 28, 17, 1, 15, 23, 26, 5, 18, 31, 10,
        2, 8, 24, 14, 32, 27, 3, 9, 19, 13, 30, 6, 22, 11, 4, 25
    ]
    transposed = long_to_bytes(int("".join(substituted[P_Box[i] - 1] for i in range(len(P_Box))), 2), length=4)
    return transposed

# Performs a single round of the Feistel network.
def feistal_round(block: bytes, round_key: bytes):
    # Split the 64-bit block into 32-bit left and right halves
    lpt = block[:4]
    rpt = block[4:]
    
    # The new left half is the old right half
    lpt_ = rpt
    # The new right half is the old left half XORed with the output of the F-function
    rpt_ = xor(F(rpt, round_key), lpt)
    return lpt_ + rpt_

# Encrypts data using the DES algorithm.
def encrypt(data: bytes, key: bytes):
    # Pad data and split into 8-byte blocks
    data = pad(data)
    blocks = [data[i:i + 8] for i in range(0, len(data), 8)]
    encrypted = b''
    keys = get_round_keys(key)
    
    for block in blocks:
        # 1. Apply initial permutation
        block = initial_permute(block)
        # 2. Perform 16 rounds of the Feistel network
        for i in range(16):
            block = feistal_round(block, keys[i])
        # 3. Swap the left and right halves
        block = block[4:] + block[:4]
        # 4. Apply the final permutation (inverse of initial)
        block = IP_1(block)
        encrypted += block
    return encrypted

# Decrypts data using the DES algorithm.
def decrypt(data: bytes, key: bytes):
    blocks = [data[i:i + 8] for i in range(0, len(data), 8)]
    decrypted = b''
    keys = get_round_keys(key)
    
    for block in blocks:
        # The process is identical to encryption, but round keys are applied in reverse order.
        block = initial_permute(block)
        for i in range(15, -1, -1): # Loop from 15 down to 0
            block = feistal_round(block, keys[i])
        block = block[4:] + block[:4]
        block = IP_1(block)
        decrypted += block
    return decrypted

# Main execution block
if __name__ == "__main__":
    m = b'Confidential Data'
    k = b"A1B2C3D4"
    print(f"Plaintext: {m.decode()}")
    print(f"Key: {k.decode()}")
    
    ct = encrypt(m, k)
    print(f"\nEncrypted (bytes): {ct}")
    
    pt = decrypt(ct, k)
    print(f"Decrypted: {unpad(pt).decode()}")
    
    # Verify correctness
    assert unpad(pt) == m