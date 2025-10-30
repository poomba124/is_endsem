from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
import base64
import hashlib
#pip install pycryptodome

# ============================================================
# 1️⃣ AES ENCRYPTION & DECRYPTION FUNCTIONS
# ============================================================

# Generate a 16-byte AES key from a password
SECRET_KEY = hashlib.sha256(b"my_secret_password").digest()[:16]  # 128-bit key

def encrypt_text(plaintext):
    """
    Encrypts a string using AES (CBC mode).
    Returns base64-encoded ciphertext.
    """
    cipher = AES.new(SECRET_KEY, AES.MODE_CBC)  # Create cipher object with random IV
    ct_bytes = cipher.encrypt(pad(plaintext.encode(), AES.block_size))  # pad to 16 bytes
    iv = base64.b64encode(cipher.iv).decode()  # encode IV
    ct = base64.b64encode(ct_bytes).decode()   # encode ciphertext
    return iv + ":" + ct  # return both IV and ciphertext together

def decrypt_text(ciphertext):
    """
    Decrypts a base64-encoded ciphertext string using AES (CBC mode).
    Returns the plaintext.
    """
    iv_str, ct_str = ciphertext.split(":")
    iv = base64.b64decode(iv_str)
    ct = base64.b64decode(ct_str)
    cipher = AES.new(SECRET_KEY, AES.MODE_CBC, iv)
    pt = unpad(cipher.decrypt(ct), AES.block_size)
    return pt.decode()


# ============================================================
# 2️⃣ CREATE A SMALL DOCUMENT DATASET
# ============================================================
documents = [
    "the sky is blue",
    "the sun is bright",
    "the sun in the blue sky",
    "we can see the shining sun",
    "bright stars light up the night",
    "the moon and stars are beautiful",
    "we love the night sky",
    "the sky is full of stars",
    "blue sky and bright sun",
    "encryption protects sensitive data"
]

# Assign each document a simple ID
doc_ids = list(range(len(documents)))  # [0,1,2,...,9]


# ============================================================
# 3️⃣ BUILD INVERTED INDEX (word → list of doc IDs)
# ============================================================
# Example: "sky" → [0, 2, 7, 8]
inverted_index = {}

for doc_id, text in zip(doc_ids, documents):
    for word in text.split():
        word = word.lower()
        if word not in inverted_index:
            inverted_index[word] = set()
        inverted_index[word].add(doc_id)

# Convert sets to lists for easier encryption
for word in inverted_index:
    inverted_index[word] = list(inverted_index[word])

print("\n📄 Original Inverted Index (unencrypted):")
for word, ids in inverted_index.items():
    print(f"{word}: {ids}")


# ============================================================
# 4️⃣ ENCRYPT THE INDEX (both words and doc IDs)
# ============================================================
encrypted_index = {}

for word, ids in inverted_index.items():
    encrypted_word = encrypt_text(word)               # encrypt the keyword
    encrypted_ids = [encrypt_text(str(i)) for i in ids]  # encrypt each document ID
    encrypted_index[encrypted_word] = encrypted_ids

print("\n🔐 Encrypted Inverted Index:")
for enc_word, enc_ids in encrypted_index.items():
    print(f"{enc_word}: {enc_ids}")


# ============================================================
# 5️⃣ SEARCH FUNCTION FOR ENCRYPTED INDEX
# ============================================================
def search(query):
    """
    Encrypt the query word, search encrypted index,
    decrypt matching doc IDs, and display matching documents.
    """
    print(f"\n🔎 Searching for: '{query}'")

    # 1. Encrypt the query word
    encrypted_query = encrypt_text(query.lower())

    # 2. Search for matching encrypted word in the index
    if encrypted_query in encrypted_index:
        encrypted_doc_ids = encrypted_index[encrypted_query]

        # 3. Decrypt the doc IDs to find actual matching documents
        decrypted_doc_ids = [int(decrypt_text(enc_id)) for enc_id in encrypted_doc_ids]

        # 4. Display matching documents
        print(f"✅ Found in documents IDs: {decrypted_doc_ids}")
        for doc_id in decrypted_doc_ids:
            print(f"📄 Document {doc_id}: {documents[doc_id]}")

    else:
        print("❌ No matches found for this query.")


# ============================================================
# 6️⃣ TEST SEARCH QUERIES
# ============================================================
search("sky")
search("sun")
search("encryption")
search("random")  # should not be found
