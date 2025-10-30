from phe import paillier   # Paillier cryptosystem library
#pip install phe

# ============================================================
# 1️⃣ CREATE DATASET
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
    "paillier encryption is cool"
]

doc_ids = list(range(len(documents)))  # [0,1,2,...,9]

print("📄 Document Dataset:")
for i, doc in enumerate(documents):
    print(f"Doc {i}: {doc}")

# ============================================================
# 2️⃣ PAILLIER KEY GENERATION
# ============================================================
public_key, private_key = paillier.generate_paillier_keypair()
print("\n🔑 Paillier Keys generated.")
print("Public key (n):", public_key.n)
print("Private key λ and μ are kept secret.")


# ============================================================
# 3️⃣ BUILD INVERTED INDEX (plaintext words)
# ============================================================
# Example: "sky" → [0,2,7,8]
inverted_index = {}

for doc_id, text in zip(doc_ids, documents):
    for word in text.split():
        word = word.lower()
        if word not in inverted_index:
            inverted_index[word] = set()
        inverted_index[word].add(doc_id)

# Convert sets to lists
for word in inverted_index:
    inverted_index[word] = list(inverted_index[word])

print("\n📑 Plaintext Inverted Index:")
for word, ids in inverted_index.items():
    print(f"{word}: {ids}")


# ============================================================
# 4️⃣ ENCRYPT THE INVERTED INDEX (Encrypt document IDs)
# ============================================================
encrypted_index = {}

for word, ids in inverted_index.items():
    encrypted_ids = [public_key.encrypt(i) for i in ids]  # encrypt doc IDs
    encrypted_index[word] = encrypted_ids

print("\n🔐 Encrypted Inverted Index (only ciphertexts shown):")
for word, enc_ids in encrypted_index.items():
    print(f"{word}: {[str(e.ciphertext()) for e in enc_ids]}")


# ============================================================
# 5️⃣ SEARCH FUNCTION
# ============================================================
def search(query):
    """
    Search for a plaintext query term.
    Retrieve encrypted doc IDs and decrypt them using private key.
    """
    query = query.lower()
    print(f"\n🔎 Searching for '{query}' ...")

    if query in encrypted_index:
        encrypted_doc_ids = encrypted_index[query]
        decrypted_doc_ids = [private_key.decrypt(e) for e in encrypted_doc_ids]

        print(f"✅ Match found in document IDs: {decrypted_doc_ids}")
        print("📄 Matching Documents:")
        for doc_id in decrypted_doc_ids:
            print(f" - Doc {doc_id}: {documents[doc_id]}")
    else:
        print("❌ No matches found.")


# ============================================================
# 6️⃣ TEST SEARCH
# ============================================================
search("sky")
search("sun")
search("paillier")
search("random")  # not present
