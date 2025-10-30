import hashlib

# -------------------------------
# MD5
# -------------------------------
def compute_md5(data: str) -> str:
    return hashlib.md5(data.encode()).hexdigest()

def verify_md5(data: str, hash_value: str) -> bool:
    return compute_md5(data) == hash_value


# -------------------------------
# SHA-1
# -------------------------------
def compute_sha1(data: str) -> str:
    return hashlib.sha1(data.encode()).hexdigest()

def verify_sha1(data: str, hash_value: str) -> bool:
    return compute_sha1(data) == hash_value


# -------------------------------
# SHA-256
# -------------------------------
def compute_sha256(data: str) -> str:
    return hashlib.sha256(data.encode()).hexdigest()

def verify_sha256(data: str, hash_value: str) -> bool:
    return compute_sha256(data) == hash_value


# -------------------------------
# SHA-512
# -------------------------------
def compute_sha512(data: str) -> str:
    return hashlib.sha512(data.encode()).hexdigest()

def verify_sha512(data: str, hash_value: str) -> bool:
    return compute_sha512(data) == hash_value


# -------------------------------
# DEMO
# -------------------------------
if __name__ == "__main__":
    text = input("Enter text:")

    # MD5
    md5_hash = compute_md5(text)
    print("MD5:    ", md5_hash, "-> Verified?", verify_md5(text, md5_hash))

    # SHA-1
    sha1_hash = compute_sha1(text)
    print("SHA-1:  ", sha1_hash, "-> Verified?", verify_sha1(text, sha1_hash))

    # SHA-256
    sha256_hash = compute_sha256(text)
    print("SHA-256:", sha256_hash, "-> Verified?", verify_sha256(text, sha256_hash))

    # SHA-512
    sha512_hash = compute_sha512(text)
    print("SHA-512:", sha512_hash, "-> Verified?", verify_sha512(text, sha512_hash))
