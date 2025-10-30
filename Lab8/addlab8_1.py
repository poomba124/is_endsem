# -----------------------------------------------------------
# Secure Data Storage and Transmission using GnuPG (Python)
# Fully updated for latest python-gnupg
# -----------------------------------------------------------

import gnupg
import os

# -----------------------------------------------------------
# Step 1: Create a folder for GPG keyring
# -----------------------------------------------------------
os.makedirs("./gpg_keys", exist_ok=True)  # Create folder if it doesn't exist
os.environ["GNUPGHOME"] = os.path.abspath("./gpg_keys")  # Set environment variable for keyring

# Initialize GPG object
gpg = gnupg.GPG()

# -----------------------------------------------------------
# Step 2: Generate a new RSA key pair
# -----------------------------------------------------------
key_input = gpg.gen_key_input(
    name_email="student@example.com",  # Key ID / Email
    passphrase="strongpassword",       # Protects private key
    key_type="RSA",                    # RSA algorithm
    key_length=2048                    # Key strength in bits
)

key = gpg.gen_key(key_input)
print("✅ Key pair generated successfully!")
print("Key Fingerprint:", key.fingerprint)

# -----------------------------------------------------------
# Step 3: Sample message to encrypt and sign
# -----------------------------------------------------------
message = "Confidential data from Cryptography Lab."

# -----------------------------------------------------------
# Step 4: Encrypt the message using the public key
# -----------------------------------------------------------
# Pass recipient as string (not a list) in latest python-gnupg
encrypted_data = gpg.encrypt(message, "student@example.com")
print("\n🔒 Encrypted message:")
print(str(encrypted_data))

# -----------------------------------------------------------
# Step 5: Decrypt the encrypted message using private key
# -----------------------------------------------------------
decrypted_data = gpg.decrypt(str(encrypted_data), passphrase="strongpassword")
print("\n🔓 Decrypted message:")
print(str(decrypted_data))

# -----------------------------------------------------------
# Step 6: Create a digital signature for the original message
# -----------------------------------------------------------
signed_data = gpg.sign(
    message,
    keyid=key.fingerprint,        # Sign with our private key
    passphrase="strongpassword"   # Unlock private key
)
print("\n✍️ Digital Signature created:")
print(str(signed_data))

# -----------------------------------------------------------
# Step 7: Verify the digital signature
# -----------------------------------------------------------
verified = gpg.verify(str(signed_data))
if verified:
    print("\n✅ Signature Verification Successful!")
    print("Signed by:", verified.username)
else:
    print("\n❌ Signature Verification Failed!")

# -----------------------------------------------------------
# Step 8: Optional – Save encrypted message to a file
# -----------------------------------------------------------
with open("encrypted_message.gpg", "w") as f:
    f.write(str(encrypted_data))
print("\n📁 Encrypted message saved to 'encrypted_message.gpg'.")
