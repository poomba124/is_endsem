# Lab5_2_client.py
import socket

# --- NETWORK CONFIGURATION ---
# The server's hostname or IP address and port. Must match the server.
HOST = "127.0.0.1"
PORT = 65432

# The same custom hash function used by the server.
def custom_hash(input_string: str):
    hash_val = 5381
    for char in input_string:
        ascii_val = ord(char)
        hash_val = (hash_val * 33) + ascii_val
        hash_val ^= (hash_val >> 16)
        hash_val &= 0xFFFFFFFF
    return hash_val

# The message to be sent.
message = "not so secret message"

# --- CLIENT LOGIC ---
# Create a socket object.
with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as client_socket:
    # Connect to the server.
    client_socket.connect((HOST, PORT))
    # Send the entire message to the server.
    client_socket.sendall(message.encode())

    # Wait to receive the hash value computed by the server.
    server_hash_str = client_socket.recv(1024).decode()
    server_hash = int(server_hash_str)
    
    # Compute the hash of the original message locally.
    local_hash = custom_hash(message)

    print(f"Original message : '{message}'")
    print(f"Local computed hash : {local_hash}")
    print(f"Hash from server    : {server_hash}")

    # The integrity check: compare the two hashes.
    if server_hash == local_hash:
        print("\n✅ Data integrity verified. The message was received correctly.")
    else:
        print("\n❌ Data corrupted or tampered with! The hashes do not match.")