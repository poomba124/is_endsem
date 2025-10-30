# Lab5_2_server.py
import socket

# --- NETWORK CONFIGURATION ---
HOST = "127.0.0.1"  # Standard loopback interface address (localhost)
PORT = 65432        # Port to listen on (non-privileged ports are > 1023)

# The same custom hash function used by the client.
def hash(input_string: str):
    hash_val = 5381
    for char in input_string:
        ascii_val = ord(char)
        hash_val = (hash_val * 33) + ascii_val
        hash_val ^= (hash_val >> 16)
        hash_val &= 0xFFFFFFFF
    return hash_val

# --- SERVER LOGIC ---
# Create a socket object.
with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as server_socket:
    # Bind the socket to the host and port.
    server_socket.bind((HOST, PORT))
    # Enable the server to accept connections.
    server_socket.listen()
    print(f"Server listening on {HOST}:{PORT}...")

    # Wait for a client to connect. This is a blocking call.
    conn, addr = server_socket.accept()
    # Use a 'with' block to automatically close the connection when done.
    with conn:
        print(f"Connected by {addr}")
        
        # Receive data from the client (up to 1024 bytes).
        data = conn.recv(1024).decode()
        if not data:
            exit() # Exit if client sends empty data
            
        print(f"Server received: '{data}'")
        # Compute the hash of the received data.
        hash_val = hash(data)
        print(f"Server computed hash: {hash_val}")
        
        # Send the computed hash back to the client as a string.
        conn.sendall(str(hash_val).encode())