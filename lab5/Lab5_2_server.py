import socket
HOST="127.0.0.1"
PORT=65432

def hash(input_string: str):
    hash_val=5381
    for char in input_string:
        ascii_val=ord(char)
        hash_val=(hash_val*33)+ascii_val
        hash_val^=(hash_val>>16)
        hash_val&= 0xFFFFFFFF
    return hash_val

with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as server_socket:
    server_socket.bind((HOST, PORT))
    server_socket.listen()
    print(f"Server listening on {HOST}:{PORT}...")

    conn, addr = server_socket.accept()
    with conn:
        print(f"Connected by {addr}")

        data = conn.recv(1024).decode()
        if not data:
            exit()
        print(f"Server received: {data}")
        hash_val = hash(data)
        print(f"Server computed hash: {hash_val}")
        conn.sendall(str(hash_val).encode())