import socket
HOST = "127.0.0.1"
PORT = 65432

def custom_hash(input_string: str):
    hash_val = 5381
    for char in input_string:
        ascii_val = ord(char)
        hash_val = (hash_val * 33) + ascii_val
        hash_val ^= (hash_val >> 16)
        hash_val &= 0xFFFFFFFF
    return hash_val

message = "not so secret message"

with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as client_socket:
    client_socket.connect((HOST, PORT))
    client_socket.sendall(message.encode())

    server_hash = int(client_socket.recv(1024).decode())
    local_hash = custom_hash(message)

    print(f"Original message : {message}")
    print(f"Local computed   : {local_hash}")
    print(f"Hash from server : {server_hash}")


    if server_hash == local_hash:
        print("Data integrity verified")
    else:
        print("Data corrupted or tampered with!")
