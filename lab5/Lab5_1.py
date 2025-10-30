def hash(input_string: str):
    hash_val=5381
    for char in input_string:
        ascii_val=ord(char)
        hash_val=(hash_val*33)+ascii_val
        hash_val^=(hash_val>>16)
        hash_val&= 0xFFFFFFFF
    return hash_val

msg="pepperoni"
print("hash value:",hex(hash(msg)))
