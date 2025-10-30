key = "GUIDANCE"
alphabet = "ABCDEFGHIKLMNOPQRSTUVWXYZ"
matrix = [c for c in key] + [c for c in alphabet if c not in key]
matrix = [matrix[:5], matrix[5:10], matrix[10:15], matrix[15:20], matrix[20:25]]

def pos(c):
    if c == "J": c = "I"
    for r, row in enumerate(matrix):
        if c in row:
            return r, row.index(c)

def encdig(a, b):
    ra, ca = pos(a)
    rb, cb = pos(b)
    if ra == rb:
        return matrix[ra][(ca+1)%5] + matrix[rb][(cb+1)%5]
    elif ca == cb:
        return matrix[(ra+1)%5][ca] + matrix[(rb+1)%5][cb]
    else:
        return matrix[ra][cb] + matrix[rb][ca]

def prepare(msg):
    msg = msg.upper().replace("J","I").replace(" ","")
    res = ""
    i = 0
    while i < len(msg):
        a = msg[i]
        b = msg[i+1] if i+1 < len(msg) else "X"
        if a == b:
            b = "X"
            i += 1
        else:
            i += 2
        res += a + b
    return res

message = "The key is hidden under the door pad"
digraphs = prepare(message)
ciphertext = ""
for i in range(0, len(digraphs), 2):
    ciphertext += encdig(digraphs[i], digraphs[i+1])

print(ciphertext) # POCLBXDRLGIYIBCGBGLXPOBILZLTTGIY