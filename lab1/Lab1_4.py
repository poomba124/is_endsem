K = [[3, 3], [2, 7]]

def mod26(x):
    return x % 26

def prepare(msg):
    msg = msg.upper().replace(" ", "")
    if len(msg) % 2 != 0:
        msg += "X"
    return msg

def encdig(a, b):
    x = (K[0][0]*a + K[0][1]*b) % 26
    y = (K[1][0]*a + K[1][1]*b) % 26
    return x, y

message = "We live in an insecure world"
msg = prepare(message)
ciphertext = ""

for i in range(0, len(msg), 2):
    a = ord(msg[i]) - ord('A')
    b = ord(msg[i+1]) - ord('A')
    x, y = encdig(a, b)
    ciphertext += chr(x + ord('A')) + chr(y + ord('A'))

print(ciphertext) # AUFAXSLDNNLDOMOOLKEMGHAL