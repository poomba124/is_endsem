import string
charset = string.ascii_uppercase

class A:
    def __init__(self, msg, key):
        self.pt = msg
        self.key = key
        self.ct = ""

    def encrypt(self):
        self.ct = ""
        for i, j in zip(self.pt, (self.key*50)[:len(self.pt)]):
            if i.upper() in charset:
                ok = charset[(charset.index(i.upper()) + charset.index(j.upper())) % 26]
                if i.isupper(): self.ct += ok
                else: self.ct += ok.lower()
            else:
                self.ct += i
        return self.ct

    def decrypt(self):
        pt = ""
        for i, j in zip(self.ct, (self.key*50)[:len(self.ct)]):
            if i.upper() in charset:
                ok = charset[(charset.index(i.upper()) - charset.index(j.upper())) % 26]
                if i.isupper(): pt += ok
                else: pt += ok.lower()
            else:
                pt += i
        self.pt = pt
        return self.pt

class B:
    def __init__(self, msg, key):
        self.pt = msg
        self.key = str(key)
        self.ct = ""

    def encrypt(self):
        self.ct = ""
        key_stream = [int(self.key)]
        for ch in self.pt:
            if ch.upper() in charset:
                key_stream.append(charset.index(ch.upper()))
        key_stream = key_stream[:len(self.pt)]
        idx = 0
        for i in self.pt:
            if i.upper() in charset:
                j = key_stream[idx]
                ok = charset[(charset.index(i.upper()) + j) % 26]
                if i.isupper(): self.ct += ok
                else: self.ct += ok.lower()
                idx += 1
            else:
                self.ct += i
        return self.ct

    def decrypt(self):
        self.pt = ""
        key_stream = [int(self.key)]
        idx = 0
        for i in self.ct:
            if i.upper() in charset:
                j = key_stream[idx]
                ok = charset[(charset.index(i.upper()) - j) % 26]
                if i.isupper(): self.pt += ok
                else: self.pt += ok.lower()
                key_stream.append(charset.index(ok.upper()))
                idx += 1
            else:
                self.pt += i
        return self.pt

if __name__ == "__main__":
    msg = "the house is being sold tonight"
    a = A(msg, 'dollars')
    print(a.encrypt())
    print(a.decrypt())
    print()
    b = B(msg, 7)
    print(b.encrypt())
    print(b.decrypt())