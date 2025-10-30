import string

charset = string.ascii_uppercase


class A:
    def __init__(self, msg, key):
        self.pt = msg
        self.key = key
        self.ct = ""

    def encrypt(self):
        self.ct = ""
        for i in self.pt:
            if i.upper() in charset:
                ok = charset[(charset.index(i.upper()) + self.key) % 26]
                if i.isupper():
                    self.ct += ok
                else:
                    self.ct += ok.lower()
            else:
                self.ct += i
        return self.ct

    def decrypt(self):
        self.pt = ""
        for i in self.ct:
            if i.upper() in charset:
                ok = charset[(charset.index(i.upper()) - self.key) % 26]
                if i.isupper():
                    self.pt += ok
                else:
                    self.pt += ok.lower()
            else:
                self.pt += i
        return self.pt


class B:
    def __init__(self, msg, key):
        self.pt = msg
        self.key = key
        self.ct = ""

    def encrypt(self):
        self.ct = ""
        for i in self.pt:
            if i.upper() in charset:
                ok = charset[(charset.index(i.upper()) * self.key) % 26]
                if i.isupper():
                    self.ct += ok
                else:
                    self.ct += ok.lower()
            else:
                self.ct += i
        return self.ct

    def decrypt(self):
        self.pt = ""
        keyinv = 1
        while (keyinv * self.key) % 26 != 1:
            keyinv += 1

        for i in self.ct:
            if i.upper() in charset:
                ok = charset[(charset.index(i.upper()) * keyinv) % 26]
                if i.isupper():
                    self.pt += ok
                else:
                    self.pt += ok.lower()
            else:
                self.pt += i
        return self.pt


class C:
    def __init__(self, msg, key):
        self.pt = msg
        self.a, self.b = key
        self.ct = ""

    def encrypt(self):
        self.ct = ""
        for i in self.pt:
            if i.upper() in charset:
                ok = charset[((self.a * (charset.index(i.upper()))) + self.b) % 26]
                if i.isupper():
                    self.ct += ok
                else:
                    self.ct += ok.lower()
            else:
                self.ct += i
        return self.ct

    def decrypt(self):
        a_inv = 1
        while (a_inv * self.a) % 26 != 1:
            a_inv += 1
        self.pt = ""
        for i in self.ct:
            if i.upper() in charset:
                ok = charset[(((charset.index(i.upper()) - self.b) % 26) * a_inv) % 26]
                if i.isupper():
                    self.pt += ok
                else:
                    self.pt += ok.lower()
            else:
                self.pt += i
        return self.pt


if __name__ == "__main__":
    m = "This is IS Lab"
    a = A(m, 20)
    e = a.encrypt()
    d = a.decrypt()
    print(f"{e}\n{d}")
    assert d == m

    print()

    m = "This is IS Lab"
    b = B(m, 15)
    e = b.encrypt()
    d = b.decrypt()
    print(f"{e}\n{d}")
    assert d == m

    print()

    m = "This is IS Lab"
    c = C(m, (15, 20))
    e = c.encrypt()
    d = c.decrypt()
    print(f"{e}\n{d}")
    assert d == m