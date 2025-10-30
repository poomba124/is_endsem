import string
charset = string.ascii_uppercase
rot = - ((charset.index('C') - charset.index('Y')) % 26)
ct = 'XVIEWYWI'
pt = "".join(charset[(charset.index(c) - 4) % 26] for c in ct)
print(pt)