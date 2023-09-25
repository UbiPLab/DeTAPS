import hashlib

q = 264926624393126082647786234614522411169
h = 34970314419892642909507782969116958274309
g = 27464808337291794528868661597410061338052

def commit(pk, r):
    hkp1 = hashlib.sha256((" ".join(map(str, pk))).encode()).hexdigest()
    m = int(hkp1, 16)
    c = pow(g,m,q) * pow(h,r,q)
    return c


def verify(pk, r, c):
    hkp1 = hashlib.sha256((" ".join(map(str, pk))).encode()).hexdigest()
    m = int(hkp1, 16)
    return c == pow(g,m,q) * pow(h,r,q)
