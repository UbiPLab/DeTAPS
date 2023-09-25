import hashlib

q = 264926624393126082647786234614522411169
h = 34970314419892642909507782969116958274309
g = 27464808337291794528868661597410061338052

def commit(pk, r):
    hkp1 = hashlib.sha256((" ".join(map(str, pk))).encode()).hexdigest()
    m = int(hkp1, 16)
    c0 = pow(g,r,q)
    c1 = m * pow(h,r,q)
    c = (c0, c1)
    return c


def verify(pk, r, c):
    hkp1 = hashlib.sha256((" ".join(map(str, pk))).encode()).hexdigest()
    m = int(hkp1, 16)
    c0 = pow(g,r,q)
    c1 = m * pow(h,r,q)
    return c0 == c[0] and c1 == c[1]
