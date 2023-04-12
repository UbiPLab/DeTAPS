import hashlib


def commit(pk, r):
    hkp1 = hashlib.sha256((" ".join(map(str, pk)) + str(r)).encode()).hexdigest()
    c = int(hkp1, 16)
    return c


def verify(pk, r, c):
    hkp1 = hashlib.sha256((" ".join(map(str, pk)) + str(r)).encode()).hexdigest()
    com = int(hkp1, 16)
    return com == c
