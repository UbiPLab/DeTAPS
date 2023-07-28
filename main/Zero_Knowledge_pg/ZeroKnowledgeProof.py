import hashlib
import math
import random
from pypbc import *
import datetime

qbits, rbits = 512, 160

p = 34970314419892642909507782969116958274309
g = 27464808337291794528868661597410061338052
q = 264926624393126082647786234614522411169

# pks = [5, 7789972324886433515830007310276509670070, 7008248216836606886526275535398584739933, 6625909801515796644859510823176628270480, 25295426451616168724967087516502713453749, 28029996752525009787242401169085825651492, 32626841904803863930033169205408718282290, 12291001626413898143176230851023168287300, 16477444000027208342145659911789049054275, 21722505318790365359601148762482653862245, 24711538406560794768747712229010041854468]
# n = 10
# z = 626318934400913296144646844922990020789
#
# R = 2070167107287647317232512132599078425034102486583640210000726391743156272227237335501505553076210467179239456003195018867908681438944648475960751264580420323678737545030714473523530976118623170091822144
# c = 218053754047908523890810358265511615791
#
# w = 145
# h = 14545602
# n3 = 5
# t = 5
# pk, r, u = 1, 1267331, 122641

def Prove1_1(q, n3, pks):
    V = 1
    B = 1
    a_list = [1]
    bits = [random.randint(0, 1) for x in range(n3 + 1)]
    for i in range(1, n3 + 1):
        a = random.randint(1, q)
        a_list.append(a)
        pk = pks[i]
        pk_a = pow(pk, a, q)
        B = B * pk_a % q
        b_i = bits[i]
        v = pow(pk, b_i, q)
        V = V * v % q
    hkp1 = hashlib.sha256((str(pks) + str(V) + str(B)).encode()).hexdigest()
    H = int(hkp1, 16) % q
    sendValue = [B, V, q, pks]
    a_list2 = [0]
    for i in range(1, n3 + 1):
        a = a_list[i]
        b_i = bits[i]
        a_ = H * b_i + a % q
        a_list2.append(a_)
    sendValue.append(a_list2)
    return sendValue


def VerifyProve1_1(sendvalue):
    B = sendvalue[0]
    V = sendvalue[1]
    q = sendvalue[2]
    pks = sendvalue[3]
    a_list = sendvalue[4]
    hkp1 = hashlib.sha256((str(pks) + str(V) + str(B)).encode()).hexdigest()
    H = int(hkp1, 16) % q
    mul_all = 1
    for i in range(1, len(a_list)):
        a_ = a_list[i]
        pk = pks[i]
        mul = pow(pk, a_, q)
        mul_all = mul_all * mul % q
    multiply = pow(V, H, q) * B
    return multiply % q == mul_all % q


def Prove1_2_1(q, g, w):
    a = random.randint(1, q)
    B = pow(g, a, q)
    V0 = pow(g, w, q)
    hkp1 = hashlib.sha256((str(g) + str(V0) + str(B)).encode()).hexdigest()
    H = int(hkp1, 16) % q
    a_ = w * H + a
    return g, V0, B, a_, q


def VerifyProve1_2_1(sendValue):
    g, V0, B, a_, q = sendValue
    hkp1 = hashlib.sha256((str(g) + str(V0) + str(B)).encode()).hexdigest()
    H = int(hkp1, 16) % q
    return pow(V0, H, q) * B % q == pow(g, a_, q)


def Prove1_2_2(q, g, n3, h, w):
    a_list = [0]
    bits = [random.randint(0, 1) for x in range(n3 + 1)]
    for i in range(1, n3 + 1 + 1):
        a = random.randint(0, q)
        a_list.append(a)
    B = 1
    for i in range(1, n3 + 1):
        B = B * pow(g, a_list[i], q) % q
    B = B * (pow(h, a_list[-1], q)) % q
    V1 = pow(g, sum(bits[1: n3 + 1]), q) * (pow(h, w, q)) % q
    hkp1 = hashlib.sha256((str(g) + str(h) + str(V1) + str(B)).encode()).hexdigest()
    H = int(hkp1, 16) % q
    sendValue = (g, h, V1, B, q, n3)
    a_list2 = [0]
    for i in range(1, n3 + 1 + 1):
        if i <= n3:
            a_ = bits[i] * H + a_list[i] % q
            a_list2.append(a_)
        else:
            a_ = w * H + a_list[i] % q
            a_list2.append(a_)
    return sendValue + (a_list2,)


def Verify1_2_2(sendValue):
    g, h, V1, B, q, n3, a_list = sendValue
    hkp1 = hashlib.sha256((str(g) + str(h) + str(V1) + str(B)).encode()).hexdigest()
    H = int(hkp1, 16) % q
    left = 1
    for i in range(1, n3 + 1):
        a_i = a_list[i]
        left = left * pow(g, a_i, q) % q
    left = left * pow(h, a_list[-1], q) % q
    right = pow(V1, H, q) * B % q
    return left == right


# def is_valid_base(a, c):
#     return math.gcd(a, c) == 1


def Prove1_3(g, h, q):
    r = random.randint(1, q)
    Com = pow(h, r, q)
    w = random.randint(0, q)
    r1 = random.randint(0, q)
    c1 = random.randint(0, q) * -1
    A = pow(h, w, q)
    # flag = is_valid_base(Com // g, q)
    # while not flag:
    #     r = random.randint(1, q)
    #     Com = pow(h, r, q)
    #     flag = is_valid_base(Com // g, q)
    B = pow(h, r1, q) * pow(Com // g, -1 * c1, q) % q

    hkp1 = hashlib.sha256((str(Com) + str(A) + str(B)).encode()).hexdigest()
    H = int(hkp1, 16) % q
    c2 = abs(H - c1) % q
    r2 = w + r * c2
    return Com, A, B, c1, c2, r1, r2, g, h, q


def Verify1_3(sendValue):
    Com, A, B, c1, c2, r1, r2, g, h, q = sendValue
    hkp1 = hashlib.sha256((str(Com) + str(A) + str(B)).encode()).hexdigest()
    H = int(hkp1, 16) % q
    flag1 = abs(H - c1) % q == c2
    flag2 = pow(h, r1, q) * pow(Com // g, -c1, q) % q == B
    flag3 = pow(h, r2, q) == A * pow(Com, c2, q) % q
    return flag1 and flag2 and flag3


def Prove2_1(n, c, z, q, R, pks, S):
    bits = [0 for x in range(n + 1)]
    for i in S:
        bits[i] = 1
    A = 1
    k_list = [random.randint(0, q) for i in range(n + 1)]
    k_z = k_list[0]
    for i in range(1, n + 1):
        pk = pks[i]
        k_bi = k_list[i]
        A = A * pow(pk, -1 * c * k_bi, p) % p
    A = A * pow(g, k_z, p) % p
    r = random.randint(0, q)
    B = pow(g, z + r, p)
    z_2 = z + r
    R_2 = R * pow(g, r, p) % p
    hkp1 = hashlib.sha256((str(pks[1:]) + str(c) + str(A) + str(B) + str(z_2) + str(R_2)).encode()).hexdigest()
    H = int(hkp1, 16) % p
    b_list2 = [z_2 * H + k_z % p]
    for i in range(1, n + 1):
        b_i = bits[i]
        k_bi = k_list[i]
        b = b_i * H + k_bi % p
        b_list2.append(b)
    return pks, c, A, B, z_2, R_2, b_list2


def Verify2_1(sendValue):
    pks, c, A, B, z_2, R_2,b_list2 = sendValue
    hkp1 = hashlib.sha256((str(pks[1:]) + str(c) + str(A) + str(B) + str(z_2) + str(R_2)).encode()).hexdigest()
    H = int(hkp1, 16) % p
    left = A * pow(R_2, H, p) % p
    mul = 1
    n = len(pks) - 1
    for i in range(1, n+1):
        pk = pks[i]
        b = b_list2[i]
        mul = mul * pow(pk, b, p) % p
    mul = pow(mul, c, p)
    left = left * mul % p
    z = b_list2[0]
    right = pow(g, z, p) % p

    return left == right


def Prove2_2_1(g, w, q):
    T0 = pow(g, w, q)
    a = random.randint(0, q)
    B = pow(g, a, q)
    hkp1 = hashlib.sha256((str(g) + str(T0) + str(B)).encode()).hexdigest()
    H = int(hkp1, 16) % q
    a_ = w * H + a
    return g, T0, B, a_, q


def Verify2_2_1(sendValue):
    g, T0, B, a_, q = sendValue
    hkp1 = hashlib.sha256((str(g) + str(T0) + str(B)).encode()).hexdigest()
    H = int(hkp1, 16) % q
    left = pow(T0, H, q) * B % q
    right = pow(g, a_, q)
    return left == right


def Prove2_2_2(q, g, n, h, w):
    a_list = [0]
    bits = [random.randint(0, 1) for x in range(n + 1)]
    for i in range(1, n + 1 + 1):
        a = random.randint(0, q)
        a_list.append(a)
    B = 1
    for i in range(1, n + 1):
        B = B * pow(g, a_list[i], q) % q
    B = B * (pow(h, a_list[-1], q)) % q
    T1 = pow(g, sum(bits[1: n + 1]), q) * (pow(h, w, q)) % q
    hkp1 = hashlib.sha256((str(g) + str(h) + str(T1) + str(B)).encode()).hexdigest()
    H = int(hkp1, 16) % q
    sendValue = (g, h, T1, B, q, n)
    a_list2 = [0]
    for i in range(1, n + 1 + 1):
        if i <= n:
            a_ = bits[i] * H + a_list[i] % q
            a_list2.append(a_)
        else:
            a_ = w * H + a_list[i] % q
            a_list2.append(a_)
    return sendValue + (a_list2,)


def Verify2_2_2(sendValue):
    g, h, T1, B, q, n, a_list = sendValue
    hkp1 = hashlib.sha256((str(g) + str(h) + str(T1) + str(B)).encode()).hexdigest()
    H = int(hkp1, 16) % q
    left = 1
    for i in range(1, n + 1):
        a_i = a_list[i]
        left = left * pow(g, a_i, q) % q
    left = left * pow(h, a_list[-1], q) % q
    right = pow(T1, H, q) * B % q
    return left == right


def Prove2_3(g, h, q):
    r = random.randint(1, q)
    Com = pow(h, r, q)
    w = random.randint(0, q)
    r1 = random.randint(0, q)
    c1 = random.randint(0, q) * -1
    A = pow(h, w, q)
    # flag = is_valid_base(Com // g, q)
    # while not flag:
    #     r = random.randint(1, q)
    #     Com = pow(h, r, q)
    #     flag = is_valid_base(Com // g, q)
    B = pow(h, r1, q) * pow(Com // g, -1 * c1, q) % q

    hkp1 = hashlib.sha256((str(Com) + str(A) + str(B)).encode()).hexdigest()
    H = int(hkp1, 16) % q
    c2 = abs(H - c1) % q
    r2 = w + r * c2
    return Com, A, B, c1, c2, r1, r2, g, h, q


def Verify2_3(sendValue):
    Com, A, B, c1, c2, r1, r2, g, h, q = sendValue
    hkp1 = hashlib.sha256((str(Com) + str(A) + str(B)).encode()).hexdigest()
    H = int(hkp1, 16) % q
    flag1 = abs(H - c1) % q == c2
    flag2 = pow(h, r1, q) * pow(Com // g, -c1, q) % q == B
    flag3 = pow(h, r2, q) == A * pow(Com, c2, q) % q
    return flag1 and flag2 and flag3


def Prove3(pk, r, g, h, q):
    A = pow(g, pk, q) * pow(h, r, q) % q
    a1 = random.randint(0, q)
    a2 = random.randint(0, q)
    B = pow(g, a1, q) * pow(h, a2, q) % q
    hkp1 = hashlib.sha256((str(g) + str(h) + str(A) + str(B)).encode()).hexdigest()
    H = int(hkp1, 16) % q
    a1_ = H * pk + a1
    a2_ = H * r + a2
    return A, B, a1_, a2_, g, h, q


def Verify3(sendValue):
    A, B, a1_, a2_, g, h, q = sendValue
    hkp1 = hashlib.sha256((str(g) + str(h) + str(A) + str(B)).encode()).hexdigest()
    H = int(hkp1, 16) % q
    return pow(A, H, q) * B % q == pow(g, a1_, q) * pow(h, a2_, q) % q


def Prove4(q, u, w):
    a = random.randint(1, q)
    B = pow(u, a, q)
    c1 = pow(u, w, q)
    hkp1 = hashlib.sha256((str(u) + str(c1) + str(B)).encode()).hexdigest()
    H = int(hkp1, 16) % q
    a_ = w * H + a
    return u, c1, B, a_, q


def Verify4(sendValue):
    u, c1, B, a_, q = sendValue
    hkp1 = hashlib.sha256((str(u) + str(c1) + str(B)).encode()).hexdigest()
    H = int(hkp1, 16) % q
    return pow(c1, H, q) * B % q == pow(u, a_, q)


def Prove5(pk, t, qbits, rbits, q):
    params = Parameters(qbits=qbits, rbits=rbits)  # 参数初始化
    pairing = Pairing(params)
    g = Element.random(pairing, G1)
    g1 = Element.random(pairing, G1)
    gid = Element.random(pairing, G1)
    hkp1 = hashlib.sha256(str(pk).encode()).hexdigest()
    hash_G_1 = Element.from_hash(pairing, G1, hkp1)
    on = pairing.apply(g, hash_G_1)
    down = pairing.apply(g1, gid)
    A = Element.__ifloordiv__(on, down)
    ind = Element.__ifloordiv__(on ** t, down ** t)
    a = random.randint(0, q)
    B = A ** a
    hkp1 = hashlib.sha256((str(ind) + str(A) + str(B)).encode()).hexdigest()
    H = int(hkp1, 16) % q
    a_ = a + H * t
    return ind, A, B, a_, q


def Verify5(sendValue):
    ind, A, B, a_, q = sendValue
    hkp1 = hashlib.sha256((str(ind) + str(A) + str(B)).encode()).hexdigest()
    H = int(hkp1, 16) % q
    return (ind ** H) * B == A ** a_


def GenerateProofs(n3, pks, n, t,z, c, R, pk,S):
    w = 1451225
    h = 14545602
    r = 1267331
    u = 122641
    sendvalue1 = Prove1_1(q, n3, pks)

    sendvalue2 = Prove1_2_1(q, g, w)

    sendvalue3 = Prove1_2_2(q, g, n3, h, w)

    sendvalue4 = Prove1_3(g, h, q)

    sendvalue5 = Prove2_1(n, c, z, q, R, pks, S)

    sendvalue6 = Prove2_2_1(g, w, q)

    sendvalue7 = Prove2_2_2(q, g, n, h, w)

    sendvalue8 = Prove2_3(g, h, q)

    snedvalue9 = Prove3(pk, r, g, h, q)

    sendvalue10 = Prove4(q, u, w)

    sendvalue11 = Prove5(pk, t, qbits, rbits, q)
    return sendvalue1, sendvalue2, sendvalue3, sendvalue4, sendvalue5, sendvalue6, sendvalue7, sendvalue8, snedvalue9, sendvalue10, sendvalue11


def VerifyProofs(sendAll):
    sendvalue1, sendvalue2, sendvalue3, sendvalue4, sendvalue5, sendvalue6, sendvalue7, sendvalue8, snedvalue9, sendvalue10, sendvalue11 = sendAll
    f1 = VerifyProve1_1(sendvalue1)
    f2 = VerifyProve1_2_1(sendvalue2)
    f3 = Verify1_2_2(sendvalue3)
    f4 = Verify1_3(sendvalue4)
    f5 = Verify2_1(sendvalue5)
    f6 = Verify2_2_1(sendvalue6)
    f7 = Verify2_2_2(sendvalue7)
    f8 = Verify2_3(sendvalue8)
    f9 = Verify3(snedvalue9)
    f10 = Verify4(sendvalue10)
    f11 = Verify5(sendvalue11)
    return f1 and f2 and f3 and f4 and f5 and f6 and f7 and f8 and f9 and f10 and f11


if __name__ == '__main__':
    pks = [5, 7789972324886433515830007310276509670070, 7008248216836606886526275535398584739933,
           6625909801515796644859510823176628270480, 25295426451616168724967087516502713453749,
           28029996752525009787242401169085825651492, 32626841904803863930033169205408718282290,
           12291001626413898143176230851023168287300, 16477444000027208342145659911789049054275,
           21722505318790365359601148762482653862245, 24711538406560794768747712229010041854468]
    n = 10
    z = 626318934400913296144646844922990020789
    R = 2070167107287647317232512132599078425034102486583640210000726391743156272227237335501505553076210467179239456003195018867908681438944648475960751264580420323678737545030714473523530976118623170091822144
    c = 218053754047908523890810358265511615791

    n3 = 5
    t = 5
    pk = 1
    S = [2,4,6,8,10]
    # sendvalue5 = Prove2_1(n, c, z, q, R, pks)
    # f5 = Verify2_1(sendvalue5)
    # print(f5)
    sendAll = GenerateProofs(n3, pks, n, t, z, c, R, pk,S)
    print(VerifyProofs(sendAll))

    # sendvalue4 = Prove1_3(g, h, q)
    # f4 = Verify1_3(sendvalue4)
    # print(f4)

