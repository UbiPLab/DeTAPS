import hashlib
import math
import random
from pypbc import *
import datetime

qbits, rbits = 512, 160
q = 1454560154151321541521
# g, w, h, n3, pks, n, t, c, R, pk, r, u
g = 1454560
w = 145
h = 14545602
n3 = 5
pks = [122331, 12123331, 1267331, 122641, 1222342331, 122342331, 122331, 12123331, 1267331, 122641, 1222342331,
       122342331]
n = 10
t = 5
c = 541651
R, pk, r, u = 122331, 12123331, 1267331, 122641
parameter = (qbits, rbits, q, g, w, h, n3, pks, n, t, c, R, pk, r, u)

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


def is_valid_base(a, c):
    return math.gcd(a, c) == 1


def Prove1_3(g, h, q):
    r = random.randint(1, q)
    Com = pow(h, r, q)
    w = random.randint(0, q)
    r1 = random.randint(0, q)
    c1 = random.randint(0, q)
    A = pow(h, w, q)
    flag = is_valid_base(Com // g, q)
    while not flag:
        r = random.randint(1, q)
        Com = pow(h, r, q)
        flag = is_valid_base(Com // g, q)
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
    flag1 = abs(H - c1) == c2
    flag2 = pow(h, r1, q) == B * pow(Com // g, c1, q) % q
    flag3 = pow(h, r2, q) == A * pow(Com, c2, q) % q
    return flag1 and flag2 and flag3


def Prove2_1(n, c, R, q, pks):
    a_list = [0]
    B = 1
    g_z = 1
    bits = [x for x in range(n + 1)]
    for i in range(1, n + 1):
        a_i = random.randint(0, q)
        a_list.append(a_i)
        pk = pks[i]
        b_i = bits[i]
        g_z = g_z * pow(pk, b_i, q) % q
        pk_a = pow(pk, a_i, q)
        B = B * pk_a % q
    g_z = pow(g_z, c, q) * R
    hkp1 = hashlib.sha256((str(pks[1:]) + str(c) + str(R) + str(g_z) + str(B)).encode()).hexdigest()
    H = int(hkp1, 16) % q
    a_list2 = [0]
    for i in range(1, n + 1):
        a_i = a_list[i]
        b_i = bits[i]
        a_ = b_i * H + a_i % q
        a_list2.append(a_)
    return B, a_list2, pks, c, R, g_z, n, q


def Verify2_1(sendValue):
    B, a_list2, pks, c, R, g_z, n, q = sendValue
    hkp1 = hashlib.sha256((str(pks[1:]) + str(c) + str(R) + str(g_z) + str(B)).encode()).hexdigest()
    H = int(hkp1, 16) % q
    left = pow(g_z // R, H, q) * pow(B, c, q) % q
    right = 1
    for i in range(1, n + 1):
        a_ = a_list2[i]
        pk = pks[i]
        right = right * pow(pk, a_, q) % q
    return left == pow(right, c, q)


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
    c1 = random.randint(0, q)
    A = pow(h, w, q)
    flag = is_valid_base(Com // g, q)
    while not flag:
        r = random.randint(1, q)
        Com = pow(h, r, q)
        flag = is_valid_base(Com // g, q)
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
    flag1 = abs(H - c1) == c2
    flag2 = pow(h, r1, q) == B * pow(Com // g, c1, q) % q
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


def GenerateProofs():
    qbits, rbits, q, g, w, h, n3, pks, n, t, c, R, pk, r, u = parameter
    sendvalue1 = Prove1_1(q, n3, pks)

    sendvalue2 = Prove1_2_1(q, g, w)

    sendvalue3 = Prove1_2_2(q, g, n3, h, w)

    sendvalue4 = Prove1_3(g, h, q)

    sendvalue5 = Prove2_1(n, c, R, q, pks)

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
    starttime = datetime.datetime.now()
    sendAll = GenerateProofs()
    endtime = datetime.datetime.now()
    # starttime = datetime.datetime.now()
    # q = 1454560154151321541521
    # n3 = 5
    # pks = [122331, 12123331, 1267331, 122641, 1222342331, 122342331]
    # for i in range(11):
    #     pks.append(i)
    # # bits = [0, 1, 1, 1, 0, 0, 1, 0, 0, 0, 0]
    # sendValue = Prove1_1(q, n3, pks)
    # rs = VerifyProve1_1(sendValue)
    # print(rs)
    # g = 1454560
    # w = 145
    # sendValue2 = Prove1_2_1(q, g, w)
    # b = VerifyProve1_2_1(sendValue2)
    # print(b)
    # n = 10
    # sendValue3 = Prove1_2_2(q, g, n3, g, w)
    # c = Verify1_2_2(sendValue3)
    # print(c)
    # h = 154521
    # g = 1454560
    # sendValue4 = Prove1_3(g, h, q)
    # d = Verify1_3(sendValue4)
    # print(d)
    #
    # n = 10
    # z = 1541212
    # c = 12412
    # R = 121045
    # pks = [random.randint(0, q) for x in range(n + 1)]
    # sendValue5 = Prove2_1(n, c, R, q, pks)
    # rs = Verify2_1(sendValue5)
    # print(rs)
    # sendValue6 = Prove2_2_1(g, w, q)
    # rs = Verify2_2_1(sendValue6)
    # print(rs)
    # q = 1454560154151321541521
    # g = 1454560
    # n = 10
    # h = 154521
    # w = 145
    # sendValue7 = Prove2_2_2(q, g, n, h, w)
    # rs = Verify2_2_2(sendValue7)
    # print(rs)
    # q = 1454560154151321541521
    # u = 154521
    # w = 145
    # sendValue8 = Prove4(q, u, w)
    # rs = Verify4(sendValue8)
    # print(rs)
    # sendValue9 = Prove5(2,5,512,160,q)
    # rs = Verify5(sendValue9)
    # print(rs)
    # sendValue10 = Prove3(10, 3,  12521, 12541, q)
    # rs = Verify3(sendValue10)
    # print(rs)
    # endtime = datetime.datetime.now()
    # print("时间：%s ms" % ((endtime - starttime).microseconds / 1000))  # 毫秒
