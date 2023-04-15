import hashlib
import pickle
import random

from pypbc import *
import AESUtils
from SgxParam import pairing


def Setup(qbits, rbits):
    # G1生成元g
    g = Element.random(pairing, G1)
    # G2生成元h
    h = Element.random(pairing, G2)
    y = Element.random(pairing, Zr)
    a = Element.random(pairing, Zr)
    while y == Element.zero(pairing, Zr):
        y = Element.random(pairing, Zr)
    while a == Element.zero(pairing, Zr):
        a = Element.random(pairing, Zr)
    # 下标从1到m-1
    D = [0]
    m = 10
    for i in range(1, m):
        d_i = Element.random(pairing, Zr)
        D.append(d_i)
    # 所有可以加密人的公钥
    dummy_users = []

    for i in range(m - 1):
        dummy_users.append(D[i + 1])
    mk = (g, y, a)
    ay = a * y
    u = g ** ay
    egh = pairing.apply(g, h)
    v = egh ** a
    h_a = h ** a
    h_a_y_all = [0]
    for i in range(1, 2 * m):
        y_i = y ** i
        ay_i = a * y_i
        element = h ** ay_i
        h_a_y_all.append(element)
    ek = (m, u, v, h_a, h_a_y_all, D)
    h_y_all = [0]
    for i in range(1, m - 1):
        y_i = y ** i
        element = h ** y_i
        h_y_all.append(element)
    ck = (m, h, h_y_all, D)
    return pairing, g, h, y, a, m, dummy_users, mk, ek, ck, D


def Join(MK, identity, pairing, D):
    g = MK[0]
    y = MK[1]
    x = Element.random(pairing, Zr)
    while x == Element.zero(pairing, Zr) or x in D:
        x = Element.random(pairing, Zr)
    upk = x
    one = Element.one(pairing, Zr)
    y_add_x = y + x
    one_div_y_add_x = Element.__ifloordiv__(one, y_add_x)
    usk = g ** one_div_y_add_x
    keypair = (upk, usk)
    return keypair


def Encrypy(ek, S, dummy_users, t, m, pairing, y, h, a):
    k = Element.random(pairing, Zr)
    while k == Element.zero(pairing, Zr):
        k = Element.random(pairing, Zr)
    u = ek[1]
    v = ek[2]

    C1 = (u ** (k * -1))

    Mul_all = Element.one(pairing, Zr)
    for element in S:
        add = element + y
        Mul_all = Mul_all * add
    Mul_all_2 = Element.one(pairing, Zr)
    for element in dummy_users:
        add = element + y
        Mul_all_2 = Mul_all_2 * add
    C2 = h ** (k * a * Mul_all * Mul_all_2)
    K = v ** k

    content = m
    key = hashlib.md5(str(K).encode()).hexdigest()
    global ciphertext
    ciphertext = AESUtils.aesEncrypt(key, content)
    Hdr = (C1, C2)
    fullHeader = (S, t, Hdr, K, ciphertext, k)
    return fullHeader


def Validate(ek, fullHeader, dummy_users, k, pairing, y, h, a):
    u = ek[1]
    C1 = fullHeader[2][0]
    C2 = fullHeader[2][1]
    t = fullHeader[1]

    S = fullHeader[0]
    Mul_all = Element.one(pairing, Zr)
    for element in S:
        add = element + y
        Mul_all = Mul_all * add

    Mul_all_2 = Element.one(pairing, Zr)
    for element in dummy_users:
        add = element + y
        Mul_all_2 = Mul_all_2 * add
    C2_2 = h ** (a * Mul_all * Mul_all_2)
    flag1 = False

    if C1 == (u ** (k * -1)) and C2 == C2_2 ** k:
        flag1 = True
    flag2 = False

    if len(S) >= t:
        flag2 = True
    left = pairing.apply(C1, C2_2)
    right = pairing.apply(C1, C2_2)
    flag3 = False
    if left == right:
        flag3 = True
    return flag1 and flag2 and flag3


def ShareDecrypt(id, usk, Hdr, pairing):
    C2 = Hdr[1]
    sign = pairing.apply(usk, C2)
    return sign


def Combine(S, k, dummy_users, t, Hdr, sign_list, cipherBytes, pairing, y, h, a, g):
    C_T_S = Element.one(pairing, Zr)
    one = Element.one(pairing, Zr)
    C1 = Hdr[0]
    for x in dummy_users:
        C_T_S = C_T_S * x
    Mul_all_2 = Element.one(pairing, Zr)
    for x in dummy_users:
        add = x + y
        Mul_all_2 = Mul_all_2 * add
    P_T_S_Y = Element.__ifloordiv__(one, y) * (Mul_all_2 - C_T_S)
    Mul_all = Element.one(pairing, Zr)
    for x in dummy_users:
        add = x + y
        Mul_all = Mul_all * add
    mul = k * a * Mul_all
    Aggregate = pairing.apply(g, h) ** mul
    value1 = pairing.apply(C1, h ** P_T_S_Y)
    value2 = value1 * Aggregate
    K = value2 ** (Element.__ifloordiv__(one, C_T_S))
    key = hashlib.md5(str(K).encode()).hexdigest()
    plainBytes = AESUtils.aesDecrypt(key, cipherBytes)
    return plainBytes


def ShareVerify(Hdr, upk, usk, pairing, y, h, a, g):
    C1 = Hdr[0]
    C2 = Hdr[1]
    r = random.randint(1, 100)
    sign = pairing.apply(usk, C2)
    usk_2 = usk ** r
    left1 = pairing.apply(usk_2, (h ** (a * y)) * (h ** (a * upk)))
    egh = pairing.apply(g, h)
    v = egh ** a
    right1 = v ** r
    left2 = pairing.apply(usk_2, C2)
    right2 = sign ** r
    return left1 == right1 and left2 == right2


def ShareAllDecrypts(S, sk_list, fullHeader, pairing):
    sign_list = []
    for i in range(len(S)):
        sign = ShareDecrypt(i, sk_list[i], fullHeader[2], pairing)
        sign_list.append(sign)
    return sign_list


def getMulandMul2(S, pairing, y, dummy_users):
    Mul_all = Element.one(pairing, Zr)
    for element in S:
        add = element + y
        Mul_all = Mul_all * add
    Mul_all_2 = Element.one(pairing, Zr)
    for element in dummy_users:
        add = element + y
        Mul_all_2 = Mul_all_2 * add
    return Mul_all, Mul_all_2


if __name__ == '__main__':
    S = []
    sk_list = []
    user_keys = []
    pairing, g, h, y, a, m, dummy_users, mk, ek, ck, D = Setup(512, 160)

    for i in range(4):
        user_key = Join(mk, i, pairing, D)
        S.append(user_key[0])
        sk_list.append(user_key[1])
        user_keys.append(user_key)
    # fullHeader = (S, t, Hdr, K)
    fullHeader = Encrypy(ek, S, dummy_users, 4, "asd", pairing, y, h, a)
    k = fullHeader[-1]
    validate = Validate(ek, fullHeader, dummy_users, k, pairing, y, h, a)

    f = ShareVerify(fullHeader[2], user_keys[0][0], user_keys[0][1], pairing, y, h, a, g)
    print(f)
    sign_list = ShareAllDecrypts(S, sk_list, fullHeader, pairing)
    ciphertext = fullHeader[-2]
    combine = Combine(S, k, dummy_users, fullHeader[1], fullHeader[2], sign_list, ciphertext, pairing, y, h, a, g)
    print(combine)
