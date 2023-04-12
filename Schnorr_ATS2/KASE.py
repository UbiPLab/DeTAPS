import hashlib

from pypbc import *

from SgxParam import pairing


def Setup(qbits, rbits, nums):
    pubk = [0]
    # 产生一个G_1群的生成元
    n = nums
    g = Element.random(pairing, G1)
    a = Element.random(pairing, Zr)
    for i in range(1, 2 * n + 1):
        # g_i = g ** (a ** i)
        g_i = Element(pairing, G1, value=g ** (a ** i))
        pubk.append(g_i)
    return pairing, g, n, pubk


def Keygen(pairing, g):
    y = Element.random(pairing, Zr)
    # v = g ** y
    v = Element(pairing, G1, value=g ** y)
    pk = v
    msk = y
    keypair = [pk, msk]
    return keypair


def Encrypt(pk, i, N, pairing, g, n, pubk):
    g_1 = pubk[1]
    g_n = pubk[n]
    g_i = pubk[i]
    t = Element.random(pairing, Zr)
    c1 = g ** t
    c2 = (pk * g_i) ** t
    cw_list = []
    for w in N:
        hkp1 = hashlib.sha256(str(w).encode()).hexdigest()
        hash_G_1 = Element.from_hash(pairing, G1, hkp1)
        on = pairing.apply(g, hash_G_1) ** t
        down = pairing.apply(g_1, g_n) ** t
        cw = Element.__ifloordiv__(on, down)
        cw_list.append(cw)
    elements = (c1, c2, cw_list)
    return elements


def Extract(msk, S, pairing, n, pubk):
    kagg = Element.one(pairing, G1)
    for j in S:
        item = n + 1 - j
        element = pubk[item]
        mul = element ** msk
        kagg = kagg * mul
    return kagg


def Trapdoor(kagg, w, pairing):
    hkp1 = hashlib.sha256(str(w).encode()).hexdigest()
    hash_G_1 = Element.from_hash(pairing, G1, hkp1)
    Tr = kagg * hash_G_1
    return Tr


def Adjust(i, S, Tr, pairing, n, pubk):
    mul_all = Element.one(pairing, G1)
    for j in S:
        if j != i:
            item = n + 1 - j + i
            element = pubk[item]
            mul_all = mul_all * element
    Tr_i = Tr * mul_all
    return Tr_i


def Test(Tr_i, i, S, elements, pairing, n, pubk):
    c1 = elements[0]
    c2 = elements[1]
    cws = elements[2]
    pub = Element.one(pairing, G1)
    for j in S:
        item = n + 1 - j
        element = pubk[item]
        pub = pub * element
    on = pairing.apply(Tr_i, c1)
    down = pairing.apply(pub, c2)
    right = Element.__ifloordiv__(on, down)
    for cw in cws:
        if cw == right:
            return True
    return False


if __name__ == '__main__':
    qbits = 512
    rbits = 160
    # 签名组id集合
    G = [i for i in range(1, 10 + 1)]
    # 1.Setup():初始化
    pairing, g, n, pubk = Setup(qbits, rbits, len(G))
    print(pairing)
    # 2.DataOwner产生公私钥对
    keypair = Keygen(pairing, g)
    pk = keypair[0]
    msk = keypair[1]

    kagg = Extract(msk, G, pairing, n, pubk)
    N = [1, 2, 3, 4, 6]
    # 3.DataOwner根据其关键字和索引加密每个文档
    gid = 1
    encrypt = Encrypt(pk, gid, N, pairing, g, n, pubk)

    # 5.用户根据聚合密钥和关键字生成唯一的陷门
    for i in range(len(N)):
        pid = N[i]
        td_i = Trapdoor(kagg, pid, pairing)
        Tri = Adjust(gid, G, td_i, pairing, n, pubk)
        test = Test(Tri, gid, G, encrypt, pairing, n, pubk)
        print(test)
