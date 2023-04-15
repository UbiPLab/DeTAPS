import hashlib
import random
from itertools import combinations
import datetime
# q = 264926624393126082647786234614522411169
# p = 34970314419892642909507782969116958274309
# g = 27464808337291794528868661597410061338052
# # q bit长度
# blq = 128
# sk_list = []
# pk_list = []


def KeyGen(n, t):
    sk_list = []
    pk_list = []
    pk_list.append(t)
    sk_list.append(0)
    q = 264926624393126082647786234614522411169
    p = 34970314419892642909507782969116958274309
    g = 27464808337291794528868661597410061338052
    for i in range(1, n + 1):
        sk = random.randint(1, q)
        pk = pow(g, sk, p)
        sk_list.append(sk)
        pk_list.append(pk)
    return pk_list, sk_list, p ,q, g

def Sign(m, C, pk_list, sk_list,p ,q, g):
    signatures_list = []
    R = 1
    r_map = {}
    R_map = {}
    for item in C:
        r_item = random.randint(1, q)
        r_map[item] = r_item
        R_item = pow(g, r_item, p)
        R_map[item] = R_item
        R = R * R_item

    for item in C:
        sk = sk_list[item]
        r = r_map[item]
        R2 = R_map[item]
        hkp1 = hashlib.sha256((str(pk_list) + str(R) + m).encode()).hexdigest()
        c = int(hkp1, 16) % q
        z = (r + c * sk) % q
        bigIntegers = [R2, z]
        signatures_list.append(bigIntegers)

    return signatures_list


def Combine(C, signatures_list):
    Z = 0
    R = 1
    for item in signatures_list:
        r = item[0]
        z = item[1]
        R = R * r
        Z = Z + z
    return R, Z, C


def Verify(t, pk_list, m, R, Z, C,p ,q, g):
    pk_C = 1
    for i in C:
        pk = pk_list[i]
        pk_C = pk_C * pk
    hkp1 = hashlib.sha256((str(pk_list) + str(R) + m).encode()).hexdigest()
    c = int(hkp1, 16) % q

    if len(C) == t and pow(g, Z, p) == (pow(pk_C, c, p) * R) % p:
        return True
    else:
        return False


def Trace(pk_list, t, n, m, R, Z,p ,q, g):
    C_list = combinations(range(1, n + 1), t)
    for (i,item) in enumerate(C_list):
        flag = Verify(t, pk_list, m, R, Z, list(item),p ,q, g)
        if flag:
            return list(item)
    return []


if __name__ == '__main__':
    m = ""
    for i in range(102400):
        m += str(1)
    n = 13
    # C = [3, 4, 6, 8, 10]
    C_list =  [[3, 4, 6, 8, 10],[3, 4, 6, 8, 10]]
    t = len(C_list[0])
    # 1.KeyGen(): 所有签名者产生公钥私钥
    pk_list, sk_list, p ,q, g = KeyGen(n, t)
    # 2.Sign():签名团依次对消息进行签名
    for C in C_list:
        signatures_list = Sign(m, C, pk_list, sk_list,p ,q, g)
        # 3.Combine()聚合签名团签名
        signature = Combine(C, signatures_list)
        # 4.验证签名团消息合法性
        res0 = Verify(t, pk_list, m, signature[0], signature[1], C,p ,q, g)
        print(res0)
        # 5.Trace()恢复签名团id
        starttime = datetime.datetime.now()
        res = Trace(pk_list, t, n, m, signature[0], signature[1],p ,q, g)
        endtime = datetime.datetime.now()
        print("一次所用时间：%s ms" % ((endtime - starttime).microseconds / 1000))  # 毫秒
        print(res)
