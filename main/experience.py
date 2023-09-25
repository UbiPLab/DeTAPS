import base64
import datetime
import hashlib
import pickle
import random
import string
import time
from itertools import combinations
from random import getrandbits

import objsize
from pypbc import *
import SgxParam
# 这里需要引入web3.py中管理账户的模块
from web3 import Account
from eth_keys import keys


def ranstr(num):
    salt = ''.join(random.sample(string.ascii_letters + string.digits, num))
    return salt

def getN(plaintext, n3):
    l = plaintext.split(",")
    N = l[-1 * n3:]
    return [int(i) for i in N]
def getPairing1():
    pairing1 = SgxParam.pairing
    return pairing1
def getPairing2():
    pairing2 = SgxParam.pairing
    return pairing2

def generateM(k):
    m = ""
    length = 1024 * k
    for i in range(length):
        m += ''.join(random.sample(string.ascii_letters + string.digits, 1))
    return m

if __name__ == '__main__':
    m = "asd"
    m[0].is
    encrypt = generateM(1)
    print(encrypt)
    starttime = datetime.datetime.now()
    message_bytes2 = base64.b64encode(encrypt.encode('utf-8'))
    endtime = datetime.datetime.now()
    print("Time：%s s" % ((endtime - starttime).total_seconds() * 1000))  # 毫秒
    print("encrypt overhead:%s KB" % (objsize.get_deep_size(encrypt) / 1024))
    #
    # g = Element.random(pairing, G1)
    # print("g = ", str(g))
    # g2 = Element(pairing, G1, value = str(g))
    # assert g == g2
    #
    # r = Element.random(pairing, Zr)
    # print(type(r))
    # print(r)
    # r2 = Element(pairing, Zr, value = int(r))
    # print(type(r2))
    # print(r2)
    # assert r2 == r
    #
    #
    #
    # a, b = (2, 3)
    # print(a)
    # C_list = combinations(range(1, 20 + 1), 5)
    # C_list2 = combinations(range(1, 7 + 1), 5)
    # all_S_list = [list(x) for x in list(C_list)[:100]]
    # print(len(all_S_list))
    # print(all_S_list)
    # print(list(C_list))
    # print(list(C_list2))
    # for (i, item) in enumerate(C_list):
    #     print(i)
    #     print(list(item))
    #
    # for (i, item) in enumerate(C_list):
    #     print(i)
    #     print(list(item))
