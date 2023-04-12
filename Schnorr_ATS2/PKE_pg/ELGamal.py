import random
import sys
from math import pow
import datetime

import objsize

# a = random.randint(2, 10) # 产生小于p的随机常数a
p = 135410250898599446603827879283006844712836537334634139477281182264755944407199483483840386951271773793849590628522802188686253163300149799072592452561040845064640735897996146993818262957280771832549537283485414761962881680478691820243  # 获得大素数q
r = 51320500147494313260576095305465705911698834495652597778015393849527989926920389745664579119862278771332478438737761963842544930018850697910422620520061233174428083990798624946760731485453661794134278764910219603843473293195096572021 # 得r


def gcd(a, b):
    if a < b:
        return gcd(b, a)
    elif a % b == 0:
        return b;
    else:
        return gcd(b, a % b)

    # Generating large random numbers


def gen_key():
    key = random.randint(pow(10, 20), p)
    while gcd(p, key) != 1:
        key = random.randint(pow(10, 20), p)
    h = power(r, key, p)
    return key, h


# Modular exponentiation
def power(a, b, c):
    x = 1
    y = a
    while b > 0:
        if b % 2 == 0:
            x = (x * y) % c;
        y = (y * y) % c
        b = int(b / 2)

    return x % c


# Asymmetric encryption
def encrypt(msg, p, h, r):
    en_msg = []
    b = gen_key()[0]  # 得b
    K = power(h, b, p) # K=(Sa)^b mod p
    C1 = power(r, b, p)  #  C1=Sb=r^b mod p

    for i in range(0, len(msg)):
        en_msg.append(msg[i])

    # print("(Sa)^b mod p used : ", K)
    for i in range(0, len(en_msg)):
        en_msg[i] = K * ord(en_msg[i])
    return en_msg, C1


def decrypt(C2, C1, a, p):
    dr_msg = []
    h = power(C1, a, p)
    for i in range(0, len(C2)):
        dr_msg.append(chr(int(C2[i] / h)))

    return ''.join(dr_msg)


# Driver code
def main():
    msg = ""
    for i in range(1024):
        msg += str(1)
    # msg = '01010asdasd'               # 共125位数字，1000bit
    a, h = gen_key()  # Private key for receiver
    C2, C1 = encrypt(msg, p, h, r)
    dmsg = decrypt(C2, C1, a, p)
    print("解密后文 :", dmsg)
    print("encrypt overhead:%s KB" % (sys.getsizeof(C2) / 1024))


if __name__ == '__main__':
    main()
