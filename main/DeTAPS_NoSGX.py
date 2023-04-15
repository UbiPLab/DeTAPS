import datetime
import random
from itertools import combinations
from random import getrandbits
import SchnorrATS
from PKE_pg import ELGamal
import KASE
import DTPKE
import Sig
from tools import Commit

encrypt_pks = [0]
encrypt_sks = [0]
combiningKeys = [[]]
tracingKeys = [[]]


def Setup(qBit, rBit, t, n, n1, n2, n3):
    print("Generating SchnorrATS keyPairs")
    S_param = SchnorrATS.KeyGen(n, t)
    print("Commitment pk")
    r_pk = getrandbits(rBit)
    com_pk = Commit.commit(S_param[0], r_pk)
    print("DTPKE Setup starts")
    D_param = DTPKE.Setup(qBit, rBit)
    D_dk, D_vk = (), ()
    print("Generating n1 Combiners' signing keys")
    sign_pks, sign_sks = Sig.KeyGen(n1)
    print("Generating n1 PKE' encryption keys")
    for i in range(1, n1 + 1):
        keypair = ELGamal.gen_key()
        encrypt_sks.append(keypair[0])
        encrypt_pks.append(keypair[1])
    print("Join n3 notaries into DTPKE")
    join_keys = [0]
    for i in range(1, n3 + 1):
        keypair = DTPKE.Join(D_param[7], i, D_param[0], D_param[-1])
        join_keys.append(keypair)
    print("KASE setup starts")
    G = [i for i in range(1, signatures_nums + 1)]
    K_param = KASE.Setup(qBit, rBit, len(G))
    print("Generating KASE keypair")
    mpk_msk = KASE.Keygen(K_param[0], K_param[1])
    ka = KASE.Extract(mpk_msk[1], G, K_param[0], K_param[2], K_param[3])

    print("Generating n1 Combining' keys")

    for i in range(1, n1 + 1):
        pk_list = S_param[0]
        sk_e = encrypt_sks[i]
        ek = D_param[8]
        sk_c = [pk_list, sk_e, t, ek, r_pk]
        combiningKeys.append(sk_c)
    print("Generating n2 Tracing' keys")

    for j in range(1, n2 + 1):
        sk_e = encrypt_sks[j]
        ck = D_param[9]
        pk_list = S_param[0]
        tracingKey = [sk_e, ck, pk_list]
        tracingKeys.append(tracingKey)
    gid_list = G
    PK = [ka, com_pk, D_param[8], D_dk, D_vk, sign_pks, encrypt_pks, K_param[3], mpk_msk[0], gid_list]
    return PK, S_param, D_param, K_param


def Sign(m, gid_list, all_S_list, all_N_list, pk_list, pk_e, sk_list, S_param):
    all_encrypts_list = []
    for i in range(len(all_S_list)):
        gid = gid_list[i]
        S = all_S_list[i]
        N = all_N_list[i]
        S_p, S_q, S_g = S_param[2], S_param[3], S_param[4]
        signs = SchnorrATS.Sign(m, S, pk_list, sk_list, S_p, S_q, S_g)
        encrypts = []
        for i in range(len(signs)):
            sign = signs[i]
            plaintext = m + "," + str(sign[0]) + "," + str(sign[1]) + "," + str(gid) + "," + ",".join(map(str, N))
            encrypt = ELGamal.encrypt(plaintext, ELGamal.p, pk_e, ELGamal.r)
            encrypts.append(encrypt)
            # print("encrypt overhead:%s MB" % (objsize.get_deep_size(encrypt) / 1024 / 1024))
        all_encrypts_list.append(encrypts)
    return all_encrypts_list


def getN(plaintext, n3):
    l = plaintext.split(",")
    N = l[-1 * n3:]
    return [int(i) for i in N]


def generateM(k):
    m = ""
    length = 1024 * k
    for i in range(length):
        m += str(1)
    return m


def generateN(all_N_list, n3, D_param):
    all_N_PK_list = []
    all_sk_list = []
    all_user_keys = []
    for N in all_N_list:
        N_PK = []
        sk_list = []
        user_keys = []
        for i in range(n3):
            user_key = DTPKE.Join(D_param[7], i, D_param[0], D_param[-1])
            N_PK.append(user_key[0])
            sk_list.append(user_key[1])
            user_keys.append(user_key)
        all_N_PK_list.append(N_PK)
        all_sk_list.append(sk_list)
        all_user_keys.append(user_keys)
    return all_N_PK_list, all_sk_list, all_user_keys


qBit = 512
rBit = 160
n = 10
# m length 2-16
m = generateM(10)
t = 5
t2 = 5
signatures_nums = 1
org_S = list(combinations(range(1, n + 1), t))
org_N = list(combinations(range(1, n + 1), t2))
random.shuffle(org_S)
random.shuffle(org_N)
org_S = org_S[:signatures_nums]
org_N = org_N[:signatures_nums]
n1 = 5
n2 = 5
all_S_list = [list(x) for x in org_S]
all_N_list = [list(x) for x in org_N]
# n3 == t'
n3 = len(all_N_list[0])

print("Start SetUp")
starttime = datetime.datetime.now()
PK, S_param, D_param, K_param = Setup(qBit, rBit, t, n, n1, n2, n)
all_N_PK_list, all_sk_list, all_user_keys = generateN(all_N_list, n3, D_param)
endtime = datetime.datetime.now()
print("SetUpTime：%s ms" % ((endtime - starttime).total_seconds() * 1000))

print("Start Signing")
starttime = datetime.datetime.now()
all_encrypts_list = Sign(m, PK[-1], all_S_list, all_N_list, S_param[0], encrypt_pks[1], S_param[1], S_param)
endtime = datetime.datetime.now()
print("Sign Time：%s ms" % ((endtime - starttime).total_seconds() * 1000))
print("Combine Param")
D_dummy_users, D_pairing, D_y, D_h, D_a = D_param[6], D_param[0], D_param[3], D_param[2], D_param[4]
K_pairing, K_g, K_n, K_pubk = K_param
SGX1_param = (
combiningKeys, all_N_PK_list, all_N_list, all_S_list, all_encrypts_list, PK, D_dummy_users, D_pairing, D_y, D_h, D_a,
K_pairing, K_g, K_n, K_pubk)
NoSGX2_param = (m, D_param, K_param, PK, S_param, all_N_list, all_N_PK_list, all_sk_list, encrypt_pks, signatures_nums)
SGX2_param = (tracingKeys, t, n, m, all_user_keys, D_param, K_param, S_param, encrypt_pks)
