import datetime
import hashlib
import random
from itertools import combinations
from random import getrandbits

import objsize

import SchnorrATS
from PKE_pg import ELGamal
import KASE
import DTPKE
import Sig
import SgxParam
import BlockChain
from Zero_Knowledge_pg import ZeroKnowledgeProof
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
    G = [i for i in range(1, signatures_num + 1)]
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
    # 产生n2个Tracing私钥,下标从1
    print("Generating n2 Tracing' keys")
    for j in range(1, n2 + 1):
        sk_e = encrypt_sks[j]
        ck = D_param[9]
        pk_list = S_param[0]
        tracingKey = [sk_e, ck, pk_list]
        tracingKeys.append(tracingKey)
    # hkp1 = hashlib.sha256((str(0) + str(datetime.datetime)).encode()).hexdigest()
    gid_list = G
    PK = [ka, com_pk, D_param[8], D_dk, D_vk, sign_pks, encrypt_pks, K_param[3], mpk_msk[0], gid_list]
    return PK, S_param, D_param, K_param


def Sign(m, gid_list, all_S_list, all_N_list, pk_list, pk_e, sk_list, S_param):
    """
    :param m: message
    :param gid_list: all_group_id
    :param all_S_list:
    :param all_N_list:
    :param pk_list: SchnorrATS pk_list
    :param pk_e: Elgamal pk
    :param sk_list: SchnorrATS sk_list
    :param S_param: SchnorrATS param
    :return: enrcypted signatures
    """
    all_encrypts_list = []
    S_p, S_q, S_g = S_param[2], S_param[3], S_param[4]
    for i in range(len(all_S_list)):
        gid = gid_list[i]
        N = all_N_list[i]
        signs = SchnorrATS.Sign(m, all_S_list[i], pk_list, sk_list, S_p, S_q, S_g)
        encrypts = []
        for i in range(len(signs)):
            plaintext = m + "," + str(signs[i][0]) + "," + str(signs[i][1]) + "," + str(gid) + "," + ",".join(
                map(str, N))
            # print(plaintext)
            encrypt = ELGamal.encrypt(plaintext, ELGamal.p, pk_e, ELGamal.r)
            encrypts.append(encrypt)
        all_encrypts_list.append(encrypts)
    return all_encrypts_list



def Combine1(sk_c, all_N_PK, all_S_list, all_encrypts_list, PK, D_dummy_users, D_pairing, D_y, D_h, D_a, K_pairing, K_g,
             K_n, K_pubk):
    '''
    :param sk_c: Combining key
    :param all_N_PK:
    :param all_S_list:
    :param all_encrypts_list:
    :param PK:
    :param D_dummy_users:
    :param D_pairing:
    :param D_y:
    :param D_h:
    :param D_a:
    :param K_pairing:
    :param K_g:
    :param K_n:
    :param K_pubk:
    :return: all_DTPKE_encrypt, all_KASE_encrypt, all_ZKPK
    '''
    n3 = len(all_N_PK[0])
    all_N_list = []
    all_signatures_list = []
    for i in range(len(all_S_list)):
        encrypts = all_encrypts_list[i]
        signatures_list = []
        for encrypt in encrypts:
            C2 = encrypt[0]
            C1 = encrypt[1]
            plaintext = ELGamal.decrypt(C2, C1, sk_c[1], ELGamal.p)
            strings = plaintext.split(",")
            N = getN(plaintext, n3)
            if N not in all_N_list:
                all_N_list.append(N)
            sign = [int(strings[1]), int(strings[2])]
            signatures_list.append(sign)
        all_signatures_list.append(signatures_list)
    # 聚合后的签名
    all_siggnature = []
    all_DTPKE_encrypt = []
    all_KASE_encrypt = []
    all_sendAll = []
    for i in range(len(all_S_list)):
        S = all_S_list[i]
        N_PK = all_N_PK[i]
        N = all_N_list[i]
        signatures_list = all_signatures_list[i]
        signature = SchnorrATS.Combine(S, signatures_list)
        all_siggnature.append(signature)
        # DTPKE加密
        DTPKE_encrypt = DTPKE.Encrypy(sk_c[3], N_PK, D_dummy_users, n3, str(signature), D_pairing, D_y, D_h, D_a)
        all_DTPKE_encrypt.append(DTPKE_encrypt)
        # KASE加密
        mpk = PK[-2]
        gid = gid_list[i]
        KASE_encrypt = KASE.Encrypt(mpk, gid, N, K_pairing, K_g, K_n, K_pubk)
        all_KASE_encrypt.append(KASE_encrypt)
        sendAll = ZeroKnowledgeProof.GenerateProofs()
        all_sendAll.append(sendAll)
    return [all_DTPKE_encrypt, all_KASE_encrypt, all_sendAll]


def Combine2(sk_s, m, all_DTPKE_encrypt, all_KASE_encrypt, all_sendAll):
    '''
    :param sk_s: Sig sk
    :param m:  message
    :param all_DTPKE_encrypt:
    :param all_KASE_encrypt:
    :param all_sendAll:
    :return: yita
    '''
    all_yita = []
    for i in range(len(all_DTPKE_encrypt)):
        yita = BlockChain.Sign(sk_s, m, all_DTPKE_encrypt[i], all_KASE_encrypt[i], all_sendAll[i])
        print("yita overhead:%s KB" % (objsize.get_deep_size(yita) / 1024))
        all_yita.append(yita)
    return all_DTPKE_encrypt, all_KASE_encrypt, all_sendAll, all_yita


def Verify(pk, m, all_DTPKE_encrypt, all_KASE_encrypt, all_sendAll, all_yita):
    '''
    :param pk: Sig pk
    :param m:
    :param all_DTPKE_encrypt:
    :param all_KASE_encrypt:
    :param all_sendAll:
    :param all_yita:
    :return: verify result
    '''
    for i in range(len(all_DTPKE_encrypt)):
        DTPKE_encrypt = all_DTPKE_encrypt[i]
        KASE_encrypt = all_KASE_encrypt[i]
        sendAll = all_sendAll[i]
        yita = all_yita[i]
        f1 = BlockChain.Verify(pk, m, DTPKE_encrypt, KASE_encrypt, sendAll, yita)
        f2 = ZeroKnowledgeProof.VerifyProofs(sendAll)
        if not (f1 and f2):
            return False

    return True

# Tracing without SGX
def Trace1(pk_e, all_N_list, all_N_PK_list, all_sk_list, pk, m, all_DTPKE_encrypt, all_KASE_encrypt, all_sendAll,
           all_yita, D_pairing, K_pairing, K_n, K_pubk, ka, G, gid_list):
    get_gid = []
    for i in range(len(all_N_list)):
        N = all_N_list[i]
        KASE_encrypt = all_KASE_encrypt[i]
        gid = gid_list[i]
        for i in range(len(N)):
            pid = N[i]
            td_i = KASE.Trapdoor(ka, pid, K_pairing)
            # print("Trapdoor overhead:%s KB" % (objsize.get_deep_size(td_i) / 1024))
            Tri = KASE.Adjust(gid, G, td_i, K_pairing, K_n, K_pubk)
            for gid in gid_list:
                test = KASE.Test(Tri, gid, G, KASE_encrypt, K_pairing, K_n, K_pubk)
                if test:
                    get_gid.append(gid)
    f1 = Sig.Verify(pk, m, all_DTPKE_encrypt, all_KASE_encrypt, all_sendAll, all_yita)
    if not f1:
        return False
    all_sign_list = []
    all_ELGamal_encrypt = []
    for i in range(len(all_N_list)):
        N = all_N_list[i]
        N_PK = all_N_PK_list[i]
        sk_list = all_sk_list[i]
        DTPKE_encrypt = all_DTPKE_encrypt[i]
        sign_list = DTPKE.ShareAllDecrypts(N_PK, sk_list, DTPKE_encrypt, D_pairing)
        plaintext = ",".join(map(str, N))
        ELGamal_encrypt = ELGamal.encrypt(plaintext, ELGamal.p, pk_e, ELGamal.r)
        all_sign_list.append(sign_list)
        all_ELGamal_encrypt.append(ELGamal_encrypt)
    return all_ELGamal_encrypt, all_sign_list


# Tracing in SGX
def Trace2(sk_t, t, n, m, sign_list, ELGamal_encrypt, DTPKE_encrypt, user_keys, D_ek, D_dummy_users, D_k, D_pairing,
           D_y, D_h, D_a, D_g, S_p, S_q, S_g):
    C2 = ELGamal_encrypt[0]
    C1 = ELGamal_encrypt[1]
    plaintext = ELGamal.decrypt(C2, C1, sk_t[0], ELGamal.p)
    N_list = plaintext.split(",")
    N = [int(i) for i in N_list]
    validate = DTPKE.Validate(D_ek, DTPKE_encrypt, D_dummy_users, D_k, D_pairing, D_y, D_h, D_a)
    if not validate:
        return False
    for item in user_keys:
        shareVerify = DTPKE.ShareVerify(DTPKE_encrypt[2], item[0], item[1], D_pairing, D_y, D_h, D_a, D_g)
        if not shareVerify:
            return False
    combine = DTPKE.Combine(N, D_k, D_dummy_users, DTPKE_encrypt[1], DTPKE_encrypt[2], sign_list, DTPKE_encrypt[-2],
                            D_pairing, D_y, D_h, D_a, D_g)
    signature = eval(combine)
    res = SchnorrATS.Trace(sk_t[2], t, n, m, signature[0], signature[1], S_p, S_q, S_g)
    return res


def generateM(k):
    m = ""
    length = 1024 * k
    for i in range(length):
        m += str(1)
    return m


def getN(plaintext, n3):
    l = plaintext.split(",")
    N = l[-1 * n3:]
    return [int(i) for i in N]

# Generate N's pk, sk
def generateN(all_N_list, n3, D_param):
    all_N_PK_list = []
    all_sk_list = []
    all_user_keys = []
    for i in range(len(all_N_list)):
        N_PK = []
        # 存储公证人N的解密私钥
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


if __name__ == '__main__':
    qBit = 512
    rBit = 160
    n = 10
    n1 = 5
    n2 = 5
    t = 5
    t2 = 3
    m = generateM(10)
    # group nums
    signatures_num = 10
    org_S = list(combinations(range(1, n + 1), t))[:signatures_num]
    org_N = list(combinations(range(1, n + 1), t2))[:signatures_num]
    random.shuffle(org_S)
    random.shuffle(org_N)
    all_S_list = [list(x) for x in org_S]
    all_N_list = [list(x) for x in org_N]
    n3 = len(all_N_list[0])
    print("Start SetUp")
    PK, S_param, D_param, K_param = Setup(qBit, rBit, t, n, n1, n2, n)
    gid_list = PK[-1]
    all_N_PK_list, all_sk_list, all_user_keys = generateN(all_N_list, n3, D_param)

    print("Start Sign")
    starttime = datetime.datetime.now()
    all_encrypts_list = Sign(m, gid_list, all_S_list, all_N_list, S_param[0], encrypt_pks[1], S_param[1], S_param)
    endtime = datetime.datetime.now()
    print("Sign Time：%s s" % ((endtime - starttime).total_seconds()))  # 毫秒

    print("Combine")
    starttime = datetime.datetime.now()
    D_dummy_users, D_pairing, D_y, D_h, D_a = D_param[6], D_param[0], D_param[3], D_param[2], D_param[4]
    K_pairing, K_g, K_n, K_pubk = K_param
    all = Combine1(combiningKeys[1], all_N_PK_list, all_S_list, all_encrypts_list, PK, D_dummy_users, D_pairing,
                   D_y, D_h, D_a, D_pairing, K_g, K_n, K_pubk)
    all_DTPKE_encrypt, all_KASE_encrypt, all_sendAll = all[0], all[1], all[2]
    endtime = datetime.datetime.now()
    print("Combine1(SGX)：%s s" % ((endtime - starttime).total_seconds()))  # 毫秒

    starttime = datetime.datetime.now()
    sign_pks, sign_sks = BlockChain.KeyGen(1)
    all_DTPKE_encrypt, all_KASE_encrypt, all_sendAll, all_yita = Combine2(sign_sks[1], m, all_DTPKE_encrypt,
                                                                          all_KASE_encrypt, all_sendAll)
    endtime = datetime.datetime.now()
    print("Combine1(NoSGX)：%s s" % ((endtime - starttime).total_seconds()))  # 毫秒
    print("combine overhead:%s KB" % (objsize.get_deep_size(all_DTPKE_encrypt + all_KASE_encrypt + all_sendAll) / 1024))

    print("Verify")
    starttime = datetime.datetime.now()
    rs = Verify(sign_pks[1], m, all_DTPKE_encrypt, all_KASE_encrypt, all_sendAll, all_yita)
    print(rs)
    endtime = datetime.datetime.now()
    print("Verify Time：%s s" % ((endtime - starttime).total_seconds()))  # 毫秒

    print("Trace")
    starttime = datetime.datetime.now()
    D_pairing = D_param[0]
    K_pairing, K_n, K_pubk = K_param[0], K_param[2], K_param[3]
    ka = PK[0]
    G = [i for i in range(1, signatures_num + 1)]
    gid = PK[-1]
    #
    all_ELGamal_encrypt, all_sign_list = Trace1(encrypt_pks[1], all_N_list, all_N_PK_list, all_sk_list, sign_pks[1], m,
                                                all_DTPKE_encrypt, all_KASE_encrypt, all_sendAll, all_yita,
                                                D_pairing, D_pairing, K_n, K_pubk, ka, G, gid)
    all_S = []
    for i in range(len(all_DTPKE_encrypt)):
        DTPKE_encrypt = all_DTPKE_encrypt[i]
        sign_list = all_sign_list[i]
        ELGamal_encrypt = all_ELGamal_encrypt[i]
        user_keys = all_user_keys[i]
        D_ek, D_dummy_users, D_k, D_g = D_param[8], D_param[6], DTPKE_encrypt[-1], D_param[1]
        S_p, S_q, S_g = S_param[2], S_param[3], S_param[4]
        S = Trace2(tracingKeys[1], t, n, m, sign_list, ELGamal_encrypt, DTPKE_encrypt, user_keys, D_ek, D_dummy_users,
                   D_k,
                   SgxParam.pairing, D_y, D_h, D_a, D_g, S_p, S_q, S_g)
        all_S.append(S)
    print(all_S)
    endtime = datetime.datetime.now()
    print("Trace Time：%s s" % ((endtime - starttime).total_seconds()))  # ms
