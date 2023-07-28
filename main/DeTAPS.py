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
knowLedge = []


def Setup(qBit, rBit, t, n, n1, n2, n3):
    # ATS产生公私钥
    print("Generating SchnorrATS keyPairs")
    # S_pk_list, S_sk_list, S_p ,S_q, S_g = SchnorrATS.KeyGen(n, t)
    S_param = SchnorrATS.KeyGen(n, t)
    knowLedge.append(S_param[0])
    knowLedge.append(S_param[3])

    # 承诺
    print("Commitment pk")
    r_pk = getrandbits(rBit)
    com_pk = Commit.commit(S_param[0], r_pk)
    # DTPKE初始化
    print("DTPKE Setup starts")
    # D_pairing, D_g, D_h, D_y, D_a, D_m, D_dummy_users, D_mk, D_ek, D_ck,D_D = DTPKE.Setup(qBit, rBit)
    D_param = DTPKE.Setup(qBit, rBit)
    D_dk, D_vk = (), ()
    # 产生n1个以太坊签名的公私钥对 Combiner Ci's signing keys
    print("Generating n1 Combiners' signing keys")
    sign_pks, sign_sks = Sig.KeyGen(n1)

    # 产生n1个PKE加密的公私钥
    print("Generating n1 PKE' encryption keys")
    for i in range(1, n1 + 1):
        keypair = ELGamal.gen_key()
        encrypt_sks.append(keypair[0])
        encrypt_pks.append(keypair[1])
    # 将n3个公证人全部加入DTPKE中
    print("Join n3 notaries into DTPKE")
    join_keys = [0]
    for i in range(1, n3 + 1):
        keypair = DTPKE.Join(D_param[7], i, D_param[0], D_param[-1])
        join_keys.append(keypair)
    # KASE初始化
    print("KASE setup starts")
    G = [i for i in range(1, signatures_num + 1)]
    # K_pairing, K_g, K_n, K_pubk = KASE.Setup(qBit, rBit, len(G))
    K_param = KASE.Setup(qBit, rBit, len(G))
    # KASE产生一对公私钥
    print("Generating KASE keypair")
    mpk_msk = KASE.Keygen(K_param[0], K_param[1])
    # 这里
    # global ka
    ka = KASE.Extract(mpk_msk[1], G, K_param[0], K_param[2], K_param[3])

    # 产生n1个Combining私钥，下标从1
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
    hkp1 = hashlib.sha256((str(0) + str(datetime.datetime)).encode()).hexdigest()
    gid_list = G

    PK = [ka, com_pk, D_param[8], D_dk, D_vk, sign_pks, encrypt_pks, K_param[3], mpk_msk[0], gid_list]
    return PK, S_param, D_param, K_param


"""
:param m: 消息    
:param gid: 授权签名团队标识符
:param S: 授权签名团队
:param N: 授权公证人团队
:param pk_list: SchnorrATS签名用到的公钥集合
:param pk_e: PKE加密所需的公钥
:param sk_list: SchnorrATS签名用到的私钥集合
"""


def Sign(m, gid_list, all_S_list, all_N_list, pk_list, pk_e, sk_list, S_param):
    all_encrypts_list = []
    S_p, S_q, S_g = S_param[2], S_param[3], S_param[4]
    for i in range(len(all_S_list)):
        gid = gid_list[i]
        N = all_N_list[i]
        signs = SchnorrATS.Sign(m, all_S_list[i], pk_list, sk_list, S_p, S_q, S_g)
        encrypts = []
        for i in range(len(signs)):
            plaintext = m + "," + str(signs[i][0]) + "," + str(signs[i][1]) + "," + str(gid) + "," + ",".join(map(str, N))
            # print(plaintext)
            encrypt = ELGamal.encrypt(plaintext, ELGamal.p, pk_e, ELGamal.r)
            encrypts.append(encrypt)
        all_encrypts_list.append(encrypts)
    return all_encrypts_list


"""
:param sk_c: CombiningKey
:param N_pk: 存储公证人N的加密公钥
:param S: 授权签名人集合
:param encrypts: PKE加密后的密文集合
"""


# Combiner先解密后聚合这些签名。
def Combine1(sk_c, all_N_PK, all_S_list, all_encrypts_list, PK, D_dummy_users, D_pairing, D_y, D_h, D_a, K_pairing, K_g, K_n, K_pubk):
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
            if N not  in all_N_list:
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
        # gid = PK[-1]
        gid = gid_list[i]
        KASE_encrypt = KASE.Encrypt(mpk, gid, N, K_pairing, K_g, K_n, K_pubk)
        all_KASE_encrypt.append(KASE_encrypt)

        pks = knowLedge[0]
        R = signature[0]
        z = signature[1]
        q = knowLedge[1]
        hkp1 = hashlib.sha256((str(pks) + str(R) + m).encode()).hexdigest()
        c = int(hkp1, 16) % q
        sendAll = ZeroKnowledgeProof.GenerateProofs(n3, pks, n, t, z, c, R, N[0],S)
        all_sendAll.append(sendAll)
    return [all_DTPKE_encrypt, all_KASE_encrypt, all_sendAll]


# 在sgx之外的部分
# :param sk_s: 太坊签名的私钥
# :param m: 消息m


def Combine2(sk_s, m, all_DTPKE_encrypt, all_KASE_encrypt, all_sendAll):
    all_yita = []
    for i in range(len(all_DTPKE_encrypt)):
        yita = BlockChain.Sign(sk_s, m, all_DTPKE_encrypt[i], all_KASE_encrypt[i], all_sendAll[i])
        # print("yita overhead:%s KB" % (objsize.get_deep_size(yita) / 1024))
        all_yita.append(yita)
    return all_DTPKE_encrypt, all_KASE_encrypt, all_sendAll, all_yita


def Verify(pk, m, all_DTPKE_encrypt, all_KASE_encrypt, all_sendAll, all_yita):
    for i in range(len(all_DTPKE_encrypt)):
        DTPKE_encrypt = all_DTPKE_encrypt[i]
        KASE_encrypt = all_KASE_encrypt[i]
        sendAll = all_sendAll[i]
        yita = all_yita[i]
        # starttime = datetime.datetime.now()
        f1 = BlockChain.Verify(pk, m, DTPKE_encrypt, KASE_encrypt, sendAll, yita)
        # endtime = datetime.datetime.now()
        # print("BlockChain.Verify Time：%s ms" % ((endtime - starttime).microseconds / 1000))  # 毫秒
        f2 = ZeroKnowledgeProof.VerifyProofs(sendAll)
        if not (f1 and f2):
            return False

    return True


def Trace1(pk_e, all_N_list, all_N_PK_list, all_sk_list, pk, m, all_DTPKE_encrypt, all_KASE_encrypt, all_sendAll, all_yita, D_pairing, K_pairing, K_n, K_pubk, ka, G, gid):
    for i in range(len(all_N_list)):
        N = all_N_list[i]
        KASE_encrypt = all_KASE_encrypt[i]
        gid = gid_list[i]
        for i in range(len(N)):
            pid = N[i]
            td_i = KASE.Trapdoor(ka, pid, K_pairing)
            Tri = KASE.Adjust(gid, G, td_i, K_pairing, K_n, K_pubk)
            test = KASE.Test(Tri, gid, G, KASE_encrypt, K_pairing, K_n, K_pubk)
            if not test:
                return False
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
    # 一个签名团的个数
    t = 5
    # 公证人的个数
    t2 = 5
    m = generateM(10)
    # 签名团的个数
    signatures_num = 1
    org_S = list(combinations(range(1, n + 1), t))[:signatures_num]
    org_N = list(combinations(range(1, n + 1), t2))[:signatures_num]
    random.shuffle(org_S)
    random.shuffle(org_N)
    all_S_list = [list(x) for x in org_S]
    all_N_list = [list(x) for x in org_N]

    n1 = 5
    n2 = 5
    # N = [1, 2, 3, 4, 5]
    # 存储公证人N的加密公钥
    n3 = len(all_N_list[0])
    print("Start SetUp")
    starttime = datetime.datetime.now()
    PK, S_param, D_param, K_param = Setup(qBit, rBit, t, n, n1, n2, n)
    gid_list = PK[-1]
    # 产生N对应的公钥，sk和公私钥对
    all_N_PK_list, all_sk_list, all_user_keys = generateN(all_N_list, n3, D_param)
    endtime = datetime.datetime.now()
    print("SetUpTime：%s ms" % ((endtime - starttime).total_seconds() * 1000))

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
    all_DTPKE_encrypt, all_KASE_encrypt, all_sendAll, all_yita = Combine2(sign_sks[1], m, all_DTPKE_encrypt, all_KASE_encrypt, all_sendAll)
    endtime = datetime.datetime.now()
    print("Combine2(NoSGX)：%s s" % ((endtime - starttime).total_seconds()))  # 毫秒
    print("combine overhead:%s KB" % (objsize.get_deep_size(all_DTPKE_encrypt + all_KASE_encrypt + all_sendAll) / 1024))
    print("Tx comb:%s KB" % (objsize.get_deep_size(all_DTPKE_encrypt + all_KASE_encrypt + all_sendAll + all_yita) / 1024))

    print("Verify")
    starttime = datetime.datetime.now()
    rs = Verify(sign_pks[1], m, all_DTPKE_encrypt, all_KASE_encrypt, all_sendAll, all_yita)
    print(rs)
    endtime = datetime.datetime.now()
    print("Verify Time：%s ms" % ((endtime - starttime).microseconds / 1000))  # 毫秒


    #
    # print("Trace")
    # starttime = datetime.datetime.now()
    # D_pairing = D_param[0]
    # K_pairing, K_n, K_pubk = K_param[0], K_param[2], K_param[3]
    # ka = PK[0]
    # G = [i for i in range(1, signatures_num + 1)]
    # gid = PK[-1]
    # #
    # all_ELGamal_encrypt, all_sign_list = Trace1(encrypt_pks[1], all_N_list,all_N_PK_list,all_sk_list, sign_pks[1], m, all_DTPKE_encrypt, all_KASE_encrypt, all_sendAll, all_yita,
    #                                     D_pairing, D_pairing, K_n, K_pubk, ka, G, gid)
    # all_S = []
    # for i in range(len(all_DTPKE_encrypt)):
    #     DTPKE_encrypt = all_DTPKE_encrypt[i]
    #     sign_list = all_sign_list[i]
    #     ELGamal_encrypt = all_ELGamal_encrypt[i]
    #     user_keys = all_user_keys[i]
    #     D_ek, D_dummy_users, D_k, D_g = D_param[8], D_param[6], DTPKE_encrypt[-1], D_param[1]
    #     S_p, S_q, S_g = S_param[2], S_param[3], S_param[4]
    #     S = Trace2(tracingKeys[1], t, n, m, sign_list, ELGamal_encrypt, DTPKE_encrypt, user_keys, D_ek, D_dummy_users, D_k,
    #                SgxParam.pairing, D_y, D_h, D_a, D_g, S_p, S_q, S_g)
    #     all_S.append(S)
    # print(all_S)
    # endtime = datetime.datetime.now()
    # print("Trace Time：%s s" % ((endtime - starttime).total_seconds()))  # 毫秒
