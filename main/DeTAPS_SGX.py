import hashlib

import SchnorrATS
from PKE_pg import ELGamal
import KASE
import DTPKE
import DeTAPS_NoSGX
from Zero_Knowledge_pg import ZeroKnowledgeProof
import datetime
"""
:param sk_c: CombiningKey
:param N_pk: 存储公证人N的加密公钥
:param S: 授权签名人集合
:param encrypts: PKE加密后的密文集合
"""


# Combiner先解密后聚合这些签名。
# Combiner先解密后聚合这些签名。
def Combine1(sk_c, all_N_PK, all_S_list, all_encrypts_list, PK, D_dummy_users, D_pairing, D_y, D_h, D_a, K_pairing, K_g, K_n, K_pubk):
    n3 = len(all_N_PK[0])
    all_signatures_list = []
    all_N_list = []
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
        # gid = PK[-1]
        gid = PK[-1][i]
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
    return all_DTPKE_encrypt, all_KASE_encrypt, all_sendAll


def getN(plaintext, n3):
    l = plaintext.split(",")
    N = l[-1 * n3:]
    return [int(i) for i in N]

combiningKeys, all_N_PK_list, all_N_list ,all_S_list, all_encrypts_list, PK, D_dummy_users, D_pairing, D_y, D_h, D_a, K_pairing, K_g, K_n, K_pubk,knowLedge,m,n,t = DeTAPS_NoSGX.SGX1_param
starttime = datetime.datetime.now()
all_DTPKE_encrypt, all_KASE_encrypt, all_sendAll = Combine1(combiningKeys[1], all_N_PK_list,all_S_list, all_encrypts_list, PK, D_dummy_users, D_pairing, D_y, D_h, D_a, K_pairing, K_g, K_n, K_pubk)
endtime = datetime.datetime.now()
print("Combine1(SGX) Time：%s s" % ((endtime - starttime).total_seconds()))

NoSGX2_param = (all_DTPKE_encrypt, all_KASE_encrypt, all_sendAll)

