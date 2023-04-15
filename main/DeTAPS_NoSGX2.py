import datetime

import objsize

import DeTAPS_NoSGX
import DeTAPS_SGX
from PKE_pg import ELGamal
import KASE
import DTPKE
import Sig
from Zero_Knowledge_pg import ZeroKnowledgeProof


def Combine2(sk_s, m, all_DTPKE_encrypt, all_KASE_encrypt, all_sendAll):
    all_yita = []
    for i in range(len(all_DTPKE_encrypt)):
        yita = Sig.Sign(sk_s, m, all_DTPKE_encrypt[i], all_KASE_encrypt[i], all_sendAll[i])
        all_yita.append(yita)
    return all_DTPKE_encrypt, all_KASE_encrypt, all_sendAll, all_yita


def Verify(pk, m, all_DTPKE_encrypt, all_KASE_encrypt, all_sendAll, all_yita):
    f1 = Sig.Verify(pk, m, all_DTPKE_encrypt, all_KASE_encrypt, all_sendAll, all_yita)
    for sendAll in all_sendAll:
        f2 = ZeroKnowledgeProof.VerifyProofs(sendAll)
        f1 = f1 and f2
    return f1


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


m, D_param, K_param, PK, S_param, all_N_list, all_N_PK_list, all_sk_list, encrypt_pks, signatures_num = DeTAPS_NoSGX.NoSGX2_param
all_DTPKE_encrypt, all_KASE_encrypt, all_sendAll = DeTAPS_SGX.NoSGX2_param
sign_pks, sign_sks = Sig.KeyGen(1)
starttime = datetime.datetime.now()
all_DTPKE_encrypt, all_KASE_encrypt, all_sendAll, all_yita = Combine2(sign_sks[1], m, all_DTPKE_encrypt,
                                                                      all_KASE_encrypt, all_sendAll)
endtime = datetime.datetime.now()
print("Combine2(Without SGX) Time：%s s" % ((endtime - starttime).total_seconds()))
print("combine overhead:%s KB" % (objsize.get_deep_size(all_DTPKE_encrypt + all_KASE_encrypt + all_sendAll) / 1024))

print("Verify")
starttime = datetime.datetime.now()
rs = Verify(sign_pks[1], m, all_DTPKE_encrypt, all_KASE_encrypt, all_sendAll, all_yita)
endtime = datetime.datetime.now()
print("Verify Time：%s s" % ((endtime - starttime).total_seconds()))

print("Trace")
D_pairing = D_param[0]
K_pairing, K_n, K_pubk = K_param[0], K_param[2], K_param[3]
ka = PK[0]
G = [i for i in range(1, signatures_num + 1)]
gid_list = PK[-1]

starttime = datetime.datetime.now()
all_ELGamal_encrypt, all_sign_list = Trace1(encrypt_pks[1], all_N_list, all_N_PK_list, all_sk_list, sign_pks[1], m,
                                            all_DTPKE_encrypt, all_KASE_encrypt, all_sendAll, all_yita,
                                            D_pairing, D_pairing, K_n, K_pubk, ka, G, gid_list)
endtime = datetime.datetime.now()
print("Trace1(Without SGX) Time：%s s" % ((endtime - starttime).total_seconds()))
SGX2_param = (all_ELGamal_encrypt, all_sign_list, all_DTPKE_encrypt)
