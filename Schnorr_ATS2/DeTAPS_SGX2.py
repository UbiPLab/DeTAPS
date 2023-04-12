import SchnorrATS
from PKE_pg import ELGamal
import DTPKE
import DeTAPS_NoSGX
import DeTAPS_NoSGX2
import datetime


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


def TraceAll(pk_e):
    all_S = []
    for i in range(len(all_DTPKE_encrypt)):
        DTPKE_encrypt = all_DTPKE_encrypt[i]
        sign_list = all_sign_list[i]
        ELGamal_encrypt = all_ELGamal_encrypt[i]
        user_keys = all_user_keys[i]
        D_ek, D_dummy_users, D_k, D_g = D_param[8], D_param[6], DTPKE_encrypt[-1], D_param[1]
        S_p, S_q, S_g = S_param[2], S_param[3], S_param[4]
        D_dummy_users, D_pairing, D_y, D_h, D_a = D_param[6], D_param[0], D_param[3], D_param[2], D_param[4]
        S = Trace2(tracingKeys[1], t, n, m, sign_list, ELGamal_encrypt, DTPKE_encrypt, user_keys, D_ek, D_dummy_users,
                   D_k,
                   D_pairing, D_y, D_h, D_a, D_g, S_p, S_q, S_g)
        all_S.append(S)

    ELGamal_encrypt = ELGamal.encrypt(str(all_S), ELGamal.p, pk_e, ELGamal.r)
    return all_S


tracingKeys, t, n, m, all_user_keys, D_param, K_param, S_param, encrypt_pks = DeTAPS_NoSGX.SGX2_param
all_ELGamal_encrypt, all_sign_list, all_DTPKE_encrypt = DeTAPS_NoSGX2.SGX2_param
starttime = datetime.datetime.now()
all_S = TraceAll(encrypt_pks[1])
endtime = datetime.datetime.now()
print("Trace2(SGX) Time：%s s" % ((endtime - starttime).total_seconds()))
print(all_S)
