def KeyGen(n1):
    sign_pks = [0]
    sign_sks = [0]
    for i in range(1, n1 + 1):
        sign_pks.append(i)
        sign_sks.append(i)
    return sign_pks, sign_sks


def Sign(sk_s, m, DTPKE_encrypt, KASE_encrypt, sendAll):
    signed_message = ""
    return signed_message

def Verify(pk, m, DTPKE_encrypt, KASE_encrypt, sendAll, yita):
    return True