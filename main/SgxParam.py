from pypbc import Parameters, Pairing

params = Parameters(qbits=512, rbits=160)  # 参数初始化
# global pairing, g, h, y, a, m, dummy_users, mk, ek, ck
pairing = Pairing(params)