import os
import random
import string

from eth_account.messages import encode_defunct
from web3 import Account, HTTPProvider
from eth_keys import keys
from web3 import Web3
from web3.middleware import geth_poa_middleware

def KeyGen(n1):
    sign_pks = [0]
    sign_sks = [0]
    path = 'keyfiles'
    path_list = os.listdir(path)[:n1]
    for file in path_list:
        with open(os.path.join(path, file), "r") as f:
            encrypted_key = f.read()
            # 从keystore中获取私钥privatekey，需要输入密码（注意这里的密码并不是私钥）
            privatekey = Account.decrypt(encrypted_key, "123")
            sign_sks.append(privatekey)
            # 先创建keys模块下的私钥对象
            priv_key = keys.PrivateKey(privatekey)
            # 再解出公钥
            public_key = priv_key.public_key
            sha3_pub_key = Web3.keccak(hexstr=str(public_key))
            # 取后20个字节
            address = Web3.toHex(sha3_pub_key[-20:])
            sign_pks.append(address)
    return sign_pks, sign_sks




def Sign(sk_s, m, DTPKE_encrypt, KASE_encrypt, sendAll):
    web3rpc = Web3(HTTPProvider("http://localhost:8545"))
    web3rpc.middleware_onion.inject(geth_poa_middleware, layer=0)
    private_key = sk_s
    message = str(m) + "," + str(DTPKE_encrypt) + "," + str(KASE_encrypt) + "," + str(sendAll)
    message = encode_defunct(text=message)
    signed_message = web3rpc.eth.account.sign_message(message, private_key=private_key)
    return signed_message



def Verify(pk, m, DTPKE_encrypt, KASE_encrypt, sendAll, yita):
    web3rpc = Web3(HTTPProvider("http://localhost:8545"))
    web3rpc.middleware_onion.inject(geth_poa_middleware, layer=0)
    for i in range(len(m)):
        f = m[i].isdigit() or m[i].isalpha()
        if not f:
            return False
    message = str(m) + "," + str(DTPKE_encrypt) + "," + str(KASE_encrypt) + "," + str(sendAll)
    message = encode_defunct(text=message)
    account_new = web3rpc.eth.account.recover_message(message, signature=yita['signature'])
    return pk == account_new.lower()

def ranstr(num):
    salt = ''.join(random.sample(string.ascii_letters + string.digits, num))
    return salt

def to_32byte_hex(val):
    return Web3.toHex(Web3.toBytes(val).rjust(32, b'\0'))

false = False
true = True
contract_abi = [{"constant":false,"inputs":[{"name":"signatures","type":"string"},{"name":"msgh","type":"bytes32"},{"name":"v","type":"uint8"},{"name":"r","type":"bytes32"},{"name":"s","type":"bytes32"}],"name":"Upload","outputs":[],"payable":false,"stateMutability":"nonpayable","type":"function"},{"constant":false,"inputs":[{"name":"Tri","type":"string"},{"name":"gid","type":"string"},{"name":"G","type":"string"},{"name":"encrypt","type":"string"},{"name":"pairing","type":"string"},{"name":"n","type":"string"},{"name":"pubk","type":"string"},{"name":"msgh","type":"bytes32"},{"name":"v","type":"uint8"},{"name":"r","type":"bytes32"},{"name":"s","type":"bytes32"}],"name":"Test","outputs":[],"payable":false,"stateMutability":"nonpayable","type":"function"},{"constant":true,"inputs":[{"name":"","type":"uint256"}],"name":"broadcastPool","outputs":[{"name":"","type":"string"}],"payable":false,"stateMutability":"view","type":"function"},{"constant":false,"inputs":[{"name":"gid","type":"string"},{"name":"G","type":"string"},{"name":"td_i","type":"string"},{"name":"pairing","type":"string"},{"name":"n","type":"string"},{"name":"pubk","type":"string"},{"name":"msgh","type":"bytes32"},{"name":"v","type":"uint8"},{"name":"r","type":"bytes32"},{"name":"s","type":"bytes32"}],"name":"Adjust","outputs":[],"payable":false,"stateMutability":"nonpayable","type":"function"}]
contract_address ="0xBBFC86da6D1c3A5c83f20258a722815d8618648a"
def txUpload():
    with open("keyfiles/UTC--2023-03-20T06-56-20.412086300Z--5d7aa0b50f30845e32f10fa9c6997b8f9faa113f") as keyfile:
        web3rpc = Web3(HTTPProvider("http://localhost:8545"))
        web3rpc.middleware_onion.inject(geth_poa_middleware, layer=0)
        acc = web3rpc.eth.accounts[0]
        web3rpc.eth.defaultAccount = acc
        contract = web3rpc.eth.contract(contract_address, abi=contract_abi)
        encrypted_key = keyfile.read()
        private_key = web3rpc.eth.account.decrypt(encrypted_key, '123')
        signatures = ranstr(8)
        message = str(signatures)
        message = encode_defunct(text=message)
        signed_message = web3rpc.eth.account.sign_message(message, private_key=private_key)
        ec_recover_args = (msghash, v, r, s) = (
            web3rpc.toHex(signed_message.messageHash),
            signed_message.v,
            to_32byte_hex(signed_message.r),
            to_32byte_hex(signed_message.s)
        )
        tx_hash = contract.functions.Upload(signatures, msghash, v, r, s).transact()
        tx_receipt = web3rpc.eth.waitForTransactionReceipt(tx_hash)
        print(tx_receipt["gasUsed"])


def txAdjust():
    with open("keyfiles/UTC--2023-03-20T06-56-20.412086300Z--5d7aa0b50f30845e32f10fa9c6997b8f9faa113f") as keyfile:
        web3rpc = Web3(HTTPProvider("http://localhost:8545"))
        web3rpc.middleware_onion.inject(geth_poa_middleware, layer=0)
        acc = web3rpc.eth.accounts[0]
        web3rpc.eth.defaultAccount = acc
        contract = web3rpc.eth.contract(contract_address, abi=contract_abi)
        encrypted_key = keyfile.read()
        private_key = web3rpc.eth.account.decrypt(encrypted_key, '123')
        gid = ranstr(8)
        G = ranstr(8)
        td_i = ranstr(8)
        pairing = ranstr(8)
        n = ranstr(8)
        pubk = ranstr(8)
        message = str(gid) + str(G) + str(td_i) + str(pairing) + str(n) + str(pubk)
        message = encode_defunct(text=message)
        signed_message = web3rpc.eth.account.sign_message(message, private_key=private_key)
        ec_recover_args = (msghash, v, r, s) = (
            web3rpc.toHex(signed_message.messageHash),
            signed_message.v,
            to_32byte_hex(signed_message.r),
            to_32byte_hex(signed_message.s)
        )
        tx_hash = contract.functions.Adjust(gid,G,td_i,pairing,n,pubk, msghash, v, r, s).transact()
        tx_receipt = web3rpc.eth.waitForTransactionReceipt(tx_hash)
        print(tx_receipt["gasUsed"])

def txTest():
    with open("keyfiles/UTC--2023-03-20T06-56-20.412086300Z--5d7aa0b50f30845e32f10fa9c6997b8f9faa113f") as keyfile:
        web3rpc = Web3(HTTPProvider("http://localhost:8545"))
        web3rpc.middleware_onion.inject(geth_poa_middleware, layer=0)
        acc = web3rpc.eth.accounts[0]
        web3rpc.eth.defaultAccount = acc
        contract = web3rpc.eth.contract(contract_address, abi=contract_abi)
        encrypted_key = keyfile.read()
        private_key = web3rpc.eth.account.decrypt(encrypted_key, '123')
        Tri = ranstr(8)
        gid = ranstr(8)
        G = ranstr(8)
        encrypt = ranstr(8)
        pairing = ranstr(8)
        n = ranstr(8)
        pubk = ranstr(8)
        message = str(Tri) + str(gid) + str(G) + str(encrypt) + str(pairing) +str(n) +str(pubk)
        message = encode_defunct(text=message)
        signed_message = web3rpc.eth.account.sign_message(message, private_key=private_key)
        ec_recover_args = (msghash, v, r, s) = (
            web3rpc.toHex(signed_message.messageHash),
            signed_message.v,
            to_32byte_hex(signed_message.r),
            to_32byte_hex(signed_message.s)
        )
        tx_hash = contract.functions.Test(Tri, gid, G,encrypt,pairing,n,pubk, msghash, v, r, s).transact()
        tx_receipt = web3rpc.eth.waitForTransactionReceipt(tx_hash)
        print(tx_receipt["gasUsed"])





if __name__ == '__main__':
    txUpload()

