#!/usr/bin/env python3
import bitcoin

import util
from test_framework.address import program_to_witness
from test_framework.key import generate_key_pair, ECKey
from test_framework.messages import COutPoint, CTransaction, CTxIn, CTxOut, CTxInWitness
import test_framework
from test_framework.script import CScript, OP_IF, OP_ELSE, OP_ENDIF, OP_HASH160, OP_EQUAL, OP_CHECKSIG, \
    SegwitV0SignatureHash, get_p2pkh_script, SIGHASH_ALL, CScriptOp
from test_framework.segwit_addr import bech32_decode
from test_framework.util import hex_str_to_bytes
# from pybitcoin import BitcoinPrivateKey
from util import TestWrapper
from hashlib import sha256
import base58
import binascii
import ecdsa
from ecdsa import SigningKey, SECP256k1, VerifyingKey, BadSignatureError

# pip install base58

def unwif(b58cstr):
    bytes = base58.b58decode_check(b58cstr)
    return (bytes[0], bytes[1:])

def get_key_from_wif(key):
    private_key = unwif(key)[1]
    if (len(private_key) == 33):
        private_key = private_key[:-1]
    return private_key


test = TestWrapper()
# Start TestNodes
#test.num_nodes = 3
test.setup(num_nodes=3)
print("count nodes", test.num_nodes)

version = test.nodes[0].getnetworkinfo()['subversion']
print("Client version is {}".format(version))

node1 = test.nodes[0] # coin sender
node2 = test.nodes[1] # coin receiver
node3 = test.nodes[2] # mainer

node1_addr = node1.getnewaddress(address_type="bech32")
node2_addr = node2.getnewaddress(address_type="bech32")

node1.generatetoaddress(250, node1_addr)
node2.generatetoaddress(250, node2_addr)
#node3.generate(2)

balance1 = node1.getbalance()
print('Balance node 1:', balance1)

balance2 = node2.getbalance()
print('Balance node 2:', balance2)

spending_tx = CTransaction()

spending_tx.nVersion = 1
spending_tx.nLockTime = 0

unspent_txid = node1.listunspent(1)[-1]["txid"]
outpoint = COutPoint(int(unspent_txid, 16), 0)
spending_tx_in = CTxIn(outpoint)
spending_tx.vin = [spending_tx_in]


channel_addr_1 = node1_addr
channel_addr_2 = node2_addr


secret = b'secret'

#Transaction script from https://medium.com/softblocks/lightning-network-in-depth-part-2-htlc-and-payment-routing-db46aea445a8
#but without timeout condition for simplicity

node1_info = node1.getaddressinfo(channel_addr_1)
node2_info = node2.getaddressinfo(channel_addr_2)

print(node1_info)
print(node2_info)

script = CScript([CScriptOp(OP_HASH160), secret, CScriptOp(OP_EQUAL),
                  CScriptOp(OP_IF),
                  bytes.fromhex(node1_info['pubkey']), CScriptOp(OP_CHECKSIG),
                  CScriptOp(OP_ELSE),
                  bytes.fromhex(node2_info['pubkey']), CScriptOp(OP_CHECKSIG),
                  CScriptOp(OP_ENDIF)])

sighash = SegwitV0SignatureHash(script=script,
                               txTo=spending_tx,
                               inIdx=0,
                               hashtype=SIGHASH_ALL,
                               amount=100_000_000)




k1 = node1.dumpprivkey(node1_info['address'])
print("dumpkey: ",k1)
# see https://github.com/patricklodder/devfundtx !!!!
# https://learnmeabitcoin.com/guide/public-key good info
private_key = SigningKey.from_string(get_key_from_wif(k1), SECP256k1, sha256)
print("private_key: ", private_key.verifying_key.to_string().hex())
print("private_key2: ", private_key.to_string().hex())



priv1 = ECKey()

priv1.set(private_key.to_string())

print("priv1: ",priv1.get_bytes().hex()) # priv1 == private_key2

sig = priv1.sign_ecdsa(sighash) + chr(SIGHASH_ALL).encode('latin-1')

print("Signature: {}\n".format(sig.hex()))

# Add a witness to the transaction. For a P2WPKH, the witness field is the signature and pubkey
spending_tx.wit.vtxinwit.append(CTxInWitness([sig.hex(), channel_addr_1]))

# Serialize signed transaction for broadcast
# print("Spending transaction:\n{}\n".format(spending_tx))

# print("Transaction weight: {}\n".format(node1.decoderawtransaction(spending_tx.serialize().hex())['weight']))

# spending_tx_str = spending_tx.serialize()

# Test mempool acceptance
# assert node1.testmempoolaccept(rawtxs=[spending_tx_str], maxfeerate=0)[0]['allowed']
# assert node1.test_transaction(spending_tx)

test.shutdown()
