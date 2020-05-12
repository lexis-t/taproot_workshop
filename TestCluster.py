#!/usr/bin/env python3
from time import sleep

import bitcoin

import util
from test_framework.address import program_to_witness, key_to_p2pkh, key_to_p2sh_p2wpkh, script_to_p2sh, byte_to_base58
from test_framework.key import generate_key_pair, ECKey
from test_framework.messages import COutPoint, CTransaction, CTxIn, CTxOut, CTxInWitness, FromHex
import test_framework
from test_framework.script import CScript, CScriptOp, OP_IF, OP_ELSE, OP_ENDIF, OP_HASH160, OP_EQUAL, OP_CHECKSIG, \
    SegwitV0SignatureHash, get_p2pkh_script, hash160, SIGHASH_ALL, OP_DUP, OP_EQUALVERIFY
from test_framework.segwit_addr import bech32_decode
from util import TestWrapper
import base58
import bitcoin

test = TestWrapper()
# Start TestNodes
# test.num_nodes = 3
test.setup(num_nodes=1)
print("count nodes", test.num_nodes)

version = test.nodes[0].getnetworkinfo()['subversion']
print("Client version is {}".format(version))

node1 = test.nodes[0]  # coin sender
# node2 = test.nodes[1]  # coin receiver
# node3 = test.nodes[2]  # mainer

node1_addr = node1.getnewaddress(address_type="legacy")
# node2_addr = node2.getnewaddress(address_type="bech32")
# node3_addr = node3.getnewaddress(address_type="bech32")

node1.generatetoaddress(250, node1_addr)
# node2.generatetoaddress(250, node2_addr)
# node3.generate(2)

node1_priv = node1.dumpprivkey(node1_addr)
print("Node1 key base58: {}".format(node1_priv))

node1_key_bytes = base58.b58decode_check(node1_priv)
print("Node1 key: {}".format(node1_key_bytes.hex()))

node1_key_reencoded = base58.b58encode_check(node1_key_bytes)
print("Node1 key reencoded: {}".format(node1_key_reencoded))

balance1 = node1.getbalance()
print('Balance node 1:', balance1)

# balance2 = node2.getbalance()
# print('Balance node 2:', balance2)

# Spending key
key0 = ECKey()
key0.generate(compressed=True)

key0_bytes = b'\xef' + key0.get_bytes() + b'\x01'
key0_wif = str(base58.b58encode_check(key0_bytes), "ascii")

addr0 = key_to_p2pkh(key0.get_pubkey().get_bytes())

print("key0 bytes: {}".format(key0_bytes.hex()))
print("key0 WIF: {}".format(key0_wif))
print("addr0: {}".format(addr0))

node1.importprivkey(key0_wif, "key0", False)
# node1.importaddress(addr0, "addr0", False)

key0_change = ECKey()
key0_change.generate(compressed=True)

addr0_change = key_to_p2pkh(key0_change.get_pubkey().get_bytes())

key0_change_bytes = b'\xef' + key0_change.get_bytes() + b'\x01'
key0_change_wif = str(base58.b58encode_check(key0_change_bytes), "ascii")

# node1.importprivkey(key0_change_wif, "key0 change", False)


# Receiving key
key1 = ECKey()
key1.generate(compressed=True)

addr1 = key_to_p2sh_p2wpkh(key1.get_pubkey().get_bytes())
# node2.importaddress(addr1, "addr1", False)

# Send coins to spending address
tx0_id = node1.sendtoaddress(addr0, 50, "Initial transaction")
print("Initial transaction id: {}".format(tx0_id))

node1.generatetoaddress(2, node1_addr)

init_balance = node1.getreceivedbyaddress(addr0)
print('Initial balance:', init_balance)

tx0_data = node1.gettransaction(tx0_id)
tx0 = FromHex(CTransaction(), tx0_data["hex"])
print(tx0)

# Transaction script from https://medium.com/softblocks/lightning-network-in-depth-part-2-htlc-and-payment-routing-db46aea445a8
# but without timeout condition for simplicity

secret = b'secret'
secret_hash = hash160(secret)

channel_script = CScript([CScriptOp(OP_HASH160), secret_hash, CScriptOp(OP_EQUAL),
                          CScriptOp(OP_IF),
                          key1.get_pubkey().get_bytes(),
                          CScriptOp(OP_ELSE),
                          key0.get_pubkey().get_bytes(),
                          CScriptOp(OP_ENDIF),
                          CScriptOp(OP_CHECKSIG)])

script_addr = script_to_p2sh(channel_script)

print("Channel script addr: {}".format(script_addr))

channel = CTransaction()
channel.nVersion = 2
channel.nLockTime = 0

outpoint = COutPoint(int(tx0_id, 16), 0)
channel_in = CTxIn(outpoint)
channel.vin = [channel_in]

channel_out = CTxOut(4_500_000_000, CScript([OP_HASH160, hash160(channel_script), OP_EQUAL]))
channel_change = CTxOut(499_999_000, CScript(
    [OP_DUP, OP_HASH160, hash160(key0.get_pubkey().get_bytes()), OP_EQUALVERIFY, OP_CHECKSIG]))
channel.vout = [channel_out, channel_change]

channel_tx = channel.serialize().hex()

res = node1.signrawtransactionwithkey(channel_tx, [key0_wif])

if not res["complete"]:
    print("Channel signature failed")
    test.shutdown()
    exit(1)

print("Signed tx: {}".format(res["hex"]))

channel_tx = res["hex"]

# channel_tx = channel.serialize()
# channel_vin_sig = key0.sign_ecdsa(channel_tx) + chr(SIGHASH_ALL).encode('latin-1')
# channel.vin[0].scriptSig = CScript([channel_vin_sig, key0.get_pubkey().get_bytes()])
# channel_tx = channel.serialize().hex()


channel_tx_id = node1.sendrawtransaction(channel_tx)
print("Channel tx: {}".format(channel_tx))

node1.generatetoaddress(2, node1_addr)


unspent = node1.listunspent(addresses=[addr0])
print("Change remained: {}".format(unspent[0]["amount"]))


# channel_tx_data = node1.gettransaction(channel_tx_id)
# channel_tx = channel_tx_data["hex"]

channel_json = node1.decoderawtransaction(channel_tx)
channel_tx_id = channel_json["txid"]

print("Channel tx id: {}".format(channel_tx_id))

spend_channel = CTransaction()
spend_channel.nVersion = 2
spend_channel.nLockTime = 0

channel_script_bytes = bytes(channel_script)

spend_channel.vin = [CTxIn(COutPoint(int(channel_tx_id, 16), 0),
                           CScript([secret, key1.get_pubkey().get_bytes(), channel_script_bytes]))]
spend_channel.vout = [CTxOut(4_499_999_000), CScript(
    [OP_DUP, OP_HASH160, hash160(key1.get_pubkey().get_bytes()), OP_EQUALVERIFY, OP_CHECKSIG])]

spend_channel_tx = spend_channel.serialize().hex()

spend_channel_tx = node1.sendrawtransaction(spend_channel_tx)
spend_channel_json = node1.decoderawtransaction(spend_channel_tx)

node1.generatetoaddress(2, node1_addr)

# sighash = SegwitV0SignatureHash(script=channel_script,
#                                 txTo=spescriptnding_tx,
#                                 inIdx=0,
#                                 hashtype=SIGHASH_ALL,
#                                 amount=100_000_000)
#
# sig = spending_key.sign_ecdsa(sighash) + chr(SIGHASH_ALL).encode('latin-1')
#
# address = program_to_witness(version, program)
# print("bech32 address: {}".format(address))
#
# print("Signature: {}\n".format(sig.hex()))
#
# # Add a witness to the transaction. For a P2WPKH, the witness field is the signature and pubkey
# spending_tx.wit.vtxinwit.append(CTxInWitness([sig.hex(), channel_addr_1]))
#
# # print(spending_tx)
#
# # Serialize signed transaction for broadcast
# spending_tx_str = spending_tx.serialize()
#
# # Test mempool acceptance
# assert node1.testmempoolaccept(rawtxs=[spending_tx_str], maxfeerate=0)[0]['allowed']


test.shutdown()
