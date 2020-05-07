#!/usr/bin/env python3
from time import sleep

import bitcoin

import util
from test_framework.address import program_to_witness, key_to_p2pkh, key_to_p2sh_p2wpkh, script_to_p2sh, byte_to_base58
from test_framework.key import generate_key_pair, ECKey
from test_framework.messages import COutPoint, CTransaction, CTxIn, CTxOut, CTxInWitness, FromHex
import test_framework
from test_framework.script import CScript, OP_IF, OP_ELSE, OP_ENDIF, OP_HASH160, OP_EQUAL, OP_CHECKSIG, \
    SegwitV0SignatureHash, get_p2pkh_script, SIGHASH_ALL, CScriptOp
from test_framework.segwit_addr import bech32_decode
from util import TestWrapper
import base58
import bitcoin

test = TestWrapper()
# Start TestNodes
# test.num_nodes = 3
test.setup(num_nodes=3)
print("count nodes", test.num_nodes)

version = test.nodes[0].getnetworkinfo()['subversion']
print("Client version is {}".format(version))

node1 = test.nodes[0]  # coin sender
node2 = test.nodes[1]  # coin receiver
node3 = test.nodes[2]  # mainer

node1_addr = node1.getnewaddress(address_type="legacy")
node2_addr = node2.getnewaddress(address_type="bech32")
node3_addr = node3.getnewaddress(address_type="bech32")

node1.generatetoaddress(250, node1_addr)
node2.generatetoaddress(250, node2_addr)
# node3.generate(2)

node1_priv = node1.dumpprivkey(node1_addr)
node1_key_bytes = base58.b58decode_check(node1_priv)
print("Node1 key: {}".format(node1_key_bytes.hex()))

balance1 = node1.getbalance()
print('Balance node 1:', balance1)

balance2 = node2.getbalance()
print('Balance node 2:', balance2)

# Spending key
spending_key = ECKey()
spending_key.generate(compressed=True)

spending_wif = bitcoin.encode_privkey(spending_key.get_bytes(), "wif_compressed", 111)
# print("WIF: {}".format(wif))

# spending_wif = byte_to_base58(spending_key.get_bytes()+b'0x01', 111)
spending_addr = key_to_p2pkh(spending_key.get_pubkey().get_bytes())

print("Spending WIF: {}".format(spending_wif))
print("Spending addr: {}".format(spending_addr))

node1.importprivkey(spending_wif, "Spending key", False)
node1.importaddress(spending_addr, "Spending address", False)

# Receiving key
receiving_key = ECKey()
receiving_key.generate(compressed=True)

receiving_addr = key_to_p2sh_p2wpkh(receiving_key.get_pubkey().get_bytes())
node2.importaddress(receiving_addr, "Receiving address", False)

# Send coins to spending address
unspent_txid = node1.sendtoaddress(spending_addr, 20, "Initial transaction")
print("Initial transaction id: {}".format(unspent_txid))

node1.generatetoaddress(1, node1_addr)

init_balance = node1.getreceivedbyaddress(spending_addr)
print('Initial balance:', init_balance)

# Create channel

secret = b'secret'

channel_script = CScript([CScriptOp(OP_HASH160), secret, CScriptOp(OP_EQUAL),
                          CScriptOp(OP_IF),
                          spending_key.get_pubkey().get_bytes(),
                          CScriptOp(OP_ELSE),
                          receiving_key.get_pubkey().get_bytes(),
                          CScriptOp(OP_ENDIF),
                          CScriptOp(OP_CHECKSIG)])

script_addr = script_to_p2sh(channel_script)

print("Channel script addr: {}".format(script_addr))

channel_tx = node1.createrawtransaction(inputs=[{"txid": unspent_txid, "vout": 0}], outputs=[{script_addr: 15}, {spending_addr: 4.99}])
# sign_res = node1.signrawtransactionwithkey(channel_tx, [spending_wif])
sign_res = node1.signrawtransactionwithwallet(channel_tx)

print(sign_res)

channel = CTransaction()
FromHex(channel, channel_tx)
print(channel)

res = node1.sendrawtransaction(channel_tx)
print(res)

# channel_sig = spending_key.sign_ecdsa(  channel_tx)

# sig_res = node1.signrawtransactionwithkey(channel_tx, )


# channel_txid = node1.sendtoaddress(script_addr, 15)

node1.generatetoaddress(1, node1_addr)

init_balance = node1.getreceivedbyaddress(spending_addr)
print('Balance after channel opening:', init_balance)

# spending_tx = CTransaction()
#
# spending_tx.nVersion = 1
# spending_tx.nLockTime = 0
#
# outpoint = COutPoint(int(unspent_txid, 16), 0)
# spending_tx_in = CTxIn(outpoint)
# spending_tx.vin = [spending_tx_in]
#
# # Transaction script from https://medium.com/softblocks/lightning-network-in-depth-part-2-htlc-and-payment-routing-db46aea445a8
# # but without timeout condition for simplicity
#
#
# sighash = SegwitV0SignatureHash(script=script,
#                                 txTo=spending_tx,
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
