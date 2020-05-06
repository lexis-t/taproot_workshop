#!/usr/bin/env python3
import bitcoin

import util
from test_framework.address import program_to_witness, key_to_p2pkh, byte_to_base58
from test_framework.key import generate_key_pair, ECKey
from test_framework.messages import COutPoint, CTransaction, CTxIn, CTxOut, CTxInWitness
import test_framework
from test_framework.script import CScript, OP_IF, OP_ELSE, OP_ENDIF, OP_HASH160, OP_EQUAL, OP_CHECKSIG, \
    SegwitV0SignatureHash, get_p2pkh_script, SIGHASH_ALL, CScriptOp
from test_framework.segwit_addr import bech32_decode
from util import TestWrapper

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

node1_addr = node1.getnewaddress(address_type="bech32")
node2_addr = node2.getnewaddress(address_type="bech32")
node3_addr = node3.getnewaddress(address_type="bech32")

node1.generatetoaddress(250, node1_addr)
node2.generatetoaddress(250, node2_addr)
# node3.generate(2)

balance1 = node1.getbalance()
print('Balance node 1:', balance1)

balance2 = node2.getbalance()
print('Balance node 2:', balance2)

priv = ECKey()
priv.generate()

#init_key = byte_to_base58(priv.get_bytes(), 0xef)
init_addr = key_to_p2pkh(priv.get_pubkey().get_bytes())

print("Initial WIP key: {}".format(init_key))
print("Initial addr: {}".format(init_addr))

#node1.importprivkey(init_key, "Test key", False)
node1.importaddress(init_addr, "Test address", False)

tx = node1.sendtoaddress(init_addr, 20, "Initial transaction")
print("Initial transaction id: {}".format(tx))

node1.generatetoaddress(10, node1_addr)

# test_transactions = node1.listtransactions("Initial transaction")
# print(test_transactions)

#print(node1.listunspent(addresses=[init_addr]))

init_balance = node1.getreceivedbyaddress(init_addr)
print('Initial balance:', init_balance)

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

# Transaction script from https://medium.com/softblocks/lightning-network-in-depth-part-2-htlc-and-payment-routing-db46aea445a8
# but without timeout condition for simplicity

node1_info = node1.getaddressinfo(channel_addr_1)
node2_info = node2.getaddressinfo(channel_addr_2)

# print(node1_info)
# print(node2_info)

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
print(k1)

# k2 = node2.dumpprivkey(node2_info['address'])
# print(k2)

key = bitcoin.decode_privkey(k1)
print(key)

priv1 = ECKey()
priv1.set(key)

sig = priv1.sign_ecdsa(sighash) + chr(SIGHASH_ALL).encode('latin-1')

print("Signature: {}\n".format(sig.hex()))

# Add a witness to the transaction. For a P2WPKH, the witness field is the signature and pubkey
spending_tx.wit.vtxinwit.append(CTxInWitness([sig.hex(), channel_addr_1]))

# print(spending_tx)

# Serialize signed transaction for broadcast
spending_tx_str = spending_tx.serialize()

# Test mempool acceptance
assert node1.testmempoolaccept(rawtxs=[spending_tx_str], maxfeerate=0)[0]['allowed']

# node1.


# addr1 = node1.get_deterministic_priv_key().address
# program = hash160(addr1)


test.shutdown()
