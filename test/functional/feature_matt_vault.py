#!/usr/bin/env python3
# Copyright (c) 2023 The Bitcoin Core developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.
"""
Test vaults with OP_CICV and OP_COCV.
"""

from typing import List, Optional, Tuple, Union

from test_framework.test_framework import BitcoinTestFramework, TestNode
from test_framework.p2p import P2PInterface
from test_framework.wallet import MiniWallet, MiniWalletMode
from test_framework.script import (
    CScript,
    OP_0,
    OP_CHECKINPUTCONTRACTVERIFY,
    OP_CHECKOUTPUTCONTRACTVERIFY,
    OP_CHECKSEQUENCEVERIFY,
    OP_CHECKSIG,
    OP_CHECKTEMPLATEVERIFY,
    OP_DROP,
    OP_DUP,
    OP_ROLL,
    OP_SWAP,
    OP_TRUE,
)
from test_framework.messages import CTransaction, COutPoint, CTxInWitness, CTxOut, CTxIn, COIN
from test_framework.util import assert_equal, assert_raises_rpc_error

from test_framework import script, key

from feature_matt import P2TR, AugmentedP2TR


# point with provably unknown private key
NUMS_KEY = bytes.fromhex("50929b74c1a04954b78b4b6035e97a5e078a5a0f28ec96d547bfee9ace803ac0")


# params:
#  - alternate_pk
#  - spend_delay
#  - recover_pk
# spending conditions:
#  - alternate_pk                  =>  anywhere
#  -                               =>  <recovery> path
#  - c:pk(unvault_pk)    (ctv_hash)=>  UNVAULTING[withdrawal_tmpl]
class Vault(P2TR):
    def __init__(self, alternate_pk: bytes, spend_delay: int, recover_pk: bytes, unvault_pk: bytes):
        assert len(alternate_pk) == 32 and len(recover_pk) == 32 and len(unvault_pk)

        self.alternate_pk = alternate_pk
        self.spend_delay = spend_delay
        self.recover_pk = recover_pk

        unvaulting = Unvaulting(alternate_pk, spend_delay, recover_pk)

        # supply a ctv_hash in witness; go to an unvaulting output
        # witness: <sig> <out_i> <ctv-hash>
        trigger = (
            "trigger",
            CScript([
                alternate_pk,
                unvaulting.get_taptree(),
                2, OP_ROLL,
                OP_CHECKOUTPUTCONTRACTVERIFY,

                unvault_pk,
                OP_CHECKSIG
            ])
        )

        # witness: <out_i>
        recover = (
            "recover",
            CScript([
                recover_pk,
                OP_0,
                OP_0,
                OP_CHECKOUTPUTCONTRACTVERIFY,
                OP_TRUE
            ])
        )

        super().__init__(alternate_pk, [trigger, recover])


# params:
#  - alternate_pk
#  - spend_delay
#  - recover_pk
# variables:
#  - ctv_hash
# spending conditions:
#  - alternate_pk    => anywhere
#  -                 =>  <recovery> path
#  -                 =>  CTV(withdrawal_tmpl)
class Unvaulting(AugmentedP2TR):
    def __init__(self, alternate_pk: bytes, spend_delay: int, recover_pk: bytes):
        assert len(alternate_pk) == 32 and len(recover_pk) == 32

        self.alternate_pk = alternate_pk
        self.spend_delay = spend_delay
        self.recover_pk = recover_pk

        super().__init__(alternate_pk)

    def get_scripts(self):
        # witness: <ctv_hash>
        withdrawal = (
            "withdrawal",
            CScript([
                OP_DUP,

                # check that the top of the stack is the embedded data
                self.alternate_pk, OP_SWAP,
                OP_CHECKINPUTCONTRACTVERIFY,

                # Check timelock
                self.spend_delay,
                OP_CHECKSEQUENCEVERIFY,
                OP_DROP,

                # Check that the transaction output is as expected
                OP_CHECKTEMPLATEVERIFY
            ])
        )

        # witness: <out_i>
        recover = (
            "recover",
            CScript([
                self.recover_pk,
                OP_0,
                OP_0,
                OP_CHECKOUTPUTCONTRACTVERIFY,
                OP_TRUE
            ])
        )

        return [withdrawal, recover]


class VaultTest(BitcoinTestFramework):
    def set_test_params(self):
        self.num_nodes = 1
        self.extra_args = [
            [
                # Use only one script thread to get the exact reject reason for testing
                "-par=1",
                # TODO: figure out changes to standardness rules
                "-acceptnonstdtxn=1",
            ]
        ]
        self.setup_clean_chain = True

    def run_test(self):
        wallet = MiniWallet(self.nodes[0], mode=MiniWalletMode.RAW_OP_2)
        node = self.nodes[0]
        node.add_p2p_connection(P2PInterface())

        # Generate some matured UTXOs to spend into vaults.
        self.generate(wallet, 200)

        self.vault_test(node, wallet)

    def vault_test(
        self,
        node: TestNode,
        wallet: MiniWallet,
    ):
        assert_equal(node.getmempoolinfo()["size"], 0)

        alternate_pk = NUMS_KEY
        spend_delay = 10
        recover_pk = NUMS_KEY
        unvault_key = key.ECKey()
        unvault_key.set((1).to_bytes(32, 'big'), True)

        vault = Vault(
            alternate_pk,
            spend_delay,
            recover_pk,
            unvault_key.get_pubkey().get_bytes()[1:]  # x-only pubkey
        )

        utxo = wallet.get_utxo()

        txid_in_int = int.from_bytes(bytes.fromhex(utxo['txid']), byteorder='big')
        utxo_in = CTxIn(
            outpoint=COutPoint(txid_in_int, utxo['vout']),
        )

        fees = 10_000
        total_amount_sats = int(utxo["value"] * COIN) - fees

        output = CTxOut(
            nValue=total_amount_sats,
            scriptPubKey=vault.get_tr_info().scriptPubKey
        )

        tx1 = CTransaction()
        tx1.nVersion = 2
        tx1.vin = [utxo_in]
        tx1.vout = [output]

        tx1_txid = self.assert_broadcast_tx(tx1, mine_all=True)

        # Start Unvaulting

        # The final withdrawal destination for the vaulted funds.
        target_amounts = split_vault_value(total_amount_sats)

        def random_key():
            result = key.ECKey()
            result.generate()
            return result

        target_keys = [random_key() for _ in range(len(target_amounts))]

        final_target_vout = [
            CTxOut(nValue=amt - 2*fees, scriptPubKey=make_segwit0_spk(key))
            for amt, key in zip(target_amounts, target_keys)
        ]

        # create trigger tx (Vault ==> Unvaulting)
        unvaulting = Unvaulting(
            alternate_pk,
            spend_delay,
            recover_pk
        )

        withdraw_template = CTransaction()
        withdraw_template.nVersion = 2
        withdraw_template.vin = [CTxIn(nSequence=spend_delay)]
        withdraw_template.vout = final_target_vout

        target_hash: bytes = withdraw_template.get_standard_template_hash(0)

        tx2 = CTransaction()
        tx2.nVersion = 2
        tx2.vin = [
            CTxIn(
                outpoint=COutPoint(int.from_bytes(bytes.fromhex(tx1_txid), byteorder='big'), 0)
            )
        ]

        tx2.vout = [
            CTxOut(
                nValue=total_amount_sats - 2*fees,
                scriptPubKey=unvaulting.get_tr_info(target_hash).scriptPubKey
            )]

        trigger_leaf_script = vault.get_tr_info().leaves["trigger"].script
        sigmsg = script.TaprootSignatureHash(
            tx2, tx1.vout, input_index=0, hash_type=0, scriptpath=True, script=trigger_leaf_script
        )
        unvault_sig = key.sign_schnorr(unvault_key.get_bytes(), sigmsg)

        tx2.wit.vtxinwit = [CTxInWitness()]
        tx2.wit.vtxinwit[0].scriptWitness.stack = [
            unvault_sig,
            script.bn2vch(0),
            target_hash,
            trigger_leaf_script,
            vault.get_tr_info().controlblock_for_script_spend("trigger"),
        ]

        tx2_txid = self.assert_broadcast_tx(tx2, mine_all=True)

        # Generate enough blocks for the timelock expire
        self.generate(wallet, spend_delay+1)

        # Complete withdrawal

        tx3 = CTransaction()
        tx3.nVersion = 2
        tx3.vin = [
            CTxIn(
                outpoint=COutPoint(int.from_bytes(bytes.fromhex(tx2_txid), byteorder='big'), 0),
                nSequence=spend_delay
            )
        ]

        tx3.vout = withdraw_template.vout

        tx3.wit.vtxinwit = [CTxInWitness()]
        tx3.wit.vtxinwit[0].scriptWitness.stack = [
            target_hash,
            unvaulting.get_tr_info(target_hash).leaves["withdrawal"].script,
            unvaulting.get_tr_info(target_hash).controlblock_for_script_spend("withdrawal"),
        ]

        self.assert_broadcast_tx(tx3, mine_all=True)

    # taken from OP_VAULT PR's functional test
    def assert_broadcast_tx(
        self,
        tx: CTransaction,
        mine_all: bool = False,
        err_msg: Optional[Union[Tuple[str], str]] = None
    ) -> str:
        """
        Broadcast a transaction and facilitate various assertions about how the
        broadcast went.
        """
        node = self.nodes[0]
        txhex = tx.serialize().hex()
        txid = tx.rehash()

        if not err_msg:
            assert_equal(node.sendrawtransaction(txhex), txid)
        else:
            assert_raises_rpc_error(-26, err_msg, node.sendrawtransaction, txhex)

        if mine_all:
            self.generate(node, 1)
            assert_equal(node.getmempoolinfo()["size"], 0)

        return txid


# from OP_VAULT's PR
def split_vault_value(total_val: int, num: int = 3) -> List[int]:
    """
    Return kind-of evenly split amounts that preserve the total value of the vault.
    """
    val_segment = total_val // num
    amts = []
    for _ in range(num - 1):
        amts.append(val_segment)
        total_val -= val_segment
    amts.append(total_val)
    return amts


# from OP_VAULT's PR
def make_segwit0_spk(privkey: key.ECKey) -> CScript:
    return CScript([script.OP_0, script.hash160(privkey.get_pubkey().get_bytes())])


if __name__ == "__main__":
    VaultTest().main()
