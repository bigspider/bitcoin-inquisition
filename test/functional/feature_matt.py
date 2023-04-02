#!/usr/bin/env python3
# Copyright (c) 2023 The Bitcoin Core developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.
"""
Test OP_CHECKINPUTCONTRACTVERIFY and OP_CHECKOUTPUTCONTRACTVERIFY
"""

from typing import Optional, Tuple, Union

from test_framework import script, key
from test_framework.test_framework import BitcoinTestFramework, TestNode
from test_framework.p2p import P2PInterface
from test_framework.wallet import MiniWallet, MiniWalletMode
from test_framework.script import (
    CScript,
    OP_CHECKINPUTCONTRACTVERIFY,
    OP_CHECKOUTPUTCONTRACTVERIFY,
    OP_ROLL,
    OP_SWAP,
    OP_TRUE,
    TaprootInfo,
)
from test_framework.messages import CTransaction, COutPoint, CTxInWitness, CTxOut, CTxIn, COIN
from test_framework.util import assert_equal, assert_raises_rpc_error


# point with provably unknown private key
NUMS_KEY = bytes.fromhex("50929b74c1a04954b78b4b6035e97a5e078a5a0f28ec96d547bfee9ace803ac0")


class P2TR():
    """
    A class representing a Pay-to-Taproot script.
    """
    def __init__(self, internal_pubkey: bytes, scripts):
        assert len(internal_pubkey) == 32

        self.internal_pubkey = internal_pubkey
        self.scripts = scripts
        self.tr_info = script.taproot_construct(internal_pubkey, scripts)

    def get_tr_info(self) -> TaprootInfo:
        return self.tr_info


class AugmentedP2TR():
    """
    An abstract class representing a Pay-to-Taproot script with some embedded data.
    While the exact script can only be produced once the embedded data is known,
    the scripts and the "naked internal key" are decided in advance.
    """
    def __init__(self, naked_internal_pubkey: bytes):
        assert len(naked_internal_pubkey) == 32

        self.naked_internal_pubkey = naked_internal_pubkey

    def get_scripts():
        raise NotImplementedError("This must be implemented in subclasses")

    def get_taptree(self):
        # use dummy data, since it doesn't affect the merkle root
        return self.get_tr_info(b'\0'*32).merkle_root

    def get_tr_info(self, data: bytes):
        assert len(data) == 32

        internal_pubkey, _ = key.tweak_add_pubkey(self.naked_internal_pubkey, data)

        return script.taproot_construct(internal_pubkey, self.get_scripts())


class EmbedData(P2TR):
    """
    An output that can only be spent to a `CompareWithEmbeddedData` output, with
    its embedded data passed as the witness.
    """
    def __init__(self):
        super().__init__(NUMS_KEY, [
            ("forced", CScript([
                    0,  # out_i
                    NUMS_KEY,  # naked output key
                    CompareWithEmbeddedData().get_taptree(),  # output Merkle tree
                    3, OP_ROLL,  # <data>
                    OP_CHECKOUTPUTCONTRACTVERIFY,
                    OP_TRUE
                ]))
        ])


class CompareWithEmbeddedData(AugmentedP2TR):
    """
    An output that can only be spent by passing the embedded data in the witness.
    """

    def __init__(self):
        super().__init__(NUMS_KEY)

    def get_scripts(self):
        return [
            (
                # witness: <data>
                "cicv",
                CScript([
                    NUMS_KEY,
                    OP_SWAP,
                    OP_CHECKINPUTCONTRACTVERIFY,
                    OP_TRUE
                ])
            )
        ]


class MattTest(BitcoinTestFramework):
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

        self.cocv_test(node, wallet)

    def cocv_test(
        self,
        node: TestNode,
        wallet: MiniWallet,
    ):
        assert_equal(node.getmempoolinfo()["size"], 0)

        #            tx1      tx2
        # MiniWallet ==> S ==(data)==> T ==> OP_TRUE
        #    S: tr(NUMS, COCV(T, data))
        #    T: tr(NUMS×data, CICV(data == 0x424242...))

        data = b'\x42'*32

        T = CompareWithEmbeddedData()
        S = EmbedData()

        # Create UTXO for S

        utxo = wallet.get_utxo()
        txid_in_int = int.from_bytes(bytes.fromhex(utxo['txid']), byteorder='big')
        utxo_in = CTxIn(
            outpoint=COutPoint(txid_in_int, utxo['vout']),
        )

        fees = 10_000
        total_amount_sats = int(utxo["value"] * COIN) - fees

        output = CTxOut(
            nValue=total_amount_sats,
            scriptPubKey=S.get_tr_info().scriptPubKey
        )

        tx1 = CTransaction()
        tx1.nVersion = 2
        tx1.vin = [utxo_in]
        tx1.vout = [output]

        tx1_txid = self.assert_broadcast_tx(tx1, mine_all=True)

        # Create UTXO for T

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
                scriptPubKey=T.get_tr_info(data).scriptPubKey
            )]

        tx2.wit.vtxinwit = [CTxInWitness()]
        tx2.wit.vtxinwit[0].scriptWitness.stack = [
            data,
            S.get_tr_info().leaves["forced"].script,
            S.get_tr_info().controlblock_for_script_spend("forced")
        ]

        tx2_txid = self.assert_broadcast_tx(tx2, mine_all=True)

        # spend T
        tx3 = CTransaction()
        tx3.nVersion = 2
        tx3.vin = [
            CTxIn(
                outpoint=COutPoint(int.from_bytes(bytes.fromhex(tx2_txid), byteorder='big'), 0)
            )
        ]
        tx3.vout = [
            CTxOut(
                nValue=total_amount_sats - 3*fees,
                scriptPubKey=P2TR(NUMS_KEY, [("true", CScript([OP_TRUE]))]).tr_info.scriptPubKey
            )]

        tx3.wit.vtxinwit = [CTxInWitness()]
        tx3.wit.vtxinwit[0].scriptWitness.stack = [
            data,
            T.get_tr_info(data).leaves["cicv"].script,
            T.get_tr_info(data).controlblock_for_script_spend("cicv")
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


if __name__ == "__main__":
    MattTest().main()
