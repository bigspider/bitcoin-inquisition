#!/usr/bin/env python3
# Copyright (c) 2023 The Bitcoin Core developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.
"""
Test OP_CHECKINPUTCONTRACTVERIFY and OP_CHECKOUTPUTCONTRACTVERIFY
"""

from typing import List, Optional, Tuple, Union

from test_framework import script, key
from test_framework.test_framework import BitcoinTestFramework, TestNode
from test_framework.p2p import P2PInterface
from test_framework.wallet import MiniWallet, MiniWalletMode
from test_framework.script import (
    CScript,
    OP_CHECKCONTRACTVERIFY,
    OP_TRUE,
    TaprootInfo,
)
from test_framework.messages import CTransaction, COutPoint, CTxInWitness, CTxOut, CTxIn, COIN
from test_framework.util import assert_equal, assert_raises_rpc_error

# Flags for OP_CHECKCONTRACTVERIFY
CCV_FLAG_CHECK_INPUT: int = 1
CCV_FLAG_IGNORE_OUTPUT_AMOUNT: int = 2


# point with provably unknown private key
NUMS_KEY: bytes = bytes.fromhex("50929b74c1a04954b78b4b6035e97a5e078a5a0f28ec96d547bfee9ace803ac0")


class P2TR:
    """
    A class representing a Pay-to-Taproot script.
    """

    def __init__(self, internal_pubkey: bytes, scripts: List[Tuple[str, CScript]]):
        assert len(internal_pubkey) == 32

        self.internal_pubkey = internal_pubkey
        self.scripts = scripts
        self.tr_info = script.taproot_construct(internal_pubkey, scripts)

    def get_tr_info(self) -> TaprootInfo:
        return self.tr_info

    def get_tx_out(self, value: int) -> CTxOut:
        return CTxOut(
            nValue=value,
            scriptPubKey=self.get_tr_info().scriptPubKey
        )


class AugmentedP2TR:
    """
    An abstract class representing a Pay-to-Taproot script with some embedded data.
    While the exact script can only be produced once the embedded data is known,
    the scripts and the "naked internal key" are decided in advance.
    """

    def __init__(self, naked_internal_pubkey: bytes):
        assert len(naked_internal_pubkey) == 32

        self.naked_internal_pubkey = naked_internal_pubkey

    def get_scripts(self) -> List[Tuple[str, CScript]]:
        raise NotImplementedError("This must be implemented in subclasses")

    def get_taptree(self) -> bytes:
        # use dummy data, since it doesn't affect the merkle root
        return self.get_tr_info(b'\0'*32).merkle_root

    def get_tr_info(self, data: bytes) -> TaprootInfo:
        assert len(data) == 32

        internal_pubkey, _ = key.tweak_add_pubkey(self.naked_internal_pubkey, data)

        return script.taproot_construct(internal_pubkey, self.get_scripts())

    def get_tx_out(self, value: int, data: bytes) -> CTxOut:
        return CTxOut(nValue=value, scriptPubKey=self.get_tr_info(data).scriptPubKey)


class EmbedData(P2TR):
    """
    An output that can only be spent to a `CompareWithEmbeddedData` output, with
    its embedded data passed as the witness.
    """

    def __init__(self, ignore_amount: bool = False):
        super().__init__(NUMS_KEY, [
            ("forced", CScript([
                    # witness: <data>
                    0,  # index
                    0,  # use NUMS as the naked pubkey
                    CompareWithEmbeddedData().get_taptree(),  # output Merkle tree
                    CCV_FLAG_IGNORE_OUTPUT_AMOUNT if ignore_amount else 0,  # flags
                    OP_CHECKCONTRACTVERIFY,
                    OP_TRUE
                ]))
        ])


class CompareWithEmbeddedData(AugmentedP2TR):
    """
    An output that can only be spent by passing the embedded data in the witness.
    """

    def __init__(self):
        super().__init__(NUMS_KEY)

    def get_scripts(self) -> List[Tuple[str, CScript]]:
        return [
            (
                "check_data",
                CScript([
                    # witness: <data>
                    -1,  # index: check current input
                    0,   # use NUMS as the naked pubkey
                    -1,  # use taptree of the current input
                    CCV_FLAG_CHECK_INPUT,  # flag: check input
                    OP_CHECKCONTRACTVERIFY,
                    OP_TRUE
                ]))
        ]


class SendToSelf(P2TR):
    """
    A utxo that can only be spent by sending the entire amount to the same script.
    The output index must match the input index.
    """

    def __init__(self):
        super().__init__(NUMS_KEY, [
            ("send_to_self", CScript([
                    # witness: <>
                    0,   # no data tweaking
                    -1,  # index: check current output
                    -1,  # use internal key of the current input
                    -1,  # use taptree of the current input
                    0,   # flag: check output, preserve amount
                    OP_CHECKCONTRACTVERIFY,
                    OP_TRUE
                ]))
        ])


class CheckContractVerifyTest(BitcoinTestFramework):
    def set_test_params(self):
        self.num_nodes = 1
        self.extra_args = [
            [
                # Use only one script thread to get the exact reject reason for testing
                "-par=1",
                # TODO: figure out changes to standardness rules
                "-acceptnonstdtxn=1",
                # TODO: remove when package relay submission becomes a thing.
                "-minrelaytxfee=0",
                "-blockmintxfee=0",
            ]
        ]
        self.setup_clean_chain = True

    def run_test(self):
        wallet = MiniWallet(self.nodes[0], mode=MiniWalletMode.RAW_OP_2)
        node = self.nodes[0]
        node.add_p2p_connection(P2PInterface())

        # Generate some matured UTXOs to spend into vaults.
        self.generate(wallet, 200)

        self.test_ccv(node, wallet, ignore_amount=True)
        self.test_ccv(node, wallet, ignore_amount=False)
        self.test_many_to_one(node, wallet)
        self.test_send_to_self(node, wallet)

    def test_ccv(
        self,
        node: TestNode,
        wallet: MiniWallet,
        ignore_amount: bool
    ):
        assert_equal(node.getmempoolinfo()["size"], 0)

        #            tx1      tx2
        # MiniWallet ==> S ==(data)==> T ==> OP_TRUE
        #    S: tr(NUMS, CheckOutputContract(T, data))
        #    T: tr(NUMS×data, CheckInputContract(data == 0x424242...))

        data = b'\x42'*32

        T = CompareWithEmbeddedData()
        S = EmbedData(ignore_amount=ignore_amount)

        # Create UTXO for S

        # If ignoring amount, the contract value (if any) can be used to pay for fees
        # otherwise, we put 0 fees for the sake of the tests.
        # In practice, package relay would likely be used to manage fees, when ready.
        amount_sats = 100000
        fees = 1000 if ignore_amount else 0

        (tx1_txid, tx1_n) = wallet.send_to(
            from_node=node,
            scriptPubKey=S.get_tr_info().scriptPubKey,
            amount=amount_sats
        )

        # Create UTXO for T

        tx2 = CTransaction()
        tx2.nVersion = 2
        tx2.vin = [
            CTxIn(
                outpoint=COutPoint(int(tx1_txid, 16), tx1_n)
            )
        ]
        tx2.vout = [T.get_tx_out(amount_sats - fees, data)]
        tx2.wit.vtxinwit = [CTxInWitness()]
        tx2.wit.vtxinwit[0].scriptWitness.stack = [
            data,
            S.get_tr_info().leaves["forced"].script,
            S.get_tr_info().controlblock_for_script_spend("forced")
        ]

        if not ignore_amount:
            # broadcast with insufficient output amount; this should fail
            tx2.vout[0].nValue -= 1
            self.assert_broadcast_tx(tx2, err_msg='ccv-insufficient-output-value')
            tx2.vout[0].nValue += 1

        tx2_txid = self.assert_broadcast_tx(tx2, mine_all=True)

        # spend T
        tx3 = CTransaction()
        tx3.nVersion = 2
        tx3.vin = [
            CTxIn(
                outpoint=COutPoint(int(tx2_txid, 16), 0)
            )
        ]
        tx3.vout = [
            CTxOut(
                nValue=amount_sats - 2 * fees,
                scriptPubKey=P2TR(NUMS_KEY, [("true", CScript([OP_TRUE]))]).tr_info.scriptPubKey
            )]

        tx3.wit.vtxinwit = [CTxInWitness()]

        # Broadcasting with incorrect data should fail
        tx3.wit.vtxinwit[0].scriptWitness.stack = [
            b'\x43'*32,  # different than data
            T.get_tr_info(data).leaves["check_data"].script,
            T.get_tr_info(data).controlblock_for_script_spend("check_data")
        ]

        # Broadcasting with correct data succeeds
        self.assert_broadcast_tx(tx3, err_msg="Mismatching contract data or program")

        tx3.wit.vtxinwit[0].scriptWitness.stack = [
            data,
            T.get_tr_info(data).leaves["check_data"].script,
            T.get_tr_info(data).controlblock_for_script_spend("check_data")
        ]

        self.assert_broadcast_tx(tx3, mine_all=True)

    def test_many_to_one(
        self,
        node: TestNode,
        wallet: MiniWallet
    ):
        assert_equal(node.getmempoolinfo()["size"], 0)

        # Creates 3 utxos with different amounts and all with the same EmbedData script.
        # Spending them together to a single output, the total amount must be preserved.

        #               tx1,tx2,tx3       tx4
        # MiniWallet ==> S1, S2, S3 ==> T ==> OP_TRUE
        #   S1: tr(NUMS, CheckOutputContract(T, data))
        #   S2: tr(NUMS, CheckOutputContract(T, data))
        #   S3: tr(NUMS, CheckOutputContract(T, data))
        #   T: tr(NUMS×data, CheckInputContract(data == 0x424242...))

        data = b'\x42'*32
        amounts_sats: List[int] = []

        T = CompareWithEmbeddedData()
        S = EmbedData()

        tx_ids_and_n: List[Tuple[str, int]] = []
        for i in range(3):
            # Create UTXO for S[i]
            amount_sats = 100000 * (i + 1)
            amounts_sats.append(amount_sats)

            tx_ids_and_n.append(wallet.send_to(
                from_node=node,
                scriptPubKey=S.get_tr_info().scriptPubKey,
                amount=amount_sats
            ))

        # Create UTXO for T
        tx4 = CTransaction()
        tx4.nVersion = 2
        tx4.vin = [
            CTxIn(
                outpoint=COutPoint(
                    int(tx_ids_and_n[i][0], 16),
                    tx_ids_and_n[i][1]
                )
            ) for i in range(3)
        ]
        tx4.vout = [T.get_tx_out(sum(amounts_sats), data)]
        tx4.wit.vtxinwit = [CTxInWitness()] * 3
        for i in range(3):
            tx4.wit.vtxinwit[i].scriptWitness.stack = [
                data,
                S.get_tr_info().leaves["forced"].script,
                S.get_tr_info().controlblock_for_script_spend("forced")
            ]

        # broadcast with insufficient output amount; this should fail
        tx4.vout[0].nValue -= 1
        self.assert_broadcast_tx(tx4, err_msg='ccv-insufficient-output-value')
        tx4.vout[0].nValue += 1

        # correct amount succeeds
        self.assert_broadcast_tx(tx4, mine_all=True)

    def test_send_to_self(
        self,
        node: TestNode,
        wallet: MiniWallet
    ):
        assert_equal(node.getmempoolinfo()["size"], 0)

        # Creates a utxo with the SendToSelf contract, and verifies that:
        # - sending to a different scriptPubKey fails;
        # - sending to an output with the same scriptPubKey works.

        amount_sats = 10000

        C = SendToSelf()

        (tx_id, n) = wallet.send_to(
            from_node=node,
            scriptPubKey=C.get_tr_info().scriptPubKey,
            amount=amount_sats
        )

        # Create UTXO for C
        tx2 = CTransaction()
        tx2.nVersion = 2
        tx2.vin = [
            CTxIn(
                outpoint=COutPoint(int(tx_id, 16), n)
            )
        ]
        tx2.vout = [C.get_tx_out(amount_sats)]
        tx2.wit.vtxinwit = [CTxInWitness()]
        tx2.wit.vtxinwit[0].scriptWitness.stack = [
            C.get_tr_info().leaves["send_to_self"].script,
            C.get_tr_info().controlblock_for_script_spend("send_to_self")
        ]

        # broadcast with insufficient output amount; this should fail
        tx2.vout[0].nValue -= 1
        self.assert_broadcast_tx(tx2, err_msg='ccv-insufficient-output-value')
        tx2.vout[0].nValue += 1

        # broadcast with incorrect output script; this should fail
        correct_script = tx2.vout[0].scriptPubKey
        tx2.vout[0].scriptPubKey = correct_script[:-1] + bytes([correct_script[-1] ^ 1])
        self.assert_broadcast_tx(tx2, err_msg="Mismatching contract data or program")
        tx2.vout[0].scriptPubKey = correct_script

        # correct amount succeeds
        self.assert_broadcast_tx(tx2, mine_all=True)

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
    CheckContractVerifyTest().main()
