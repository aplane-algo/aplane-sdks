# SPDX-License-Identifier: MIT
# Copyright (C) 2026 APlane Project LLC

import pytest

from aplane.algokit import ApsignerAccount, create_apsigner_account, list_apsigner_accounts
from aplane.signer import GroupSignResponse, KeyInfo, SignerError


class MockTxn:
    def __init__(self, sender: str) -> None:
        self.sender = sender


class MockSignerClient:
    def __init__(self) -> None:
        self.sign_calls = []

    def sign_requests(self, requests, *, request_id=None):
        self.sign_calls.append((requests, request_id))
        return GroupSignResponse(signed=["aabb", "ccdd"])

    def list_keys(self, refresh=False):
        return [
            KeyInfo(
                address="ADDR",
                key_type="ed25519",
            )
        ]


def test_account_signer_sends_requested_indexes() -> None:
    client = MockSignerClient()
    account = ApsignerAccount(
        client,
        "SENDER",
        auth_address="AUTH",
        request_id=lambda: "sdk-algokit-test",
        lsig_args={"preimage": b"\x01\x02"},
        encode_transaction=lambda txn: b"TX" + txn.sender.encode(),
    )

    signed = account.signer([MockTxn("1"), MockTxn("2"), MockTxn("3")], [0, 2])

    assert account.addr == "SENDER"
    assert account.auth_address == "AUTH"
    assert signed == [bytes.fromhex("aabb"), bytes.fromhex("ccdd")]
    assert client.sign_calls == [
        (
            [
                {
                    "txn_bytes_hex": "545831",
                    "txn_sender": "1",
                    "auth_address": "AUTH",
                    "lsig_args": {"preimage": "0102"},
                },
                {
                    "txn_bytes_hex": "545833",
                    "txn_sender": "3",
                    "auth_address": "AUTH",
                    "lsig_args": {"preimage": "0102"},
                },
            ],
            "sdk-algokit-test",
        )
    ]


def test_list_apsigner_accounts() -> None:
    client = MockSignerClient()
    accounts = list_apsigner_accounts(client, refresh=True)

    assert len(accounts) == 1
    assert accounts[0].addr == "ADDR"
    assert accounts[0].auth_address == "ADDR"


def test_create_apsigner_account() -> None:
    client = MockSignerClient()
    account = create_apsigner_account(
        client,
        "ADDR",
        encode_transaction=lambda _txn: b"TX",
    )

    assert account.addr == "ADDR"
    assert callable(account.signer)


def test_rejects_reshaped_signer_response() -> None:
    class ReshapingClient(MockSignerClient):
        def sign_requests(self, requests, *, request_id=None):
            self.sign_calls.append((requests, request_id))
            return GroupSignResponse(signed=["aabb", "ccdd"])

    account = ApsignerAccount(
        ReshapingClient(),
        "ADDR",
        encode_transaction=lambda _txn: b"TX",
    )

    with pytest.raises(SignerError, match="different number"):
        account.signer([MockTxn("ADDR")], [0])
