#!/usr/bin/env python3

import os

from algokit_utils import AlgoAmount, AlgorandClient, PaymentParams
from aplane import SignerClient
from aplane.algokit import create_apsigner_account


sender = os.environ["APLANE_ADDRESS"]
algorand = AlgorandClient.testnet()

with SignerClient.from_env() as signer:
    auth = algorand.client.algod.account_information(sender).auth_addr or sender
    account = create_apsigner_account(signer, sender, auth_address=auth)
    txn = algorand.create_transaction.payment(
        PaymentParams(
            sender=sender,
            signer=account,
            receiver=sender,
            amount=AlgoAmount(micro_algo=0),
            validity_window=1000,
        )
    )
    signed = account.signer([txn], [0])
    print(algorand.client.algod.send_raw_transaction(signed).tx_id)
