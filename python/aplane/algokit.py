# SPDX-License-Identifier: MIT
# Copyright (C) 2026 APlane Project LLC

"""AlgoKit Utils adapter for apsigner-backed transaction signing."""

from collections.abc import Callable, Sequence
from typing import Any, Optional, Protocol

from .signer import GroupSignResponse, KeyInfo, SignerError


class _GroupSignerClient(Protocol):
    def sign_requests(
        self,
        requests: list[dict[str, Any]],
        *,
        request_id: Optional[str] = None,
    ) -> GroupSignResponse: ...

    def list_keys(self, refresh: bool = False) -> list[KeyInfo]: ...


TransactionEncoder = Callable[[Any], bytes]
RequestIDFactory = Callable[[], str]


def _default_encode_transaction(txn: Any) -> bytes:
    try:
        from algokit_transact.codec.transaction import encode_transaction
    except ImportError as exc:
        raise SignerError(
            "AlgoKit transaction encoder not found; install algokit-utils with algokit_transact"
        ) from exc
    return encode_transaction(txn)


def _txn_sender(txn: Any) -> str:
    sender = getattr(txn, "sender", None)
    if sender is None:
        raise SignerError("AlgoKit transaction is missing sender")
    return str(sender)


class ApsignerAccount:
    """
    AlgoKit AddressWithTransactionSigner adapter backed by apsigner.

    The adapter signs the transaction indexes AlgoKit asks it to sign. It does
    not reshape the transaction group; Falcon or LogicSig flows that require
    dummy insertion should use APlane's native plan/sign APIs before handing a
    group to AlgoKit.
    """

    def __init__(
        self,
        client: _GroupSignerClient,
        address: str,
        *,
        auth_address: Optional[str] = None,
        lsig_args: Optional[dict[str, bytes]] = None,
        request_id: Optional[str | RequestIDFactory] = None,
        encode_transaction: Optional[TransactionEncoder] = None,
    ) -> None:
        self._client = client
        self._addr = address
        self.auth_address = auth_address or address
        self._lsig_args = lsig_args
        self._request_id = request_id
        self._encode_transaction = encode_transaction or _default_encode_transaction

    @property
    def addr(self) -> str:
        return self._addr

    @property
    def signer(self) -> Callable[[Sequence[Any], Sequence[int]], list[bytes]]:
        return self._sign

    def _next_request_id(self) -> Optional[str]:
        if callable(self._request_id):
            return self._request_id()
        return self._request_id

    def _sign(self, txn_group: Sequence[Any], indexes_to_sign: Sequence[int]) -> list[bytes]:
        if not indexes_to_sign:
            return []

        requests: list[dict[str, Any]] = []
        for index in indexes_to_sign:
            if index < 0 or index >= len(txn_group):
                raise SignerError(f"index {index} out of range for {len(txn_group)} transactions")

            txn = txn_group[index]
            if txn is None:
                raise SignerError(f"transaction is required at index {index}")

            req = {
                "txn_bytes_hex": self._encode_transaction(txn).hex(),
                "txn_sender": _txn_sender(txn),
                "auth_address": self.auth_address,
            }
            if self._lsig_args:
                req["lsig_args"] = {
                    name: value.hex()
                    for name, value in self._lsig_args.items()
                }
            requests.append(req)

        result = self._client.sign_requests(requests, request_id=self._next_request_id())

        if len(result.signed) != len(indexes_to_sign):
            raise SignerError(
                "apsigner returned a different number of signed transactions than AlgoKit requested"
            )

        return [bytes.fromhex(item) for item in result.signed]


def create_apsigner_account(
    client: _GroupSignerClient,
    address: str,
    **kwargs: Any,
) -> ApsignerAccount:
    return ApsignerAccount(client, address, **kwargs)


def list_apsigner_accounts(
    client: _GroupSignerClient,
    *,
    refresh: bool = False,
) -> list[ApsignerAccount]:
    return [
        ApsignerAccount(client, key.address, auth_address=key.address)
        for key in client.list_keys(refresh=refresh)
    ]
