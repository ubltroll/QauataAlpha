from functools import partial
from typing import (
    Tuple,
    cast,
)
from eth_hash.auto import keccak
from eth_typing import (
    Address,
    Hash32,
)
import rlp
from rlp.sedes import (
    big_endian_int,
    binary,
)

from eth.rlp.sedes import address

from eth.abc import (
    ReceiptAPI,
    TransactionBuilderAPI,
)
from eth.constants import (
    CREATE_CONTRACT_ADDRESS,
    GAS_TX,
    GAS_TXDATAZERO,
    GAS_TXDATANONZERO,
)
from eth.validation import (
    validate_uint256,
    validate_is_integer,
    validate_is_bytes,
    validate_lt_secpk1n,
    validate_lte,
    validate_gte,
    validate_canonical_address,
)

from eth.rlp.logs import Log
from eth.rlp.receipts import Receipt
from eth.rlp.transactions import (
    SignedTransactionMethods,
    BaseUnsignedTransaction,
    BaseTransactionMethods,
)

from .abc import (
    QauataTransactionFieldsAPI,
    QauataSignedTransactionAPI,
    QauataUnsignedTransactionAPI,
)

from .validation import (
    validate_data_before_keystore,
    validate_qauata_sig_length,
    validate_qauata_public_key,
    validate_qauata_transaction_signature,
    validate_qauata_transaction_signature_logically,
)

from .utils import (
    create_transaction_signature,
    calculate_intrinsic_gas,
)


HEISENBERG_TX_GAS_SCHEDULE = {
    'gas_tx':GAS_TX,
    'gas_tx_create':0,
    'gas_tx_keystore_force':1888888,
    'gas_txdata_zero':GAS_TXDATAZERO,
    'gas_txdata_nonzero':GAS_TXDATANONZERO,
}


qauata_get_intrinsic_gas = partial(calculate_intrinsic_gas, HEISENBERG_TX_GAS_SCHEDULE)


QAUATA_UNSIGNED_TRANSACTION_FIELDS = [
    ('nonce', big_endian_int),
    ('gas_price', big_endian_int),
    ('gas', big_endian_int),
    ('to', address),
    ('value', big_endian_int),
    ('chain_id', big_endian_int),
    ('data', binary),
]

QAUATA_TRANSACTION_FIELDS = [
    ('nonce', big_endian_int),
    ('gas_price', big_endian_int),
    ('gas', big_endian_int),
    ('from', address),
    ('to', address),
    ('value', big_endian_int),
    ('chain_id', big_endian_int),
    ('data', binary),
    ('sig', binary),
]



class QauataBaseTransaction(
        rlp.Serializable,
        QauataTransactionFieldsAPI,
        TransactionBuilderAPI):
    # "Legacy" transactions implemented by BaseTransaction are a combination of
    # the transaction codec (TransactionBuilderAPI) *and* the transaction
    # object (SignedTransactionAPI). In a multi-transaction-type world, that
    # becomes less desirable, and that responsibility splits up. See Berlin
    # transactions, for example.

    # Note that it includes at least one legacy field (v) that is not
    # explicitly accessible in new transaction types. See the v docstring in
    # LegacyTransactionFieldsAPI for more.

    # this is duplicated to make the rlp library happy, otherwise it complains
    # about no fields being defined but inheriting from multiple `Serializable`
    # bases.
    fields = QAUATA_TRANSACTION_FIELDS

    @classmethod
    def decode(cls, encoded: bytes) -> QauataSignedTransactionAPI:
        return rlp.decode(encoded, sedes=cls)

    def encode(self) -> bytes:
        return rlp.encode(self)

    @property
    def hash(self) -> Hash32:
        return cast(Hash32, keccak(rlp.encode(self)))

class HeisenbergTransaction(QauataBaseTransaction, QauataSignedTransactionAPI):
    fields = QAUATA_TRANSACTION_FIELDS

    def validate(self) -> None:
        validate_uint256(self.nonce, title="Transaction.nonce")
        validate_uint256(self.gas_price, title="Transaction.gas_price")
        validate_uint256(self.gas, title="Transaction.gas")
        if self.to != CREATE_CONTRACT_ADDRESS:
            validate_canonical_address(self.to, title="Transaction.to")
        validate_uint256(self.value, title="Transaction.value")
        validate_is_bytes(self.data, title="Transaction.data")
        validate_is_bytes(self.sig, title="Transaction.sig")
        validate_qauata_sig_length(self.sig, title="Transaction.sig")
        if self.nonce == 0:
            validate_qauata_public_key(self.data, self.sender, title="Transaction.data")

    def check_signature_validity(self) -> None:
        validate_qauata_transaction_signature_logically(self)

    def get_sender(self) -> Address:
        return getattr(self, "from")

    @property
    def sender(self) -> Address:
        return self.get_sender()

    def get_intrinsic_gas(self) -> int:
        return qauata_get_intrinsic_gas(self)

    @property
    def intrinsic_gas(self) -> Address:
        return self.get_intrinsic_gas()

    @property
    def access_list(self):
        return []

    def gas_used_by(self, computation):
        return self.get_intrinsic_gas() + computation.get_gas_used()

    def get_message_for_signing(self) -> bytes:
        kwargs = {
            "nonce": self.nonce,
            "gas_price": self.gas_price,
            "gas": self.gas,
            "to": self.to,
            "value": self.value,
            "chain_id": self.chain_id,
            "data": self.data,
        }
        return rlp.encode(HeisenbergUnsignedTransaction(**kwargs))

    @property
    def is_signature_valid(self) -> bool:
        try:
            self.check_signature_validity()
        except ValidationError:
            return False
        else:
            return True

    @classmethod
    def create_unsigned_transaction(cls,
                                    *,
                                    nonce: int,
                                    gas_price: int,
                                    gas: int,
                                    to: Address,
                                    value: int,
                                    chain_id: int,
                                    data: bytes) -> 'HeisenbergUnsignedTransaction':
        return HeisenbergUnsignedTransaction(nonce, gas_price, gas, to, value, chain_id, data)

    @classmethod
    def new_transaction(
            cls,
            nonce: int,
            gas_price: int,
            gas: int,
            from_: Address,
            to: Address,
            value: int,
            chain_id: int,
            data: bytes,
            sig: bytes) -> QauataSignedTransactionAPI:
        if nonce == 0:
            validate_qauata_public_key(data, from_, 'Transaction.data')
        return cls(nonce, gas_price, gas, from_, to, value, chain_id, data, sig)

    def make_receipt(
            self,
            status: bytes,
            gas_used: int,
            log_entries: Tuple[Tuple[bytes, Tuple[int, ...], bytes], ...]) -> ReceiptAPI:
        # 'status' is a misnomer in ETH-Frontier. Until Byzantium, it is the
        # intermediate state root.

        logs = [
            Log(address, topics, data)
            for address, topics, data
            in log_entries
        ]

        return Receipt(
            state_root=status,
            gas_used=gas_used,
            logs=logs,
        )

    # Transactions are treated as setting both max-fees as the gas price
    @property
    def max_priority_fee_per_gas(self) -> int:
        return self.gas_price

    @property
    def max_fee_per_gas(self) -> int:
        return self.gas_price


class BaseUnsignedTransaction(BaseTransactionMethods, rlp.Serializable, QauataUnsignedTransactionAPI):
    fields = QAUATA_UNSIGNED_TRANSACTION_FIELDS


class HeisenbergUnsignedTransaction(BaseUnsignedTransaction):

    def validate(self) -> None:
        validate_uint256(self.nonce, title="Transaction.nonce")
        validate_is_integer(self.gas_price, title="Transaction.gas_price")
        validate_uint256(self.gas, title="Transaction.gas")
        if self.to != CREATE_CONTRACT_ADDRESS:
            validate_canonical_address(self.to, title="Transaction.to")
        validate_uint256(self.value, title="Transaction.value")
        validate_is_bytes(self.data, title="Transaction.data")
        super().validate()

    def as_signed_transaction(self, chain_id: int, crypto_engine: bytes) -> HeisenbergTransaction:
        if self.nonce == 0:
            validate_data_before_keystore(self.data, crypto_engine.canonical_address, 'Transaction.data')
        sig = create_transaction_signature(self, crypto_engine)
        kwargs = {
            "nonce": self.nonce,
            "gas_price": self.gas_price,
            "gas": self.gas,
            "from": crypto_engine.canonical_address,
            "to": self.to,
            "value": self.value,
            "chain_id": chain_id,
            "data": self.data,
            "sig": sig,
        }
        return HeisenbergTransaction(**kwargs)

    def get_intrinsic_gas(self) -> int:
        return qauata_get_intrinsic_gas(self)

    # Transactions are treated as setting both max-fees as the gas price
    @property
    def max_priority_fee_per_gas(self) -> int:
        return self.gas_price

    @property
    def max_fee_per_gas(self) -> int:
        return self.gas_price
