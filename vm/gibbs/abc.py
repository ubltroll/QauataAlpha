from abc import (
    ABC,
    abstractmethod
)

from typing import (
    Any,
    Dict,
    Optional,
    Tuple,
    Hashable,
)

from eth_typing import (
    Address,
    Hash32,
)

from eth.abc import (
    StateAPI,
    TransactionDecoderAPI,
)

class GibbsTransactionFieldsAPI(ABC):
    """
    A class to define all common transaction fields.
    """
    @property
    @abstractmethod
    def nonce(self) -> int:
        ...

    @property
    @abstractmethod
    def gas_price(self) -> int:
        """
        Will raise :class:`AttributeError` if get or set on a 1559 transaction.
        """
        ...

    @property
    @abstractmethod
    def gas(self) -> int:
        ...

    @property
    @abstractmethod
    def type(self) -> int:
        """
        Types: 0x0 -> Normal Transaction (Legacy), 0x17(23) -> Key-store Transaction
        """
        ...

    @property
    @abstractmethod
    def to(self) -> Address:
        ...

    @property
    @abstractmethod
    def value(self) -> int:
        ...

    @property
    @abstractmethod
    def data(self) -> bytes:
        ...

    @property
    @abstractmethod
    def sig(self) -> int:
        ...

    @property
    @abstractmethod
    def hash(self) -> Hash32:
        """
        Return the hash of the transaction.
        """
        ...

    @property
    @abstractmethod
    def chain_id(self) -> int:
        ...

class BaseTransactionAPI(ABC):
    """
    A class to define all common methods of a transaction.
    """
    @abstractmethod
    def validate(self) -> None:
        """
        Hook called during instantiation to ensure that all transaction
        parameters pass validation rules.
        """
        ...

    @property
    @abstractmethod
    def intrinsic_gas(self) -> int:
        """
        Convenience property for the return value of `get_intrinsic_gas`
        """
        ...

    @abstractmethod
    def get_intrinsic_gas(self) -> int:
        """
        Return the intrinsic gas for the transaction which is defined as the amount of gas that
        is needed before any code runs.
        """
        ...

    @abstractmethod
    def gas_used_by(self, computation: 'ComputationAPI') -> int:
        """
        Return the gas used by the given computation. In Frontier,
        for example, this is sum of the intrinsic cost and the gas used
        during computation.
        """
        ...



class GibbsUnsignedTransactionAPI(BaseTransactionAPI):

    """
    A class representing a transaction before it is signed.
    """
    type:int
    nonce: int
    gas_price: int
    gas: int
    to: Address
    value: int
    data: bytes

    #
    # API that must be implemented by all Transaction subclasses.
    #
    @abstractmethod
    def as_signed_transaction(self, crypto_engine: 'RainbowCrypto') -> 'GibbsSignedTransactionAPI':
        """
        Return a version of this transaction which has been signed using the
        provided `private_key`
        """
        ...

class GibbsSignedTransactionAPI(BaseTransactionAPI, GibbsTransactionFieldsAPI):

    def __init__(self, *args: Any, **kwargs: Any) -> None:
        ...

    """
    A class representing a transaction that was signed with a private key.
    """
    @property
    @abstractmethod
    def sender(self) -> Address:
        """
        Convenience and performance property for the return value of `get_sender`
        """
        ...

    type_id: Optional[int]
    """
    The type of EIP-2718 transaction

    Each EIP-2718 transaction includes a type id (which is the leading
    byte, as encoded).

    If this transaction is a legacy transaction, that it has no type. Then,
    type_id will be None.
    """

    # +-------------------------------------------------------------+
    # | API that must be implemented by all Transaction subclasses. |
    # +-------------------------------------------------------------+

    #
    # Validation
    #
    @abstractmethod
    def validate(self) -> None:
        """
        Hook called during instantiation to ensure that all transaction
        parameters pass validation rules.
        """

        ...

    #
    # Signature and Sender
    #
    @property
    @abstractmethod
    def is_signature_valid(self) -> bool:
        """
        Return ``True`` if the signature is valid, otherwise ``False``.
        """
        ...

    @abstractmethod
    def check_signature_validity(self) -> None:
        """
        Check if the signature is valid. Raise a ``ValidationError`` if the signature
        is invalid.
        """
        ...

    @abstractmethod
    def get_sender(self) -> Address:
        """
        Get the 20-byte address which sent this transaction.

        This can be a slow operation. ``transaction.sender`` is always preferred.
        """
        ...

    #
    # Conversion to and creation of unsigned transactions.
    #
    @abstractmethod
    def get_message_for_signing(self) -> bytes:
        """
        Return the bytestring that should be signed in order to create a signed transaction.
        """
        ...

    # We can remove this API and inherit from rlp.Serializable when it becomes typesafe
    def as_dict(self) -> Dict[Hashable, Any]:
        """
        Return a dictionary representation of the transaction.
        """
        ...

    @abstractmethod
    def make_receipt(
            self,
            status: bytes,
            gas_used: int,
            log_entries: Tuple[Tuple[bytes, Tuple[int, ...], bytes], ...]) -> 'ReceiptAPI':
        """
        Build a receipt for this transaction.

        Transactions have this responsibility because there are different types
        of transactions, which have different types of receipts. (See
        access-list transactions, which change the receipt encoding)

        :param status: success or failure (used to be the state root after execution)
        :param gas_used: cumulative usage of this transaction and the previous
            ones in the header
        :param log_entries: logs generated during execution
        """
        ...

    @abstractmethod
    def encode(self) -> bytes:
        """
        This encodes a transaction, no matter if it's: a legacy transaction, a
        typed transaction, or the payload of a typed transaction. See more
        context in decode.
        """
        ...

class GibbsTransactionBuilderAPI(TransactionDecoderAPI):
    """
    Responsible for creating and encoding transactions.

    Most simply, the builder is responsible for some pieces of the encoding for
    RLP. In legacy transactions, this happens using rlp.Serializeable. It is
    also responsible for initializing the transactions. The two transaction
    initializers assume legacy transactions, for now.

    Some VMs support multiple distinct transaction types. In that case, the
    builder is responsible for dispatching on the different types.
    """

    @classmethod
    @abstractmethod
    def deserialize(cls, encoded: 'DecodedZeroOrOneLayerRLP') -> 'GibbsSignedTransactionAPI':
        """
        Extract a transaction from an encoded RLP object.

        This method is used by rlp.decode(..., sedes=TransactionBuilderAPI).
        """
        ...

    @classmethod
    @abstractmethod
    def serialize(cls, obj: 'GibbsSignedTransactionAPI') -> 'DecodedZeroOrOneLayerRLP':
        """
        Encode a transaction to a series of bytes used by RLP.

        In the case of legacy transactions, it will actually be a list of
        bytes. That doesn't show up here, because pyrlp doesn't export type
        annotations.

        This method is used by rlp.encode(obj).
        """
        ...

    @classmethod
    @abstractmethod
    def create_unsigned_transaction(cls,
                                    *,
                                    type: int,
                                    nonce: int,
                                    gas_price: int,
                                    gas: int,
                                    to: Address,
                                    value: int,
                                    data: bytes) -> 'GibbsUnsignedTransactionAPI':
        """
        Create an unsigned transaction.
        """
        ...

    @classmethod
    @abstractmethod
    def new_transaction(
            cls,
            nonce: int,
            gas_price: int,
            gas: int,
            from_: Address,
            to: Address,
            value: int,
            data: bytes,
            sig: bytes) -> 'GibbsSignedTransactionAPI':
        """
        Create a signed transaction.
        """
        ...


class GibbsStateAPI(StateAPI):
    @property
    @abstractmethod
    def get_public_key(self, address: Address) -> bytes:
        """
        Return the public key.
        """
        ...
