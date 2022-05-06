from typing import (
    Optional,
)

from eth_utils import (
    ValidationError,
)

from eth_typing import (
    Address,
)

from rainbow import (
    RainbowCrypto,
)

from eth.abc import (
    BlockHeaderAPI,
    StateAPI,
    SignedTransactionAPI,
    VirtualMachineAPI,
)

from .abc import (
    QauataSignedTransactionAPI,
    QauataStateAPI,
)


def validate_qauata_public_key(value: bytes, address: Address, title: str = "Value") -> None:
    if len(value) != RainbowCrypto.RAINBOW_PUBLICKEYBYTES:
        raise ValidationError(
            f"{title} is not a valid rainbow Ia circumzenithal public key: "
            f"  Must be {RainbowCrypto.RAINBOW_PUBLICKEYBYTES} bytes in length: Got length: {len(value)}"
        )
    if value[:len(address)] != address:
        raise ValidationError(
            f"{title} not matched or address collision:"
            f"  Not matched with address: {address!r}"
        )

def validate_qauata_sig_length(value: bytes, title: str = "Value") -> None:
    if len(value) != RainbowCrypto.RAINBOW_SINATURESBYTES:
        raise ValidationError(
            f"{title} is not a valid rainbow Ia circumzenithal signature: "
            f"  Must be {RainbowCrypto.RAINBOW_SINATURESBYTES} bytes in length:  Got length: {len(value)}"
        )

def validate_qauata_private_key_length(value: bytes, title: str = "Value") -> None:
    if len(value) != RainbowCrypto.RAINBOW_SECRETKEYBYTES:
        raise ValidationError(
            f"{title} is not a valid rainbow Ia circumzenithal private key: "
            f"  Must be {RainbowCrypto.RAINBOW_SECRETKEYBYTES} bytes in length:  Got length: {len(value)}"
        )

def validate_qauata_transaction_vm(state: QauataStateAPI,
                                transaction: QauataSignedTransactionAPI) -> None:
    max_gas_cost = transaction.gas * state.get_gas_price(transaction)
    sender_balance = state.get_balance(transaction.sender)

    if sender_balance < max_gas_cost:
        raise ValidationError(
            f"Sender {transaction.sender!r} cannot afford txn gas "
            f"{max_gas_cost} with account balance {sender_balance}"
        )

    total_cost = transaction.value + max_gas_cost

    if sender_balance < total_cost:
        raise ValidationError(
            f"Sender does not have enough balance to cover transaction value and gas "
            f" (has {sender_balance}, needs {total_cost})"
        )

    sender_nonce = state.get_nonce(transaction.sender)
    if sender_nonce != transaction.nonce:
        raise ValidationError(
            f"Invalid transaction nonce: Expected {sender_nonce}, but got {transaction.nonce}"
        )
    if state.get_code(transaction.sender) == b'' and sender_nonce != 0:
        validate_qauata_public_key(state.get_public_key(transaction.sender), transaction.sender, title="PBK on chain")

def validate_qauata_transaction_signature(state: QauataStateAPI,
                                          transaction: QauataSignedTransactionAPI) -> None:
    message = transaction.get_message_for_signing()
    if state.get_code(transaction.sender) != b'':
        raise ValidationError(
            f"Bad signature: Expected transaction sent from externally owned account"
        )
    sender_public_key = b''
    if transaction.nonce == 0:
        sender_public_key = transaction.data
    else:
        sender_public_key = state.get_public_key(transaction.sender)
    validate_qauata_transaction_signature_logically(transaction, sender_public_key)

def validate_qauata_transaction_signature_logically(transaction: QauataSignedTransactionAPI,
                                                    sender_public_key: Optional[bytes] = None) -> None:
    message = transaction.get_message_for_signing()
    if not sender_public_key:
        if transaction.nonce == 0:
            sender_public_key = transaction.data
        else:
            return None #Validation check implented in VM
    try:
        is_verified = RainbowCrypto.raw_verify(sender_public_key, transaction.sig, message)
    except Exception as e:
        raise ValidationError(
            f"Bad signature: {e}"
        )
    if not is_verified:
        raise ValidationError("Invalid Signature")




def validate_frontier_transaction_against_header(_vm: VirtualMachineAPI,
                                                 base_header: BlockHeaderAPI,
                                                 transaction: SignedTransactionAPI) -> None:
    if base_header.gas_used + transaction.gas > base_header.gas_limit:
        raise ValidationError(
            f"Transaction exceeds gas limit: using {transaction.gas}, "
            f"bringing total to {base_header.gas_used + transaction.gas}, "
            f"but limit is {base_header.gas_limit}"
        )
