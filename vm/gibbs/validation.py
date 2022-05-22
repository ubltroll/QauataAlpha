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
    GibbsSignedTransactionAPI,
    GibbsStateAPI,
)

from .constants import (
    GIBBS_GAS_LIMIT_MINIMUM,
    GIBBS_GAS_LIMIT_MAXIMUM,
    GIBBS_GAS_LIMIT_ADJUSTMENT_FACTOR,
)

def validate_qauata_public_key(value: bytes, address: Address, title: str = "Value") -> None:
    if len(value) != RainbowCrypto.RAINBOW_PUBLICKEYBYTES:
        raise ValidationError(
            f"{title} is not a valid rainbow Ia circumzenithal public key: "
            "First transaction must be a keystore transaction: "
            f"  Must be {RainbowCrypto.RAINBOW_PUBLICKEYBYTES} bytes in length: Got length: {len(value)}"
        )
    if value[:len(address)] != address:
        raise ValidationError(
            f"{title} not matched or address collision:"
            f"  Not matched with address: {address!r}"
        )

def validate_data_before_keystore(value: bytes, address: Address, title: str = "Value") -> None:
    if value != b'':
        try:
            validate_qauata_public_key(value, address, title)
        except ValidationError:
            raise ValidationError(
                f"Bad keystore transaction: {title} is not empty or legal public key"
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

def validate_gibbs_transaction(state: GibbsStateAPI,
                                transaction: GibbsSignedTransactionAPI) -> None:
    #Validate gas
    if transaction.gas < transaction.intrinsic_gas:
        raise ValidationError(
            f"Gas lower than intrinsic cost:"
            f"at least {transaction.intrinsic_gas} but got {transaction.gas}"
        )
    #Validate balance
    max_gas_cost = transaction.gas * state.get_gas_price(transaction)
    try:
        sender_balance = state.get_balance(transaction.sender)
    except AttributeError:
        raise AttributeError(
            "Transaction must be signed first"
        )
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
    #Validate nonce
    sender_nonce = state.get_nonce(transaction.sender)
    if sender_nonce != transaction.nonce:
        raise ValidationError(
            f"Invalid transaction nonce: Expected {sender_nonce}, but got {transaction.nonce}"
        )
    #Validate signature
    if transaction.type == 23:
        #0x17 -> keystore transaction
        if sender_nonce != 0:
            raise ValidationError(
                f"Key-store Transaction must have sent firstly:"
                f" Expected nonce 0, but got {transaction.nonce}"
            )
        public_key = transaction.data
        validate_qauata_public_key(public_key, transaction.sender, title="Transaction.data")
    elif transaction.type == 0:
        #0x0 -> Legacy transaction
        public_key = state.get_public_key(transaction.sender)
        validate_qauata_public_key(public_key, transaction.sender, title="PBK on chain")
    validate_qauata_transaction_rainbow_signature(transaction, public_key)

def validate_gibbs_transaction_type(transaction: GibbsSignedTransactionAPI, check_signature_validity = False) -> None:
    if transaction.type == 23:
        #0x17 -> keystore transaction
        if transaction.nonce != 0:
            raise ValidationError(
                f"Key-store Transaction must have sent firstly:"
                f" Expected nonce 0, but got {transaction.nonce}"
            )
        public_key = transaction.data
        validate_qauata_public_key(public_key, transaction.sender, title="Transaction.data")
        if check_signature_validity:
            validate_qauata_transaction_rainbow_signature(transaction, public_key)
    elif transaction.type == 0:
        #0x0 -> Legacy transaction
        pass
    else:
        raise ValidationError(
            f"Unsupported Transaction type:"
            f" Expected 0x0 (Legacy) or 0x17 (Keystore), but got {transaction.type}"
        )


def validate_qauata_transaction_rainbow_signature(transaction: 'SignedTransactionAPI',
                                                    sender_public_key: 'bytes') -> None:
    message = transaction.get_message_for_signing()
    try:
        is_verified = RainbowCrypto.raw_verify(sender_public_key, transaction.sig, message)
    except Exception as e:
        raise ValidationError(
            f"Bad signature: {e}"
        )
    if not is_verified:
        raise ValidationError("Invalid Signature")

def validate_gas_limit(gas_limit: int, parent_gas_limit: int) -> None:
    boundary_range = parent_gas_limit // GIBBS_GAS_LIMIT_ADJUSTMENT_FACTOR
    # the boundary range is the exclusive limit, therefore the inclusive bounds are
    # (boundary_range - 1) and (boundary_range + 1) for upper and lower bounds, respectively
    high_bound = min(GIBBS_GAS_LIMIT_MAXIMUM, parent_gas_limit + boundary_range - 1)
    low_bound = max(GIBBS_GAS_LIMIT_MINIMUM, parent_gas_limit - boundary_range + 1)

    if gas_limit < low_bound:
        raise ValidationError(
            f"The gas limit {gas_limit} is too low. It must be at least {low_bound}"
        )
    elif gas_limit > high_bound:
        raise ValidationError(
            f"The gas limit {gas_limit} is too high. It must be at most {high_bound}"
        )

def validate_gibbs_transaction_against_header(_vm: VirtualMachineAPI,
                                                 base_header: BlockHeaderAPI,
                                                 transaction: SignedTransactionAPI) -> None:
    if base_header.gas_used + transaction.gas > base_header.gas_limit:
        raise ValidationError(
            f"Transaction exceeds gas limit: using {transaction.gas}, "
            f"bringing total to {base_header.gas_used + transaction.gas}, "
            f"but limit is {base_header.gas_limit}"
        )
