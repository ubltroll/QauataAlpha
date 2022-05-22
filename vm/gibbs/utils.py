from eth.abc import (
    UnsignedTransactionAPI,
)
from eth.constants import (
    CREATE_CONTRACT_ADDRESS,
)
import rlp

from rainbow import (
    RainbowCrypto,
)

from .validation import (
    validate_qauata_private_key_length,
)
from .constants import (
    QAUATA_KEYSTORE_CODE_MARK_PREFIX,
    QAUATA_KEYSTORE_CODE_MARK_LENGTH,
)


def create_transaction_signature(unsigned_txn: UnsignedTransactionAPI,
                                 rb: RainbowCrypto) -> bytes:
    message = rlp.encode(unsigned_txn)
    try:
        sig = rb.sign_message(message)
    except Exception as e:
        raise ValidationError(
            f"Bad signature: {e}"
        )
    return sig

def code_is_keystore(address: bytes, raw_code: bytes) -> bool:
    return (
        raw_code[:QAUATA_KEYSTORE_CODE_MARK_LENGTH + len(address)] == QAUATA_KEYSTORE_CODE_MARK_PREFIX + address
        and len(raw_code) == QAUATA_KEYSTORE_CODE_MARK_LENGTH + RainbowCrypto.RAINBOW_PUBLICKEYBYTES
        )

def data_is_keystore(address: bytes, data: bytes) -> bool:
    return data[:len(address)] == address and len(data) == RainbowCrypto.RAINBOW_PUBLICKEYBYTES

def public_key_to_keystore(public_key: bytes) -> bytes:
    return QAUATA_KEYSTORE_CODE_MARK_PREFIX + public_key

def calculate_intrinsic_gas(
        gas_schedule: dict,
        transaction: 'SignedTransactionAPI',
) -> int:
    num_zero_bytes = transaction.data.count(b'\x00')
    num_non_zero_bytes = len(transaction.data) - num_zero_bytes
    if transaction.to == CREATE_CONTRACT_ADDRESS:
        create_cost = gas_schedule['gas_tx_create']
    else:
        create_cost = 0
    if is_gibbs_keystore_transaction(transaction) and gas_schedule.get('gas_tx_keystore_force'):
        return gas_schedule['gas_tx_keystore_force']
    else:
        return (
            gas_schedule['gas_tx']
            + num_zero_bytes * gas_schedule['gas_txdata_zero']
            + num_non_zero_bytes * gas_schedule['gas_txdata_nonzero']
            + create_cost
        )

def is_gibbs_keystore_transaction(transaction) -> bool:
    return (
        transaction.type == 23
    )
