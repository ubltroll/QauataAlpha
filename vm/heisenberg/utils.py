from eth.abc import (
    UnsignedTransactionAPI,
)

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

    validate_qauata_private_key_length(private_key, title="Private key")
    message = transaction.get_message_for_signing()
    try:
        sig = rainbow.sign_message(message)
    except Exception as e:
        raise ValidationError(
            f"Bad signature: {e}"
        )
    return sig

def code_is_keystore(address: bytes, raw_code: bytes) -> bool:
    return (
        raw_code[:QAUATA_KEYSTORE_CODE_MARK_LENGTH] == QAUATA_KEYSTORE_CODE_MARK_PREFIX + address
        and len(raw_code) == QAUATA_KEYSTORE_CODE_MARK_LENGTH + RainbowCrypto.RAINBOW_PUBLICKEYBYTES
        )

def public_key_to_keystore(public_key: bytes) -> bytes:
    return QAUATA_KEYSTORE_CODE_MARK_PREFIX + public_key
