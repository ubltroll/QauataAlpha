from .validation import (
    validate_qauata_private_key_length,
)

from eth.abc import (
    UnsignedTransactionAPI,
)

from rainbow import (
    RainbowCrypto,
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

