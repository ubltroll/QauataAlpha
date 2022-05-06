from typing import (
    Any,
)

from eth.chains.base import (
    MiningChain,
)

from eth_typing import Address

class QauataMiningChain(MiningChain):
    def create_transaction(self, *args: Any, **kwargs: Any) -> 'SignedTransactionAPI':
        return self.get_vm().create_transaction(*args, **kwargs)

    def create_unsigned_transaction(self,
                                    *,
                                    nonce: int,
                                    gas_price: int,
                                    gas: int,
                                    to: Address,
                                    value: int,
                                    data: bytes) -> 'UnsignedTransactionAPI':
        return self.get_vm().create_unsigned_transaction(
            nonce=nonce,
            gas_price=gas_price,
            gas=gas,
            to=to,
            value=value,
            chain_id=self.chain_id,
            data=data,
        )
