from eth.vm.transaction_context import BaseTransactionContext


class HeisenbergTransactionContext(BaseTransactionContext):
    __slots__ = ['_gas_price', '_origin', '_log_counter', '_is_key_store']

    def __init__(self, gas_price: int, origin: bytes, is_keystore = False) -> None:
        self._is_key_store = is_keystore
        super().__init__(gas_price, origin)

    @property
    def is_keystore(self) -> bool:
        return self._is_key_store
