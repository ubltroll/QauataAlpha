from typing import (
    Type,
    Any,
)

from eth_bloom import (
    BloomFilter,
)

from eth.abc import (
    BlockAPI,
    BlockHeaderAPI,
    ReceiptAPI,
    StateAPI,
    SignedTransactionAPI,
    ComputationAPI,
)
from eth.constants import (
    BLOCK_REWARD,
    UNCLE_DEPTH_PENALTY_FACTOR,
    ZERO_HASH32,
)
from eth.rlp.logs import Log
from eth.rlp.receipts import Receipt

from eth.vm.base import VM

from .blocks import HeisenbergrBlock
from .constants import MAX_REFUND_QUOTIENT
from .state import HeisenbergState
from .headers import (
    create_heisenberg_header_from_parent,
    compute_heisenberg_difficulty,
    configure_heisenberg_header,
)
from .constants import (
    EIP658_TRANSACTION_STATUS_CODE_FAILURE,
    EIP658_TRANSACTION_STATUS_CODE_SUCCESS,
)
from .validation import (
    validate_frontier_transaction_against_header,
    validate_gas_limit,
)


def make_hesienberg_receipt(computation: ComputationAPI,
                          new_cumulative_gas_used: int) -> ReceiptAPI:
    # Reusable for other forks
    # This skips setting the state root (set to 0 instead). The logic for making a state root
    # lives in the FrontierEVM, so that state merkelization at each receipt is skipped at Byzantium+.

    logs = [
        Log(address, topics, data)
        for address, topics, data
        in computation.get_log_entries()
    ]

    receipt = Receipt(
        state_root=ZERO_HASH32,
        gas_used=new_cumulative_gas_used,
        logs=logs,
    )

    return receipt


class HeisenbergVM(VM):
    # fork name
    fork: str = 'hesienberg'  # noqa: E701  # flake8 bug that's fixed in 3.6.0+

    # classes
    block_class: Type[BlockAPI] = HeisenbergrBlock
    _state_class: Type[StateAPI] = HeisenbergState

    # methods
    create_header_from_parent = staticmethod(create_heisenberg_header_from_parent)    # type: ignore
    compute_difficulty = staticmethod(compute_heisenberg_difficulty)      # type: ignore
    configure_header = configure_heisenberg_header
    validate_transaction_against_header = validate_frontier_transaction_against_header

    @staticmethod
    def get_block_reward() -> int:
        return BLOCK_REWARD

    @staticmethod
    def get_uncle_reward(block_number: int, uncle: BlockHeaderAPI) -> int:
        return BLOCK_REWARD * (
            UNCLE_DEPTH_PENALTY_FACTOR + uncle.block_number - block_number
        ) // UNCLE_DEPTH_PENALTY_FACTOR

    @classmethod
    def get_nephew_reward(cls) -> int:
        return cls.get_block_reward() // 32

    def add_receipt_to_header(self,
                              old_header: BlockHeaderAPI,
                              receipt: ReceiptAPI) -> BlockHeaderAPI:
        return old_header.copy(
            bloom=int(BloomFilter(old_header.bloom) | receipt.bloom),
            gas_used=receipt.gas_used,
            state_root=self.state.make_state_root(),
        )

    @classmethod
    def calculate_net_gas_refund(cls, consumed_gas: int, gross_refund: int) -> int:
        max_refund = consumed_gas // MAX_REFUND_QUOTIENT
        return min(max_refund, gross_refund)

    @classmethod
    def finalize_gas_used(cls,
                          transaction: SignedTransactionAPI,
                          computation: ComputationAPI) -> int:

        gas_remaining = computation.get_gas_remaining()
        consumed_gas = transaction.gas - gas_remaining

        gross_refund = computation.get_gas_refund()
        net_refund = cls.calculate_net_gas_refund(consumed_gas, gross_refund)

        return consumed_gas - net_refund

    @classmethod
    def make_receipt(
            cls,
            base_header: BlockHeaderAPI,
            transaction: SignedTransactionAPI,
            computation: ComputationAPI,
            state: StateAPI) -> ReceiptAPI:

        gas_used = base_header.gas_used + cls.finalize_gas_used(transaction, computation)

        if computation.is_error:
            status_code = EIP658_TRANSACTION_STATUS_CODE_FAILURE
        else:
            status_code = EIP658_TRANSACTION_STATUS_CODE_SUCCESS

        return transaction.make_receipt(status_code, gas_used, computation.get_log_entries())

    @classmethod
    def validate_gas(
            cls,
            header: BlockHeaderAPI,
            parent_header: BlockHeaderAPI) -> None:
        validate_gas_limit(header.gas_limit, parent_header.gas_limit)

    #
    # Transactions
    #
    def create_transaction(self, *args: Any, **kwargs: Any) -> 'SignedTransactionAPI':
        return self.get_transaction_builder().new_transaction(*args, **kwargs)

    def create_unsigned_transaction(self, *args: Any, **kwargs: Any) -> 'UnsignedTransactionAPI':
        return self.get_transaction_builder().create_unsigned_transaction(*args, **kwargs)
