from typing import (
    Any,
)

from eth.abc import BlockHeaderAPI
from eth.validation import (
    validate_gt,
    validate_header_params_for_configuration,
)

from eth.constants import (
    GENESIS_GAS_LIMIT,
    DIFFICULTY_ADJUSTMENT_DENOMINATOR,
    DIFFICULTY_MINIMUM,
    BOMB_EXPONENTIAL_PERIOD,
    BOMB_EXPONENTIAL_FREE_PERIODS,
)
from eth._utils.db import (
    get_parent_header,
)
from eth._utils.headers import (
    compute_gas_limit,
    fill_header_params_from_parent,
    new_timestamp_from_parent,
)
from eth.rlp.headers import BlockHeader

from .constants import (
    HEISENBERG_DIFFICULTY_ADJUSTMENT_CUTOFF,
    HEISENBERG_GAS_LIMIT_MINIMUM,
)


def compute_heisenberg_difficulty(parent_header: BlockHeaderAPI, timestamp: int) -> int:
    """
    Computes the difficulty for a block based on the parent block.
    """
    validate_gt(timestamp, parent_header.timestamp, title="Header timestamp")

    offset = parent_header.difficulty // DIFFICULTY_ADJUSTMENT_DENOMINATOR

    # We set the minimum to the lowest of the protocol minimum and the parent
    # minimum to allow for the initial frontier *warming* period during which
    # the difficulty begins lower than the protocol minimum.
    difficulty_minimum = min(parent_header.difficulty, DIFFICULTY_MINIMUM)

    if timestamp - parent_header.timestamp < HEISENBERG_DIFFICULTY_ADJUSTMENT_CUTOFF:
        base_difficulty = max(
            parent_header.difficulty + offset,
            difficulty_minimum,
        )
    else:
        base_difficulty = max(
            parent_header.difficulty - offset,
            difficulty_minimum,
        )

    # Adjust for difficulty bomb.
    num_bomb_periods = (
        (parent_header.block_number + 1) // BOMB_EXPONENTIAL_PERIOD
    ) - BOMB_EXPONENTIAL_FREE_PERIODS

    if num_bomb_periods >= 0:
        difficulty = max(
            base_difficulty + 2**num_bomb_periods,
            DIFFICULTY_MINIMUM,
        )
    else:
        difficulty = base_difficulty

    return difficulty


def create_heisenberg_header_from_parent(parent_header: BlockHeaderAPI,
                                       **header_params: Any) -> BlockHeader:
    if 'timestamp' not in header_params:
        header_params['timestamp'] = new_timestamp_from_parent(parent_header)

    if 'difficulty' not in header_params:
        # Use setdefault to ensure the new header has the same timestamp we use to calculate its
        # difficulty.
        header_params['difficulty'] = compute_heisenberg_difficulty(
            parent_header,
            header_params['timestamp'],
        )
    if 'gas_limit' not in header_params:
        header_params['gas_limit'] = (
            compute_gas_limit(
                parent_header,
                genesis_gas_limit=GENESIS_GAS_LIMIT,
            )
        )#TODO: gas limit calculation

    all_fields = fill_header_params_from_parent(parent_header, **header_params)
    return BlockHeader(**all_fields)


def configure_heisenberg_header(vm: "HeisenbergVM", **header_params: Any) -> BlockHeader:
    validate_header_params_for_configuration(header_params)

    with vm.get_header().build_changeset(**header_params) as changeset:
        if 'timestamp' in header_params and vm.get_header().block_number > 0:
            parent_header = get_parent_header(changeset.build_rlp(), vm.chaindb)
            changeset.difficulty = compute_heisenberg_difficulty(
                parent_header,
                header_params['timestamp'],
            )

        header = changeset.commit()
    return header
