from typing import (
    Any,
)

from eth.abc import BlockHeaderAPI
from eth.validation import (
    validate_gt,
    validate_header_params_for_configuration,
)

from eth._utils.db import (
    get_parent_header,
)
from eth._utils.headers import (
    fill_header_params_from_parent,
    new_timestamp_from_parent,
)
from eth.rlp.headers import BlockHeader

from .constants import (
    GIBBS_DIFFICULTY_ADJUSTMENT_CUTOFF,
    GIBBS_DIFFICULTY_MINIMUM,
    GIBBS_GAS_LIMIT_MINIMUM,
    GIBBS_GAS_LIMIT_MAXIMUM,
    GIBBS_GENESIS_GAS_LIMIT,
    GIBBS_GAS_LIMIT_ADJUSTMENT_FACTOR,
    GIBBS_DIFFICULTY_ADJUSTOR,
)


def compute_gibbs_difficulty(parent_header: BlockHeaderAPI, timestamp: int) -> int:
    """
    Computes the difficulty for a block based on the parent block.
    """
    validate_gt(timestamp, parent_header.timestamp, title="Header timestamp")

    offset = parent_header.difficulty // GIBBS_DIFFICULTY_ADJUSTOR

    # We set the minimum to the lowest of the protocol minimum and the parent
    # minimum to allow for the initial frontier *warming* period during which
    # the difficulty begins lower than the protocol minimum.
    difficulty_minimum = min(parent_header.difficulty, GIBBS_DIFFICULTY_MINIMUM)

    if timestamp - parent_header.timestamp < GIBBS_DIFFICULTY_ADJUSTMENT_CUTOFF:
        base_difficulty = max(
            parent_header.difficulty + offset,
            GIBBS_DIFFICULTY_MINIMUM,
        )
    else:
        base_difficulty = max(
            parent_header.difficulty - offset,
            GIBBS_DIFFICULTY_MINIMUM,
        )

    return base_difficulty

def compute_gibbs_gas_limit(parent_header: BlockHeaderAPI) -> int:
    if GIBBS_GENESIS_GAS_LIMIT < GIBBS_GAS_LIMIT_MINIMUM:
        raise ValueError(
            "The `genesis_gas_limit` value must be greater than the "
            f"GAS_LIMIT_MINIMUM.  Got {GIBBS_GENESIS_GAS_LIMIT}.  Must be greater than "
            f"{GIBBS_GAS_LIMIT_MINIMUM}"
        )

    if parent_header is None:
        return GIBBS_GENESIS_GAS_LIMIT

    adjustor = parent_header.gas_limit // GIBBS_GAS_LIMIT_ADJUSTMENT_FACTOR

    gas_limit = max(
        GIBBS_GAS_LIMIT_MINIMUM,
        (parent_header.gas_limit + adjustor if
        parent_header.gas_used >= parent_header.gas_limit else
        parent_header.gas_limit - adjustor)
    )

    return gas_limit


def create_gibbs_header_from_parent(parent_header: BlockHeaderAPI,
                                       **header_params: Any) -> BlockHeader:
    if 'timestamp' not in header_params:
        header_params['timestamp'] = new_timestamp_from_parent(parent_header)

    if 'difficulty' not in header_params:
        # Use setdefault to ensure the new header has the same timestamp we use to calculate its
        # difficulty.
        header_params['difficulty'] = compute_gibbs_difficulty(
            parent_header,
            header_params['timestamp'],
        )
    if 'gas_limit' not in header_params:
        header_params['gas_limit'] = (
            compute_gibbs_gas_limit(
                parent_header)
        )#TODO: gas limit calculation

    all_fields = fill_header_params_from_parent(parent_header, **header_params)
    return BlockHeader(**all_fields)


def configure_gibbs_header(vm: "GibbsVM", **header_params: Any) -> BlockHeader:
    validate_header_params_for_configuration(header_params)

    with vm.get_header().build_changeset(**header_params) as changeset:
        if 'timestamp' in header_params and vm.get_header().block_number > 0:
            parent_header = get_parent_header(changeset.build_rlp(), vm.chaindb)
            changeset.difficulty = compute_gibbs_difficulty(
                parent_header,
                header_params['timestamp'],
            )

        header = changeset.commit()
    return header
