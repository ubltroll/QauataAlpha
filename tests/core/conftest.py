import pytest
from eth_utils import to_canonical_address

from eth.vm.transaction_context import BaseTransactionContext

from rainbow import RainbowCrypto

from pathlib import Path

import pytest

from eth_utils import (
    decode_hex,
    to_tuple,
    to_wei,
    setup_DEBUG2_logging,
)

from eth_keys import keys
import rlp

from eth import constants
from eth.chains.base import (
    Chain,
    MiningChain,
)
from eth.consensus import PowConsensus
from eth.consensus.noproof import NoProofConsensus
from eth.db.atomic import AtomicDB
from eth.rlp.headers import BlockHeader
from vm.heisenberg import (
    HeisenbergVM,
)
from chains import (
    QauataMiningChain,
)
from rainbow import RainbowCrypto

#
#  Setup DEBUG2 level logging.
#
# This needs to be done before the other imports
setup_DEBUG2_logging()


@pytest.fixture()
def VM():
    return HeisenbergVM


@pytest.fixture
def base_db():
    return AtomicDB()


@pytest.fixture
def funded_account():
    return RainbowCrypto.new()


@pytest.fixture
def funded_address(funded_account):
    return funded_account.canonical_address


@pytest.fixture
def funded_address_initial_balance():
    return to_wei(1000, 'ether')


# wrapped in a method so that different callers aren't using (and modifying) the same dict
def _get_genesis_defaults():
    # values that are not yet customizeable (and will automatically be default) are commented out
    return {
        'difficulty': constants.GENESIS_DIFFICULTY,
        'gas_limit': 6141592,
        'coinbase': constants.GENESIS_COINBASE,
        'nonce': constants.GENESIS_NONCE,
        'mix_hash': constants.GENESIS_MIX_HASH,
        'extra_data': constants.GENESIS_EXTRA_DATA,
        'timestamp': 1501851927,
        # 'block_number': constants.GENESIS_BLOCK_NUMBER,
        # 'parent_hash': constants.GENESIS_PARENT_HASH,
        # "bloom": 0,
        # "gas_used": 0,
        # "uncles_hash": decode_hex("1dcc4de8dec75d7aab85b567b6ccd41ad312451b948a7413f0a142fd40d49347")  # noqa: E501
        # "receipt_root": decode_hex("56e81f171bcc55a6ff8345e692c0f86e5b48e01b996cadc001622fb5e363b421"),  # noqa: E501
        # "transaction_root": decode_hex("56e81f171bcc55a6ff8345e692c0f86e5b48e01b996cadc001622fb5e363b421"),  # noqa: E501
    }

@pytest.fixture
def genesis_state(funded_address, funded_address_initial_balance):
    return {
        funded_address: {
            'balance': funded_address_initial_balance,
            'nonce': 0,
            'code': b'',
            'storage': {},
        }
    }

@pytest.fixture
def minging_chain_with_block_validation_POW(VM, base_db, genesis_state):
    """
    Return a Chain object containing just the genesis block.
    The Chain's state includes one funded account, which can be found in the
    funded_address in the chain itself.
    This Chain will perform all validations when importing new blocks, so only
    valid and finalized blocks can be used with it. If you want to test
    importing arbitrarily constructe, not finalized blocks, use the
    chain_without_block_validation fixture instead.
    """
    klass = QauataMiningChain.configure(
        __name__='TestChain',
        vm_configuration=(
            (constants.GENESIS_BLOCK_NUMBER, VM.configure(consensus_class=PowConsensus)),
        ),
        chain_id=1337,
    )
    chain = klass.from_genesis(base_db, _get_genesis_defaults(), genesis_state)
    return chain



@pytest.fixture(scope='function')
def chain_from_vm(request, base_db, genesis_state):
    """
    This fixture is to be used only when the properties of the
    chains differ from one VM to another.
    For example, the block rewards change from one VM chain to another
    """
    def get_chain_from_vm(vm):
        return _chain_with_block_validation(vm, base_db, genesis_state)
    return get_chain_from_vm


def import_block_without_validation(chain, block):
    return super(type(chain), chain).import_block(block, perform_validation=False)



@pytest.fixture
def account_a():
    return RainbowCrypto.new()


@pytest.fixture
def account_b():
    return RainbowCrypto.new()


@pytest.fixture
def canonical_address_a(account_a):
    return to_canonical_address(account_a.canonical_address)


@pytest.fixture
def canonical_address_b(account_b):
    return to_canonical_address(account_b.canonical_address)


@pytest.fixture
def transaction_context(canonical_address_b):
    tx_context = BaseTransactionContext(
        gas_price=1,
        origin=canonical_address_b,
    )
    return tx_context
