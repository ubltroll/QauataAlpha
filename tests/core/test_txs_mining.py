import pytest

from eth_utils import (
    decode_hex,
    ValidationError,
)


from eth import constants

from eth.tools.builder.chain import api

from chains import (
    QauataMiningChain,
)

@pytest.fixture
def pow_consensus_chain(vm_class):
    return api.build(
        QauataMiningChain,
        api.fork_at(vm_class, 0),
        api.genesis(),
    )

@pytest.fixture
def noproof_consensus_chain(VM, genesis_state):
    # This will always have the same vm configuration as the POW chain
    return api.build(
        QauataMiningChain,
        api.fork_at(VM, 0),
        api.disable_pow_check(),
        api.chain_id(1023),
        api.genesis(params=dict(gas_limit=6141592), state=genesis_state),
    )

def new_transaction(chain,
            to,
            value=0,
            crypto_engine=None,
            gas_price=10**10,
            gas=1888888,
            data=b'',
            nonce=None,):
        if nonce is None:
            nonce = chain.get_vm().state.get_nonce(crypto_engine.canonical_address)
        return chain.create_unsigned_transaction(nonce = nonce, gas_price = gas_price, gas = gas,
            to = to, value = value, data = data).as_signed_transaction(chain.chain_id, crypto_engine)

def test_apply_keystore_transaction(
        minging_chain_with_block_validation_POW,
        funded_address,
        funded_account,
        funded_address_initial_balance):
    chain = minging_chain_with_block_validation_POW
    vm = chain.get_vm()
    recipient = funded_address
    amount = 0
    from_ = funded_address
    tx = new_transaction(chain, recipient, amount, funded_account, data=funded_account.public_key)
    receipt, computation = vm.apply_transaction(vm.get_header(), tx)
    new_header = vm.add_receipt_to_header(vm.get_header(), receipt)
    gas_est = 1888888
    assert tx.nonce == 0
    assert not computation.is_error
    tx_gas = tx.gas_price * gas_est
    state = vm.state
    assert state.get_nonce(funded_address) == 1
    assert state.get_balance(from_) == (
        funded_address_initial_balance - amount - tx_gas)
    assert new_header.gas_used == gas_est

def test_apply_transfer_transaction_without_keystore(
        minging_chain_with_block_validation_POW,
        funded_address,
        funded_account,
        funded_address_initial_balance):
    chain = minging_chain_with_block_validation_POW
    vm = chain.get_vm()
    recipient = funded_address
    amount = 1000
    from_ = funded_address
    tx = new_transaction(chain, recipient, amount, funded_account, data=b'')
    try:
        receipt, computation = vm.apply_transaction(vm.get_header(), tx)
    except ValidationError:
        pass

def test_apply_keystore_transfer_transaction(
        minging_chain_with_block_validation_POW,
        funded_address,
        canonical_address_a,
        funded_account,
        funded_address_initial_balance):
    chain = minging_chain_with_block_validation_POW
    vm = chain.get_vm()
    assert vm.state.get_nonce(funded_address) == 0
    tx = new_transaction(chain, funded_address, 0, funded_account, data=funded_account.public_key)
    assert vm.state.get_nonce(funded_address) == 0
    receipt, computation = vm.apply_transaction(vm.get_header(), tx)
    new_header = vm.add_receipt_to_header(vm.get_header(), receipt)
    gas_est = 1888888
    assert tx.nonce == 0
    assert not computation.is_error
    tx_gas = tx.gas_price * gas_est
    state = vm.state
    assert state.get_balance(funded_address) == (
        funded_address_initial_balance - tx_gas)
    assert len(state.get_code(funded_address)) == 0
    assert len(state.get_public_key(funded_address)) == 60192
    assert new_header.gas_used == gas_est
    amount = 560000
    tx = new_transaction(chain, canonical_address_a, amount, funded_account, nonce=1)
    assert tx.nonce == 1
    receipt, computation = vm.apply_transaction(vm.get_header(), tx)
    new_header = vm.add_receipt_to_header(vm.get_header(), receipt)
    gas_est += 21000
    assert state.get_balance(funded_address) == (
        funded_address_initial_balance - amount
        - tx.gas_price * gas_est)
    assert new_header.gas_used == 21000

def test_mining_block_without_validation(noproof_consensus_chain,
                                        funded_address,
                                        canonical_address_a,
                                        canonical_address_b,
                                        funded_account):
    chain = noproof_consensus_chain
    tx1 = new_transaction(chain, funded_address, 0, funded_account, data=funded_account.public_key, nonce = 0)
    tx2 = new_transaction(chain, canonical_address_a, 10**18, funded_account, data=b'', nonce = 1)
    tx3 = new_transaction(chain, canonical_address_b, 10**18, funded_account, data=b'', nonce = 2)
    assert chain.get_block().number == 1
    chain.mine_all([tx1, tx2])
    assert chain.get_block().number == 2
    chain.mine_all([tx3])
    assert chain.get_block().number == 3
