import pytest
from vm.gibbs import GibbsVM
from vm.gibbs.transactions import (
    GibbsUnsignedTransaction,
)
from eth_utils import (
    ValidationError,
)
from eth._utils.address import (
    generate_contract_address,
)

def new_transaction(type, nonce, gas_price, gas, to, value, chain_id, data, account):
    raw_tx = GibbsUnsignedTransaction(type, nonce, gas_price, gas, to, value, chain_id, data)
    return raw_tx.as_signed_transaction(account)

@pytest.fixture
def chain(minging_chain_with_block_validation_POW_Gibbs):
    return minging_chain_with_block_validation_POW_Gibbs

def test_apply_transaction(
        chain,
        funded_address,
        funded_account,
        funded_address_initial_balance,
        canonical_address_a):
    vm = chain.get_vm()
    amount = 100
    tx = new_transaction(0, 0, 100, 200000, b'', 0, 1337, b'', funded_account)
    with pytest.raises(ValidationError):
        vm.apply_transaction(vm.get_header(), new_transaction(0, 0, 100, 200000, b'', 0, 1337, b'', funded_account))
    with pytest.raises(ValidationError):
        tx = new_transaction(23, 0, 100, 200000, funded_address, 0, 1337, funded_account.public_key, funded_account)
        vm.apply_transaction(vm.get_header(), tx)
    tx = new_transaction(23, 0, 100, 2000000, funded_address, amount, 1337, funded_account.public_key, funded_account)
    gas_cost = chain.estimate_gas(tx, vm.get_header())
    receipt, computation = vm.apply_transaction(vm.get_header(), tx)
    new_header = vm.add_receipt_to_header(vm.get_header(), receipt)

    assert not computation.is_error
    tx_gas = tx.gas_price * gas_cost
    state = vm.state
    assert state.get_balance(funded_address) == (
        funded_address_initial_balance - tx_gas)
    tx = new_transaction(0, 1, 100, 2000000, canonical_address_a, amount, 1337, b'', funded_account)
    vm.apply_transaction(vm.get_header(), tx)
    assert state.get_balance(canonical_address_a) == amount
    contract = bytes.fromhex('6060604052604f8060106000396000f360606040523615600d57600d565b604d5b600073ff'+
    'ffffffffffffffffffffffffffffffffffffff166108fc349081150290604051809050600060405180830381858888f19350505050505b565b00')
    tx = new_transaction(0, 2, 100, 2000000, b'', amount, 1337, contract, funded_account)
    vm.apply_transaction(vm.get_header(), tx)
    #assert generate_contract_address(funded_address, 2).hex() == 0
    contract_address = generate_contract_address(funded_address, 2)
    assert state.get_code(contract_address) != b''
    tx = new_transaction(0, 3, 100, 2000000, contract_address, 10*amount, 1337, b'', funded_account)
    vm.apply_transaction(vm.get_header(), tx)
    assert state.get_balance(contract_address) == amount
