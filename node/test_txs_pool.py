import asyncio
import contextlib
import pytest
import uuid

from async_service import background_asyncio_service
from eth._utils.address import (
    force_bytes_to_address
)
import rlp

from trinity._utils.transactions import DefaultTransactionValidator
from trinity.components.builtin.tx_pool.pool import (
    TxPool,
)

from trinity.constants import TO_NETWORKING_BROADCAST_CONFIG
from trinity.protocol.eth.events import (
    TransactionsEvent,
)
from trinity.protocol.eth.peer import (
    ETHProxyPeerPool,
    ETHPeerPoolEventServer
)
from trinity.sync.common.events import SendLocalTransaction
from trinity.tools.factories import LatestETHPeerPairFactory, ChainContextFactory

from .tx_pool.pool import (
    InternalTxPool,
    MemoryTxPool,
) 

from trinity.protocol.eth.peer import ETHPeerPool

from trinity.protocol.common.events import PeerJoinedEvent

class MockPeerPoolWithConnectedPeers(ETHPeerPool):
    def __init__(self, peers, event_bus=None) -> None:
        super().__init__(privkey=None, context=None, event_bus=event_bus)
        for peer in peers:
            self.connected_nodes[peer.session] = peer

    async def run(self) -> None:
        raise NotImplementedError("This is a mock PeerPool implementation, you must not _run() it")


@contextlib.asynccontextmanager
async def run_peer_pool_event_server(event_bus, peer_pool, handler_type=None):

    handler_type = DefaultPeerPoolEventServer if handler_type is None else handler_type

    event_server = handler_type(
        event_bus,
        peer_pool,
    )
    async with background_asyncio_service(event_server):
        yield event_server

def observe_incoming_transactions(event_bus):
    incoming_tx = []
    got_txns = asyncio.Event()

    async def _txn_handler(event):
        got_txns.clear()

        incoming_tx.append(event.command.payload[0])
        got_txns.set()

    event_bus.subscribe(TransactionsEvent, _txn_handler)

    return incoming_tx, got_txns


@pytest.fixture
def tx_validator(chain_with_block_validation):
    return DefaultTransactionValidator(chain_with_block_validation, 0)

@pytest.fixture
def tx_restore_fn(tx_validator):
    return lambda tx: tx_validator.get_appropriate_tx_builder().deserialize(tx)


@pytest.fixture
async def client_and_server():
    peer_pair = LatestETHPeerPairFactory(
        alice_peer_context=ChainContextFactory(),
        bob_peer_context=ChainContextFactory(),
    )
    async with peer_pair as (client_peer, server_peer):
        yield client_peer, server_peer


@pytest.fixture
async def two_connected_tx_pools(event_bus,
                                 other_event_bus,
                                 event_loop,
                                 funded_address_private_key,
                                 chain_with_block_validation,
                                 tx_validator,
                                 tx_restore_fn,
                                 client_and_server):

    alice_event_bus = event_bus
    bob_event_bus = other_event_bus
    bob, alice = client_and_server

    bob_peer_pool = MockPeerPoolWithConnectedPeers([bob], event_bus=bob_event_bus)
    alice_peer_pool = MockPeerPoolWithConnectedPeers([alice], event_bus=alice_event_bus)

    async with contextlib.AsyncExitStack() as stack:
        await stack.enter_async_context(run_peer_pool_event_server(
            bob_event_bus, bob_peer_pool, handler_type=ETHPeerPoolEventServer
        ))

        await stack.enter_async_context(run_peer_pool_event_server(
            alice_event_bus, alice_peer_pool, handler_type=ETHPeerPoolEventServer
        ))

        bob_proxy_peer_pool = ETHProxyPeerPool(bob_event_bus, TO_NETWORKING_BROADCAST_CONFIG)
        await stack.enter_async_context(background_asyncio_service(bob_proxy_peer_pool))

        alice_proxy_peer_pool = ETHProxyPeerPool(alice_event_bus, TO_NETWORKING_BROADCAST_CONFIG)
        await stack.enter_async_context(background_asyncio_service(alice_proxy_peer_pool))

        alice_tx_pool = MemoryTxPool(
            alice_event_bus,
            alice_proxy_peer_pool,
            tx_validator,
            tx_restore_fn
        )
        await stack.enter_async_context(background_asyncio_service(alice_tx_pool))

        bob_tx_pool = MemoryTxPool(
            bob_event_bus,
            bob_proxy_peer_pool,
            tx_validator,
            tx_restore_fn
        )
        await stack.enter_async_context(background_asyncio_service(bob_tx_pool))

        yield (alice, alice_event_bus, alice_tx_pool, ), (bob, bob_event_bus, bob_tx_pool)

def create_random_tx(chain, private_key, is_valid=True):
    transaction = chain.create_unsigned_transaction(
        nonce=0,
        gas_price=1,
        gas=2100000000000 if is_valid else 0,
        # For simplicity, both peers create tx with the same private key.
        # We rely on unique data to create truly unique txs
        data=uuid.uuid4().bytes,
        to=force_bytes_to_address(b'\x10\x10'),
        value=1,
    ).as_signed_transaction(private_key, chain_id=chain.chain_id if is_valid else chain.chain_id + 1)
    return rlp.decode(rlp.encode(transaction))

@pytest.mark.asyncio
async def test_tx_propagation_by_relay_local_tx(two_connected_tx_pools,
                              chain_with_block_validation,
                              funded_address_private_key):

    (
        (alice, alice_event_bus, alice_tx_pool),
        (bob, bob_event_bus, bob_tx_pool)
    ) = two_connected_tx_pools

    alice_incoming_tx, alice_got_tx = observe_incoming_transactions(alice_event_bus)
    bob_incoming_tx, bob_got_tx = observe_incoming_transactions(bob_event_bus)


    tx_broadcasted_by_alice = create_random_tx(chain_with_block_validation, funded_address_private_key)
    
    # Alice sends some txs (Important we let the TxPool send them to feed the bloom)
    await alice_event_bus.broadcast(SendLocalTransaction(tx_broadcasted_by_alice))

    await asyncio.wait_for(bob_got_tx.wait(), timeout=0.2)
    assert len(bob_incoming_tx) == 1
    assert alice_tx_pool.pending_txs_number == 1

    assert bob_incoming_tx[0] == tx_broadcasted_by_alice

    # Clear the recording, we asserted all we want and would like to have a fresh start
    bob_incoming_tx.clear()
    bob_got_tx.clear()
    #await alice_tx_pool._handle_tx('local', [tx_broadcasted_by_alice])
    
    with pytest.raises(asyncio.TimeoutError):
        await asyncio.wait_for(alice_got_tx.wait(), timeout=0.2)
    assert alice_tx_pool.pending_txs_number == 1
    assert bob_tx_pool.pending_txs_number == 1

    await alice_event_bus.broadcast(SendLocalTransaction(create_random_tx(chain_with_block_validation,
        funded_address_private_key, is_valid=False)))
    with pytest.raises(asyncio.TimeoutError):
        await asyncio.wait_for(alice_got_tx.wait(), timeout=0.2)
    assert alice_tx_pool.pending_txs_number == 1
    assert bob_tx_pool.pending_txs_number == 1



def test_internal_pool(chain_with_block_validation, funded_address_private_key, tx_restore_fn):
    pool = InternalTxPool(tx_restore_fn)
    local = create_random_tx(chain_with_block_validation, funded_address_private_key)
    pool.put_txs([local], isLocal=True)
    assert len(pool) == 1
    pool.put_txs([create_random_tx(chain_with_block_validation, funded_address_private_key),
        create_random_tx(chain_with_block_validation, funded_address_private_key)])
    assert len(pool) == 3
    assert pool.get_txs(2)[0] == local
    assert len(pool) == 3
    pool.remove(local)
    assert len(pool) == 2

