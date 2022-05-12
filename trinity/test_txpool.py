import asyncio
import contextlib
import pytest
import uuid
from async_service import background_asyncio_service
from trinity.constants import (
    NETWORKING_EVENTBUS_ENDPOINT,
    TO_NETWORKING_BROADCAST_CONFIG,
)
from trinity.protocol.eth.peer import (
    ETHProxyPeerPool,
    ETHPeerPoolEventServer
)
from trinity.protocol.eth.peer import ETHPeerPool


def observe_incoming_transactions(event_bus):
    incoming_tx = []
    got_txns = asyncio.Event()

    async def _txn_handler(event):
        got_txns.clear()

        incoming_tx.append(event.command.payload[0])
        got_txns.set()

    event_bus.subscribe(TransactionsEvent, _txn_handler)

    return incoming_tx, got_txns

class MockPeerPoolWithConnectedPeers(ETHPeerPool):
    def __init__(self, peers, event_bus=None) -> None:
        super().__init__(privkey=None, context=None, event_bus=event_bus)
        for peer in peers:
            self.connected_nodes[peer.session] = peer

    async def run(self) -> None:
        raise NotImplementedError("This is a mock PeerPool implementation, you must not _run() it")


@pytest.fixture(scope='session')
def event_loop():
    loop = asyncio.new_event_loop()
    try:
        yield loop
    finally:
        loop.close()

@pytest.fixture
async def client_and_server():
    peer_pair = LatestETHPeerPairFactory(
        alice_peer_context=ChainContextFactory(),
        bob_peer_context=ChainContextFactory(),
    )
    async with peer_pair as (client_peer, server_peer):
        yield client_peer, server_peer

@contextlib.asynccontextmanager
async def make_networking_event_bus():
    # Tests run concurrently, therefore we need unique IPC paths
    ipc_path = Path(f"networking-{uuid.uuid4()}.ipc")
    networking_connection_config = ConnectionConfig(
        name=NETWORKING_EVENTBUS_ENDPOINT,
        path=ipc_path
    )
    async with AsyncioEndpoint.serve(networking_connection_config) as endpoint:
        yield endpoint

@pytest.fixture
async def event_bus():
    async with make_networking_event_bus() as endpoint:
        yield endpoint


# Tests with multiple peers require us to give each of them there independent 'networking' endpoint
@pytest.fixture
async def other_event_bus():
    async with make_networking_event_bus() as endpoint:
        yield endpoint

from trinity.protocol.common.peer_pool_event_bus import (
    DefaultPeerPoolEventServer,
)
@contextlib.asynccontextmanager
async def run_peer_pool_event_server(event_bus, peer_pool, handler_type=None):

    handler_type = DefaultPeerPoolEventServer if handler_type is None else handler_type

    event_server = handler_type(
        event_bus,
        peer_pool,
    )
    async with background_asyncio_service(event_server):
        yield event_server


@pytest.fixture
async def two_connected_tx_pools(event_bus,
                                 other_event_bus,
                                 event_loop,
                                 funded_address_private_key,
                                 chain_with_block_validation,
                                 tx_validator,
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

        alice_tx_pool = TxPool(
            alice_event_bus,
            alice_proxy_peer_pool,
            tx_validator,
        )
        await stack.enter_async_context(background_asyncio_service(alice_tx_pool))

        bob_tx_pool = TxPool(
            bob_event_bus,
            bob_proxy_peer_pool,
            tx_validator,
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
    ).as_signed_transaction(private_key, chain_id=chain.chain_id)
    return rlp.decode(rlp.encode(transaction))

@pytest.mark.asyncio
async def test_tx_propagation(two_connected_tx_pools,
                              chain_with_block_validation,
                              funded_address_private_key):

    (
        (alice, alice_event_bus, alice_tx_pool),
        (bob, bob_event_bus, bob_tx_pool)
    ) = two_connected_tx_pools

    alice_incoming_tx, alice_got_tx = observe_incoming_transactions(alice_event_bus)
    bob_incoming_tx, bob_got_tx = observe_incoming_transactions(bob_event_bus)

    txs_broadcasted_by_alice = [
        create_random_tx(chain_with_block_validation, funded_address_private_key)
    ]

    # Alice sends some txs (Important we let the TxPool send them to feed the bloom)
    await alice_tx_pool._handle_tx(bob.session, txs_broadcasted_by_alice)

    await asyncio.wait_for(bob_got_tx.wait(), timeout=0.2)
    assert len(bob_incoming_tx) == 1

    assert bob_incoming_tx[0] == txs_broadcasted_by_alice[0]

    # Clear the recording, we asserted all we want and would like to have a fresh start
    bob_incoming_tx.clear()
    bob_got_tx.clear()

    # Alice sends same txs again (Important we let the TxPool send them to feed the bloom)
    await alice_tx_pool._handle_tx(bob.session, txs_broadcasted_by_alice)

    # Check that Bob doesn't receive them again
    with pytest.raises(asyncio.TimeoutError):
        await asyncio.wait_for(bob_got_tx.wait(), timeout=0.2)
    assert len(bob_incoming_tx) == 0

    # Bob sends exact same txs back (Important we let the TxPool send them to feed the bloom)
    await alice_tx_pool._handle_tx(alice.session, txs_broadcasted_by_alice)

    # Check that Alice won't get them as that is where they originally came from
    with pytest.raises(asyncio.TimeoutError):
        await asyncio.wait_for(alice_got_tx.wait(), timeout=0.2)
    assert len(alice_incoming_tx) == 0

    txs_broadcasted_by_bob = [
        create_random_tx(chain_with_block_validation, funded_address_private_key),
        txs_broadcasted_by_alice[0]
    ]

    # Bob sends old + new tx
    await bob_tx_pool._handle_tx(alice.session, txs_broadcasted_by_bob)

    await asyncio.wait_for(alice_got_tx.wait(), timeout=0.2)

    # Check that Alice receives only the one tx that it didn't know about
    assert alice_incoming_tx[0] == txs_broadcasted_by_bob[0]
    assert len(alice_incoming_tx) == 1
