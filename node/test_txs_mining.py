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
from trinity.config import (
    Eth1AppConfig,
    TrinityConfig,
)

from trinity.constants import TO_NETWORKING_BROADCAST_CONFIG
from trinity.protocol.eth.events import (
    TransactionsEvent,
    NewBlockEvent,
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
from .tx_pool.mining_pool import MiningTxPool

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
    got_block = asyncio.Event()

    async def _txn_handler(event):
        got_block.clear()

        incoming_tx.append(event.command.payload[0])
        got_block.set()

    event_bus.subscribe(TransactionsEvent, _txn_handler)

    return incoming_tx, got_block


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


def create_random_tx(chain, private_key, is_valid=True):
    transaction = chain.create_unsigned_transaction(
        nonce=0,
        gas_price=1,
        gas=210000 if is_valid else 0,
        # For simplicity, both peers create tx with the same private key.
        # We rely on unique data to create truly unique txs
        data=uuid.uuid4().bytes,
        to=force_bytes_to_address(b'\x10\x10'),
        value=1,
    ).as_signed_transaction(private_key, chain_id=chain.chain_id if is_valid else chain.chain_id + 1)
    return rlp.decode(rlp.encode(transaction))

@pytest.fixture
async def two_connected_mining_pools(event_bus,
                                 other_event_bus,
                                 event_loop,
                                 funded_address_private_key,
                                 chain_with_block_validation,
                                 tx_validator,
                                 tx_restore_fn,
                                 client_and_server):
    trinity_config = TrinityConfig(app_identifier="eth1", network_id=1)

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

        alice_tx_pool = MiningTxPool(
            trinity_config,
            alice_event_bus,
            alice_proxy_peer_pool,
            tx_validator,
            tx_restore_fn,
            chain_with_block_validation
        )
        await stack.enter_async_context(background_asyncio_service(alice_tx_pool))

        bob_tx_pool = MiningTxPool(
            trinity_config,
            bob_event_bus,
            bob_proxy_peer_pool,
            tx_validator,
            tx_restore_fn,
            chain_with_block_validation
        )
        await stack.enter_async_context(background_asyncio_service(bob_tx_pool))

        yield (alice, alice_event_bus, alice_tx_pool, ), (bob, bob_event_bus, bob_tx_pool)

def observe_incoming_blocks(event_bus):
    incoming_block = []
    got_block = asyncio.Event()

    async def _block_handler(event):
        got_block.clear()
        incoming_block.append(event.command.payload.block)
        got_block.set()

    event_bus.subscribe(NewBlockEvent, _block_handler)

    return incoming_block, got_block

def observe_incoming_transactions(event_bus):
    incoming_tx = []
    got_txns = asyncio.Event()

    async def _txn_handler(event):
        got_txns.clear()
        incoming_tx.append(event.command.payload[0])
        got_txns.set()

    event_bus.subscribe(TransactionsEvent, _txn_handler)

    return incoming_tx, got_txns

@pytest.mark.asyncio
async def test_block_propagation(two_connected_mining_pools,
                              chain_with_block_validation,
                              funded_address_private_key):
    (
        (alice, alice_event_bus, alice_tx_pool),
        (bob, bob_event_bus, bob_tx_pool)
    ) = two_connected_mining_pools

    alice_got_blocks, alice_got_block = observe_incoming_blocks(alice_event_bus)
    bob_got_blocks, bob_got_block = observe_incoming_blocks(bob_event_bus)

    _, bob_got_txns = observe_incoming_transactions(bob_event_bus)

    tx_broadcasted_by_alice = create_random_tx(chain_with_block_validation, funded_address_private_key)

    # Alice sends some txs (Important we let the TxPool send them to feed the bloom)
    await alice_event_bus.broadcast(SendLocalTransaction(tx_broadcasted_by_alice))

    # Bob should receive block
    await asyncio.wait_for(bob_got_block.wait(), timeout=1)

    assert alice_tx_pool.pending_txs_number == 0
    assert len(bob_got_blocks) == 1
    assert bob_got_blocks[0].transactions[0] == tx_broadcasted_by_alice