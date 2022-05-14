import asyncio
from typing import (
    Callable,
    Iterable,
    List,
    Sequence,
    Tuple,
)
import uuid
from sortedcontainers import SortedList
from functools import cmp_to_key

from async_service import Service
from lahja import EndpointAPI

import rlp

import time

from p2p.abc import SessionAPI

from trinity._utils.logging import get_logger
from trinity.protocol.eth.events import (
    TransactionsEvent,
    GetPooledTransactionsEvent,
)
from trinity.protocol.eth.peer import (
    ETHProxyPeer,
    ETHProxyPeerPool,
)
from trinity.rlp.sedes import UninterpretedTransaction
from trinity.sync.common.events import (
    SendLocalTransaction,
    NewBlockImported,
)

from trinity.protocol.common.events import PeerJoinedEvent
from .constant import (
    ASK_POOLED_TX_MAXIMUM,
    TX_LIFETIME_REMOTE,
    TX_LIFETIME_LOCAL,
)

class InternalTxPool(object):
    __slots__=['txs_remote', 'txs_local', 'hash_to_tx', 'tx_to_hash_fn', 'tx_due_time']
    def __init__(self, tx_restore_fn):
        # Sorting txs: by gasPrice and nonce
        def cmp_tx(tx_a, tx_b):
            tx_a = tx_restore_fn(tx_a)
            tx_b = tx_restore_fn(tx_b)
            asc_key = (tx_a.gas_price - tx_b.gas_price) * 100 + tx_a.nonce - tx_b.nonce
            return -asc_key
        self.txs_remote = SortedList(key=cmp_to_key(cmp_tx))
        self.txs_local = SortedList(key=cmp_to_key(cmp_tx))
        self.hash_to_tx = {}
        self.tx_to_hash_fn = lambda tx: tx_restore_fn(tx).hash
        self.tx_due_time = {}

    def __len__(self):
        return len(self.txs_remote) + len(self.txs_local)
    
    def put_txs(self,
                txs: Sequence[UninterpretedTransaction],  
                isLocal = False) -> None:
        pool = self.txs_local if isLocal else self.txs_remote
        dut_time = int(time.time()) + (TX_LIFETIME_LOCAL if isLocal else TX_LIFETIME_REMOTE)
        for tx in txs:
            pool.add(tx)
            tx_hash = self.tx_to_hash_fn(tx)
            self.hash_to_tx[tx_hash]  = tx
            self.tx_due_time[tx_hash] = dut_time

    def get_txs(self, limit = 100) -> Sequence[UninterpretedTransaction]:
        pending = []
        pending += self.txs_local[:min(len(self.txs_local), limit)]
        pending += self.txs_remote[:min(len(self.txs_remote), limit - len(pending))]
        return pending

    def has_tx(self, tx: Sequence[UninterpretedTransaction]) -> bool:
        #return tx in self.txs_remote or tx in self.txs_local
        return self.tx_to_hash_fn(tx) in self.hash_to_tx

    def ensure_alive(self, tx) -> bool:
        tx_hash = self.tx_to_hash_fn(tx)
        if time.time() <= self.tx_due_time[tx_hash]:
            return True
        else:
            self.remove(tx)
            return False

    def remove(self, tx) -> 'UninterpretedTransaction':
        tx_hash = self.tx_to_hash_fn(tx)
        return self.remove_by_hash(tx_hash)

    def remove_by_hash(self, tx_hash) -> 'UninterpretedTransaction':
        record_tx = self.hash_to_tx.get(tx_hash)
        if record_tx:
            if record_tx in self.txs_remote:
                self.txs_remote.remove(record_tx)
            if record_tx in self.txs_local:
                self.txs_local.remove(record_tx)
            del self.hash_to_tx[tx_hash]
            if tx_hash in self.tx_due_time:
                del self.tx_due_time[tx_hash]
        return record_tx



class MemoryTxPool(Service):

    def __init__(self,
                 event_bus: EndpointAPI,
                 peer_pool: ETHProxyPeerPool,
                 tx_validation_fn: Callable[[UninterpretedTransaction], bool],
                 tx_restore_fn: Callable[[UninterpretedTransaction], 'SignedTransactionAPI'],
                 ) -> None:
        self.logger = get_logger('trinity.components.txpool.TxPoolService')

        self._internal_pool = InternalTxPool(tx_restore_fn)
        self._event_bus = event_bus
        self._peer_pool = peer_pool

        if tx_validation_fn is None:
            raise ValueError('Must pass a tx validation function')

        if tx_restore_fn is None:
            raise ValueError('Must pass a tx deserialization function')

        self.tx_validation_fn = tx_validation_fn
        self.tx_restore_fn = tx_restore_fn

    @property
    def pending_txs_number(self) -> int:
        return len(self._internal_pool)

    async def run(self) -> None:
        self.logger.info("Running Memory Tx Pool")

        # Send all known pending transactions to new node
        self.manager.run_daemon_task(self._send_pending_transactions)

        # Process all local transactions coming through the JSON-RPC API
        self.manager.run_daemon_task(self._process_local_transaction)

        # Process recived transactions
        self.manager.run_daemon_task(self._handle_tx)

        # Remove tx in new imported blocks from pending pool
        self.manager.run_daemon_task(self._handle_new_block)

    def incoming_txs(self, txs):
        fresh_txs = [tx for tx in txs if not self._internal_pool.has_tx(tx)]
        self.incoming_txs_validated([tx for tx in fresh_txs if self.tx_validation_fn(tx)])

    def incoming_txs_validated(self, txs):
        self._internal_pool.put_txs(txs)

    async def _send_pending_transactions(self) -> None:
        async for event in self._event_bus.stream(PeerJoinedEvent):
            receiving_peer = await self._peer_pool.ensure_proxy_peer(event.session)
            receiving_peer.eth_api.send_transactions(self._internal_pool.get_txs(ASK_POOLED_TX_MAXIMUM))

    async def _handle_tx(self) -> None:
        async for event in self._event_bus.stream(TransactionsEvent):
            self.logger.debug2('Received %d transactions from %s', len(event.command.payload), event.session)
            self.incoming_txs(event.command.payload)

    async def _process_local_transaction_relay(self, tx):
        serialized_transaction = rlp.decode(rlp.encode(tx))
        self.incoming_txs((serialized_transaction,))
        peers = await self._peer_pool.get_peers()
        for receiving_peer in peers:
            self.logger.debug2(
                'Sending transaction to %s',
                receiving_peer,
            )
            receiving_peer.eth_api.send_transactions((serialized_transaction,))
            # release to the event loop since this loop processes a
            # lot of data queue up a lot of outbound messages.
            await asyncio.sleep(0)

    async def _process_local_transaction(self) -> None:
        async for event in self._event_bus.stream(SendLocalTransaction):
            await self._process_local_transaction_relay(event.transaction)

    #untest, or checked when minging?
    async def _handle_new_block(self) -> None:
        async for event in self._event_bus.stream(NewBlockImported):
            for tx in event.block.transactions: #BlockAPI -> SignedTransactionAPI
                self._internal_pool.remove_by_hash(tx.hash)
            
