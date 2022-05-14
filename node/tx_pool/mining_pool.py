import asyncio
from async_timeout import timeout

from .pool import MemoryTxPool
from trinity.components.builtin.attach.console import (
    get_eth1_shell_context,
)
from trinity.db.manager import DBClient
from eth.db.chain import ChainDB
from eth_utils import (
    ValidationError,
)
from eth.db.trie import make_trie_root_and_nodes
from eth.consensus.pow import mine_pow_nonce
from eth.vm.interrupt import (
    EVMMissingData,
)
from .constant import (
    MINING_TIMEOUT_EACH_STEP,
    MINING_BUILDING_CYCLE,
    MINING_RELEASING_CYCLE,
)

from trinity.sync.common.events import (
    SendLocalTransaction,
    NewBlockImported,
)
import rlp


class MiningTxPool(MemoryTxPool):
    def __init__(self,
                 trinity_config,
                 event_bus: 'EndpointAPI',
                 peer_pool: 'ETHProxyPeerPool',
                 tx_validation_fn: 'Callable[[UninterpretedTransaction], bool]',
                 tx_restore_fn: 'Callable[[UninterpretedTransaction], SignedTransactionAPI]',
                 test_param = None # Test mode ON if test_param is not None
                 ) -> None:

        ipc_path = trinity_config.database_ipc_path
        trinity_already_running = ipc_path.exists()
        if trinity_already_running:
            chain_config = app_config.get_chain_config()
            db = DBClient.connect(ipc_path)
            self.chain = chain_config.full_chain_class(db)
        else:
            #raise NotImplementedError('Mining component cannot run by itself') 
            self.chain = test_param

        # Test Mode
        self.test_param = test_param

        # Block to mine
        self.filled_pending_block = None

        # Initiate MemoryTxPool
        super().__init__(event_bus, peer_pool, tx_validation_fn, tx_restore_fn)

    async def run(self):
        self.logger.info("Running Mining Tx Pool")

        # Building block regularly
        self.manager.run_daemon_task(self._building_block_cycle)

        # Mining block regularly
        self.manager.run_daemon_task(self._mining_block_cycle)

        #
        # Running daemon task for MemoryTxPool 
        #

        # Send all known pending transactions to new node
        self.manager.run_daemon_task(self._send_pending_transactions)

        # Process all local transactions coming through the JSON-RPC API
        self.manager.run_daemon_task(self._process_local_transaction)

        # Process recived transactions
        self.manager.run_daemon_task(self._handle_tx)

        # Remove tx in new imported blocks from pending pool
        self.manager.run_daemon_task(self._handle_new_block)

    def _prepare_mining_txs(self, limit=20):
        self.logger.debug2("Mining setup: Internal txs: %d", self.pending_txs_number)
        txs = self._internal_pool.get_txs(limit)
        self.logger.debug2("Mining setup: Preparing %d txs", len(txs))
        return txs

    async def resamble_working_block(self):
        self.logger.debug2('Mining resamber: Building working block')
        base_block = self.chain.get_block()
        self.fill_transactions(
            self.chain.get_vm(at_header=base_block.header),
            self._prepare_mining_txs(),
            base_block.header,
            base_block
            )
        return

    # Override
    async def _handle_new_block(self):
        async for event in self._event_bus.stream(NewBlockImported):
            for tx in event.block.transactions: #BlockAPI -> SignedTransactionAPI
                self._internal_pool.remove_by_hash(tx.hash)
            await self.resamble_working_block()

    # Override
    async def _process_local_transaction(self) -> None:
        async for event in self._event_bus.stream(SendLocalTransaction):
            await self._process_local_transaction_relay(event.transaction)
            await self.resamble_working_block()
            if self.test_param is not None:
                await self.mine()

    async def _building_block_cycle(self):
        while self.manager.is_running:
            await self.resamble_working_block()
            await asyncio.sleep(MINING_BUILDING_CYCLE)

    async def _mining_block_cycle(self):
        if self.test_param is not None:
            await asyncio.sleep(100)
        while self.manager.is_running:
            await self.mine()
            await asyncio.sleep(MINING_RELEASING_CYCLE)


    def fill_transactions(self,
                          vm: 'VM',
                          transactions: 'Sequence[SignedTransactionAPI]',
                          base_header: 'BlockHeaderAPI',
                          base_block: 'BlockAPI'
                        ) -> 'Tuple[BlockHeaderAPI, Tuple[ReceiptAPI, ...], Tuple[ComputationAPI, ...]]':
        receipts = []
        computations = []
        previous_header = base_header
        result_header = base_header
        self.logger.debug2("Mining Filler: Trying to fill block with %d txs", len(transactions))
        applied_txs =[]
        for transaction_index, transaction in enumerate(transactions):
            if not self._internal_pool.ensure_alive(transaction):
                self.logger.debug2("Mining Filler: Dump tx: tx is dead")
                continue
            transaction = self.tx_restore_fn(transaction)
            if result_header.gas_used + transaction.gas >= result_header.gas_limit:
                self.logger.debug2("Mining Filler: Dump tx: gas not enough")
                break
            try:
                snapshot = vm.state.snapshot()
                receipt, computation = vm.apply_transaction(
                    previous_header,
                    transaction,
                )
            except EVMMissingData:
                vm.state.revert(snapshot)
            except ValidationError:
                self.logger.debug2("Mining Filler: Dump tx: tx validation failed")
                continue

            applied_txs.append(transaction)
                
            result_header = vm.add_receipt_to_header(previous_header, receipt)
            previous_header = result_header
            receipts.append(receipt)
            computations.append(computation)

            vm.transaction_applied_hook(
                transaction_index,
                transactions,
                base_header,
                result_header,
                computation,
                receipt,
            )

        tx_root_hash, tx_kv_nodes = make_trie_root_and_nodes(applied_txs)
        receipt_root_hash, receipt_kv_nodes = make_trie_root_and_nodes(receipts)

        filled_pending_block = base_block.copy(
            transactions=applied_txs,
            header=result_header.copy(
                transaction_root=tx_root_hash,
                receipt_root=receipt_root_hash,
            ),
        )

        # Do not waste time to mine empty block in test
        if self.test_param and len(applied_txs) == 0:
            return

        # Set header here
        filled_pending_block.header.coinbase
        filled_pending_block.header.extra_data

        self.filled_pending_block = filled_pending_block
        return filled_pending_block
    
    async def work(self, filled_pending_block) -> "Tuple['nonce', 'mix_hash']":
        if filled_pending_block.number != self.chain.get_vm().get_block().number:
            self.logger.debug2('Mining miner: %d != %d', filled_pending_block.number, self.chain.get_vm().get_block().number)
            raise ValueError('Mining miner: Illegal header')
        try:
            nonce, mix_hash = mine_pow_nonce(
                filled_pending_block.number,
                filled_pending_block.header.mining_hash,
                filled_pending_block.header.difficulty
            )
            return nonce, mix_hash
        except Exception:
            raise asyncio.TimeoutError('Mining worker: Max attempts reached')

    def remove_txs_from_pool(self, txs: 'SignedTransactionAPI'):
        return [self._internal_pool.remove_by_hash(tx.hash) for tx in txs]


    async def mine(self):
        filled_pending_block = self.filled_pending_block
        if filled_pending_block is None:
            return
        self.logger.debug3('start mining: difficulty: %d', filled_pending_block.header.difficulty)
        try:
            async with timeout(MINING_TIMEOUT_EACH_STEP):
                nonce, mix_hash = await self.work(filled_pending_block)
        except asyncio.TimeoutError:
            self.logger.debug3('Mining miner: time out, release to loop')
            return
        except ValueError:
            self.logger.debug3('Mining miner: illegal header')
            return
        self.logger.info('Mining miner: new block # %d found with %d transactions',
                        filled_pending_block.number, len(filled_pending_block.transactions))
        mined_result = self.chain.get_vm().mine_block(filled_pending_block, mix_hash=mix_hash, nonce=nonce)
        mined_block  = mined_result.block
        self.chain.chaindb.persist_block(mined_block)
        self.chain.header = self.chain.create_header_from_parent(filled_pending_block.header)

        score = self.chain.get_score(mined_block.hash)
        broadcast_block = mined_block.copy(
            transactions = self.remove_txs_from_pool(mined_block.transactions)
            )
        #broadcast here
        peers = await self._peer_pool.get_peers()
        
        for receiving_peer in peers:
            self.logger.debug(
                'Sending newly mined block to %s',
                receiving_peer,
            )
            receiving_peer.eth_api.send_new_block(broadcast_block, score)
            # release to the event loop since this loop processes a
            # lot of data queue up a lot of outbound messages.
            await asyncio.sleep(0)