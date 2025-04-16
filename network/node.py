"""
Network Node Module

This module implements the networking layer for nodes participating
in the Temporal Consensus Protocol, handling P2P communications
and entropy exchange.
"""

import time
import json
import asyncio
import threading
import uuid
import base64
import hashlib
from typing import Dict, List, Set, Any, Optional, Callable
from fastapi import FastAPI, HTTPException, BackgroundTasks
from fastapi.middleware.cors import CORSMiddleware
import uvicorn
from pydantic import BaseModel
import requests
from ..consensus.protocol import TemporalConsensusProtocol, TemporalFingerprint
from ..blockchain.blockchain import TemporalBlockchain, Block

# API Models
class NodeInfo(BaseModel):
    node_id: str
    address: str
    port: int
    public_key: Optional[str] = None
    metadata: Optional[Dict] = None
    
class EntropySignature(BaseModel):
    node_id: str
    signature_id: str
    timestamp: float
    data_hash: Optional[str] = None
    entropy_signature: str
    
class BlockData(BaseModel):
    block_dict: Dict
    
class TransactionData(BaseModel):
    transaction: Dict
    
class ValidationResult(BaseModel):
    transaction_id: str
    valid: bool
    status: str
    validations_count: Optional[int] = None
    required_validations: Optional[int] = None
    
class NetworkMessage(BaseModel):
    message_type: str
    sender_id: str
    content: Dict
    timestamp: float
    message_id: str = None

class TemporalNode:
    """
    Implementation of a node in the Temporal Consensus Protocol network,
    handling P2P communication and consensus participation.
    """
    
    def __init__(self, node_id: str = None, host: str = "localhost", port: int = 8000):
        self.node_id = node_id or str(uuid.uuid4())
        self.host = host
        self.port = port
        self.address = f"http://{host}:{port}"
        
        # Initialize blockchain and consensus components
        self.blockchain = TemporalBlockchain(node_id=self.node_id)
        self.consensus_protocol = self.blockchain.consensus_protocol
        
        # Network peers
        self.peers: Dict[str, NodeInfo] = {}
        
        # Message handlers
        self.message_handlers: Dict[str, Callable] = {
            "new_block": self._handle_new_block,
            "new_transaction": self._handle_new_transaction,
            "entropy_signature": self._handle_entropy_signature,
            "chain_request": self._handle_chain_request,
            "chain_response": self._handle_chain_response
        }
        
        # Initialize API application
        self.app = FastAPI(title=f"Temporal Node {self.node_id[:8]}")
        self._setup_api_routes()
        
        # Add CORS middleware
        self.app.add_middleware(
            CORSMiddleware,
            allow_origins=["*"],
            allow_credentials=True,
            allow_methods=["*"],
            allow_headers=["*"],
        )
        
        # Server control
        self._server_thread = None
        self._running = False
        
        # Background tasks
        self._tasks = []
        
    def _setup_api_routes(self):
        """Configure API endpoints"""
        
        @self.app.get("/")
        def root():
            return {
                "node": self.node_id,
                "peers": len(self.peers),
                "chain_length": len(self.blockchain.chain)
            }
            
        @self.app.get("/node/info")
        def get_node_info():
            return {
                "node_id": self.node_id,
                "address": self.address,
                "port": self.port,
                "peers": len(self.peers),
                "chain_length": len(self.blockchain.chain),
                "pending_transactions": len(self.blockchain.pending_transactions),
                "timestamp": time.time()
            }
            
        @self.app.get("/peers")
        def get_peers():
            return {
                "peers": [peer.dict() for peer in self.peers.values()]
            }
            
        @self.app.post("/peers/register")
        def register_peer(node: NodeInfo):
            # Don't register self
            if node.node_id == self.node_id:
                return {"status": "ignored", "reason": "self-registration"}
                
            # Store peer
            self.peers[node.node_id] = node
            
            # Register with consensus protocol
            self.consensus_protocol.register_node(
                node.node_id, 
                {"address": node.address, "port": node.port}
            )
            
            return {"status": "registered", "node_id": node.node_id}
            
        @self.app.post("/message")
        def receive_message(message: NetworkMessage, background_tasks: BackgroundTasks):
            # Handle message asynchronously
            background_tasks.add_task(self._process_message, message)
            return {"status": "received", "message_id": message.message_id}
            
        @self.app.post("/entropy/signature")
        def receive_entropy_signature(signature: EntropySignature):
            # Convert to TemporalFingerprint object
            fingerprint = self._deserialize_fingerprint(signature)
            
            # Process fingerprint
            success = self.consensus_protocol.receive_fingerprint(fingerprint)
            
            return {
                "status": "received" if success else "failed",
                "signature_id": signature.signature_id
            }
            
        @self.app.post("/transactions/new")
        def new_transaction(tx_data: TransactionData):
            # Add transaction to blockchain
            transaction_id = self.blockchain.add_transaction(tx_data.transaction)
            
            # Broadcast to peers
            self.broadcast_message({
                "message_type": "new_transaction",
                "content": {
                    "transaction": tx_data.transaction,
                    "transaction_id": transaction_id
                }
            })
            
            return {"status": "added", "transaction_id": transaction_id}
            
        @self.app.post("/blocks/new")
        def new_block(block_data: BlockData):
            # Convert to Block object
            block = Block.from_dict(block_data.block_dict)
            
            # Validate and add to chain
            if self.blockchain.add_block(block):
                return {"status": "added", "block_hash": block.hash}
            else:
                return {"status": "rejected", "reason": "invalid block"}
                
        @self.app.get("/chain")
        def get_chain():
            return {
                "chain": self.blockchain.get_chain_data(),
                "length": len(self.blockchain.chain)
            }
    
    async def _process_message(self, message: NetworkMessage):
        """Process received network message"""
        if not message.message_id:
            message.message_id = str(uuid.uuid4())
            
        # Check if message type has a handler
        if message.message_type in self.message_handlers:
            try:
                await self.message_handlers[message.message_type](message)
            except Exception as e:
                print(f"Error processing message {message.message_type}: {e}")
        else:
            print(f"Unknown message type: {message.message_type}")
    
    async def _handle_new_block(self, message: NetworkMessage):
        """Handle incoming new block message"""
        block_dict = message.content.get("block")
        if not block_dict:
            return
            
        # Convert to Block object
        block = Block.from_dict(block_dict)
        
        # Validate and add to chain
        if self.blockchain.add_block(block):
            print(f"Added new block #{block.index} from {message.sender_id}")
            
            # Broadcast to other peers
            self.broadcast_message({
                "message_type": "new_block",
                "content": {"block": block_dict}
            }, exclude=[message.sender_id])
    
    async def _handle_new_transaction(self, message: NetworkMessage):
        """Handle incoming new transaction message"""
        transaction = message.content.get("transaction")
        transaction_id = message.content.get("transaction_id")
        
        if not transaction:
            return
            
        # Add transaction to blockchain
        local_tx_id = self.blockchain.add_transaction(transaction)
        
        print(f"Added new transaction {local_tx_id} from {message.sender_id}")
        
        # Broadcast to other peers
        self.broadcast_message({
            "message_type": "new_transaction",
            "content": {
                "transaction": transaction,
                "transaction_id": transaction_id or local_tx_id
            }
        }, exclude=[message.sender_id])
    
    async def _handle_entropy_signature(self, message: NetworkMessage):
        """Handle incoming entropy signature message"""
        signature_data = message.content.get("signature")
        if not signature_data:
            return
            
        # Convert to EntropySignature model
        signature = EntropySignature(**signature_data)
        
        # Convert to TemporalFingerprint object
        fingerprint = self._deserialize_fingerprint(signature)
        
        # Process fingerprint
        self.consensus_protocol.receive_fingerprint(fingerprint)
        
        # Broadcast to other peers
        self.broadcast_message({
            "message_type": "entropy_signature",
            "content": {"signature": signature_data}
        }, exclude=[message.sender_id])
    
    async def _handle_chain_request(self, message: NetworkMessage):
        """Handle request for blockchain data"""
        # Send our chain to the requester
        response = {
            "message_type": "chain_response",
            "content": {
                "chain": self.blockchain.get_chain_data(),
                "length": len(self.blockchain.chain)
            }
        }
        
        # Send directed message to requester
        self.send_message(message.sender_id, response)
    
    async def _handle_chain_response(self, message: NetworkMessage):
        """Handle response with blockchain data"""
        chain_data = message.content.get("chain", [])
        
        # Convert to Block objects
        competing_chain = [Block.from_dict(block_dict) for block_dict in chain_data]
        
        # Attempt fork resolution
        updated = self.blockchain.fork_resolution(competing_chain)
        
        if updated:
            print(f"Updated chain from {message.sender_id}, new length: {len(self.blockchain.chain)}")
    
    def _deserialize_fingerprint(self, signature: EntropySignature) -> TemporalFingerprint:
        """Convert EntropySignature model to TemporalFingerprint object"""
        # Decode base64 encoded signature
        entropy_sig_bytes = base64.b64decode(signature.entropy_signature)
        
        # Convert data hash if present
        data_hash = None
        if signature.data_hash:
            data_hash = base64.b64decode(signature.data_hash)
            
        # Create TemporalFingerprint
        fingerprint = TemporalFingerprint(
            node_id=signature.node_id,
            timestamp=signature.timestamp,
            data_hash=data_hash,
            entropy_signature=entropy_sig_bytes
        )
        fingerprint.signature_id = signature.signature_id
        
        return fingerprint
    
    def _serialize_fingerprint(self, fingerprint: TemporalFingerprint) -> EntropySignature:
        """Convert TemporalFingerprint to EntropySignature model"""
        # Encode bytes as base64
        entropy_sig_b64 = base64.b64encode(fingerprint.entropy_signature).decode()
        
        # Convert data hash if present
        data_hash_b64 = None
        if fingerprint.data_hash:
            data_hash_b64 = base64.b64encode(fingerprint.data_hash).decode()
            
        return EntropySignature(
            node_id=fingerprint.node_id,
            signature_id=fingerprint.signature_id,
            timestamp=fingerprint.timestamp,
            data_hash=data_hash_b64,
            entropy_signature=entropy_sig_b64
        )
    
    def start(self):
        """Start the node server"""
        if self._running:
            return
            
        self._running = True
        
        # Start server in a separate thread
        def run_server():
            uvicorn.run(self.app, host=self.host, port=self.port)
            
        self._server_thread = threading.Thread(target=run_server)
        self._server_thread.daemon = True
        self._server_thread.start()
        
        # Start background tasks
        self._start_background_tasks()
        
        print(f"Node {self.node_id[:8]} started at {self.address}")
    
    def stop(self):
        """Stop the node server"""
        self._running = False
        
        # Stop background tasks
        for task in self._tasks:
            task.cancel()
            
        print(f"Node {self.node_id[:8]} stopped")
    
    def connect_to_peer(self, address: str) -> bool:
        """Connect to a peer node by its address"""
        try:
            # Get peer info
            response = requests.get(f"{address}/node/info")
            if response.status_code != 200:
                print(f"Failed to connect to peer at {address}: {response.status_code}")
                return False
                
            peer_info = response.json()
            
            # Create NodeInfo object
            node = NodeInfo(
                node_id=peer_info["node_id"],
                address=address,
                port=peer_info["port"],
                metadata={"discovered_at": time.time()}
            )
            
            # Register peer locally
            self.peers[node.node_id] = node
            
            # Register with consensus protocol
            self.consensus_protocol.register_node(
                node.node_id, 
                {"address": node.address, "port": node.port}
            )
            
            # Register self with the peer
            self_info = NodeInfo(
                node_id=self.node_id,
                address=self.address,
                port=self.port
            )
            
            response = requests.post(
                f"{address}/peers/register",
                json=self_info.dict()
            )
            
            if response.status_code != 200:
                print(f"Failed to register with peer at {address}: {response.status_code}")
                return False
                
            print(f"Connected to peer {node.node_id[:8]} at {address}")
            
            # Request peer's chain to check for updates
            self.request_chain(node.node_id)
            
            return True
            
        except Exception as e:
            print(f"Error connecting to peer at {address}: {e}")
            return False
    
    def discover_peers(self, initial_peer: str = None):
        """Discover peers from connected nodes"""
        if initial_peer:
            self.connect_to_peer(initial_peer)
            
        for peer_id, peer in list(self.peers.items()):
            try:
                # Get peer's peers
                response = requests.get(f"{peer.address}/peers")
                if response.status_code != 200:
                    continue
                    
                peers_data = response.json().get("peers", [])
                
                # Connect to new peers
                for peer_data in peers_data:
                    peer_address = peer_data.get("address")
                    if peer_address and peer_data.get("node_id") != self.node_id:
                        if peer_data.get("node_id") not in self.peers:
                            self.connect_to_peer(peer_address)
                            
            except Exception as e:
                print(f"Error discovering peers from {peer_id}: {e}")
    
    def broadcast_entropy_signature(self):
        """Broadcast node's entropy signature to all peers"""
        # Create a new temporal fingerprint
        fingerprint = self.consensus_protocol.create_temporal_fingerprint()
        
        # Convert to EntropySignature model
        signature = self._serialize_fingerprint(fingerprint)
        
        # Broadcast to all peers
        self.broadcast_message({
            "message_type": "entropy_signature",
            "content": {"signature": signature.dict()}
        })
    
    def broadcast_block(self, block: Block):
        """Broadcast a new block to all peers"""
        # Convert to dictionary
        block_dict = block.to_dict()
        
        # Broadcast to all peers
        self.broadcast_message({
            "message_type": "new_block",
            "content": {"block": block_dict}
        })
    
    def request_chain(self, peer_id: str):
        """Request blockchain data from a specific peer"""
        if peer_id not in self.peers:
            print(f"Unknown peer: {peer_id}")
            return
            
        # Send chain request message
        self.send_message(peer_id, {
            "message_type": "chain_request",
            "content": {}
        })
    
    def mine_block(self) -> Block:
        """Create and validate a new block with pending transactions"""
        # Create new block
        block = self.blockchain.create_block()
        
        # Validate and add to chain
        if self.blockchain.add_block(block):
            print(f"Mined new block #{block.index} with hash {block.hash[:8]}")
            
            # Broadcast to peers
            self.broadcast_block(block)
            
            return block
        else:
            print(f"Failed to mine block #{block.index}")
            return None
    
    def send_message(self, peer_id: str, message_data: Dict):
        """Send a message to a specific peer"""
        if peer_id not in self.peers:
            print(f"Unknown peer: {peer_id}")
            return False
            
        peer = self.peers[peer_id]
        
        # Create full message
        message = NetworkMessage(
            message_type=message_data["message_type"],
            sender_id=self.node_id,
            content=message_data["content"],
            timestamp=time.time(),
            message_id=message_data.get("message_id", str(uuid.uuid4()))
        )
        
        try:
            # Send message to peer
            response = requests.post(
                f"{peer.address}/message",
                json=message.dict()
            )
            
            return response.status_code == 200
            
        except Exception as e:
            print(f"Error sending message to {peer_id}: {e}")
            return False
    
    def broadcast_message(self, message_data: Dict, exclude: List[str] = None):
        """Broadcast a message to all peers except those in exclude list"""
        if exclude is None:
            exclude = []
            
        # Create full message
        message = NetworkMessage(
            message_type=message_data["message_type"],
            sender_id=self.node_id,
            content=message_data["content"],
            timestamp=time.time(),
            message_id=message_data.get("message_id", str(uuid.uuid4()))
        )
        
        # Send to all peers except excluded
        for peer_id, peer in self.peers.items():
            if peer_id not in exclude:
                try:
                    requests.post(
                        f"{peer.address}/message",
                        json=message.dict(),
                        timeout=2.0  # Short timeout to prevent blocking
                    )
                except Exception as e:
                    print(f"Error broadcasting to {peer_id}: {e}")
    
    def _start_background_tasks(self):
        """Start background tasks for node operation"""
        
        # Task to periodically broadcast entropy signature
        async def entropy_broadcast_task():
            while self._running:
                self.broadcast_entropy_signature()
                await asyncio.sleep(10)  # Broadcast every 10 seconds
                
        # Task to mine blocks when enough transactions are pending
        async def mining_task():
            while self._running:
                # Check if we have pending transactions
                if len(self.blockchain.pending_transactions) >= 1:
                    self.mine_block()
                await asyncio.sleep(15)  # Check every 15 seconds
                
        # Task to discover new peers
        async def peer_discovery_task():
            while self._running:
                self.discover_peers()
                await asyncio.sleep(60)  # Discover every 60 seconds
                
        # Task to remove inactive peers
        async def cleanup_task():
            while self._running:
                # Remove inactive nodes from consensus protocol
                self.consensus_protocol.remove_inactive_nodes(timeout=300)
                await asyncio.sleep(120)  # Run every 2 minutes
                
        # Start all tasks
        loop = asyncio.get_event_loop()
        self._tasks = [
            loop.create_task(entropy_broadcast_task()),
            loop.create_task(mining_task()),
            loop.create_task(peer_discovery_task()),
            loop.create_task(cleanup_task())
        ]
