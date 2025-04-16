"""
Blockchain Module

This module implements the core blockchain data structure
using the Temporal Consensus Protocol.
"""

import time
import hashlib
import json
from typing import Dict, List, Optional, Any, Set
import uuid
from ..consensus.protocol import TemporalConsensusProtocol, TemporalFingerprint

class Block:
    """
    Represents a block in the blockchain with temporal signatures
    for validation and consensus.
    """
    
    def __init__(self, index: int, timestamp: float = None, 
               previous_hash: str = None, transactions: List[Dict] = None):
        self.index = index
        self.timestamp = timestamp or time.time()
        self.previous_hash = previous_hash
        self.transactions = transactions or []
        self.merkle_root = self._calculate_merkle_root()
        self.temporal_fingerprints: List[TemporalFingerprint] = []
        self.hash = self._calculate_hash()
        self.validated = False
        self.block_id = str(uuid.uuid4())
        
    def _calculate_merkle_root(self) -> str:
        """Calculate Merkle root of transactions"""
        if not self.transactions:
            return hashlib.sha256(b'empty_block').hexdigest()
            
        # Hash each transaction
        transaction_hashes = [
            hashlib.sha256(json.dumps(tx, sort_keys=True).encode()).hexdigest()
            for tx in self.transactions
        ]
        
        # Build Merkle tree
        while len(transaction_hashes) > 1:
            # If odd number of hashes, duplicate the last one
            if len(transaction_hashes) % 2 != 0:
                transaction_hashes.append(transaction_hashes[-1])
                
            # Pair up hashes and combine them
            next_level = []
            for i in range(0, len(transaction_hashes), 2):
                combined = transaction_hashes[i] + transaction_hashes[i+1]
                next_level.append(hashlib.sha256(combined.encode()).hexdigest())
                
            transaction_hashes = next_level
            
        return transaction_hashes[0]
        
    def _calculate_hash(self) -> str:
        """Calculate block hash incorporating temporal elements"""
        block_data = {
            "index": self.index,
            "timestamp": self.timestamp,
            "previous_hash": self.previous_hash,
            "merkle_root": self.merkle_root,
            "temporal_fingerprints": [
                fp.signature_id for fp in self.temporal_fingerprints
            ],
        }
        
        # Serialize and hash
        block_string = json.dumps(block_data, sort_keys=True)
        return hashlib.sha256(block_string.encode()).hexdigest()
        
    def add_temporal_fingerprint(self, fingerprint: TemporalFingerprint) -> None:
        """Add a temporal fingerprint to the block"""
        self.temporal_fingerprints.append(fingerprint)
        # Recalculate hash when fingerprints change
        self.hash = self._calculate_hash()
        
    def to_dict(self) -> Dict:
        """Convert block to dictionary for serialization"""
        return {
            "index": self.index,
            "timestamp": self.timestamp,
            "previous_hash": self.previous_hash,
            "hash": self.hash,
            "merkle_root": self.merkle_root,
            "transactions": self.transactions,
            "temporal_fingerprints": [
                json.loads(fp.serialize().decode()) for fp in self.temporal_fingerprints
            ],
            "validated": self.validated,
            "block_id": self.block_id
        }
        
    @classmethod
    def from_dict(cls, block_dict: Dict) -> 'Block':
        """Create block from dictionary"""
        block = cls(
            index=block_dict["index"],
            timestamp=block_dict["timestamp"],
            previous_hash=block_dict["previous_hash"],
            transactions=block_dict["transactions"]
        )
        
        block.merkle_root = block_dict["merkle_root"]
        block.hash = block_dict["hash"]
        block.validated = block_dict.get("validated", False)
        block.block_id = block_dict.get("block_id", str(uuid.uuid4()))
        
        # Deserialize fingerprints
        for fp_dict in block_dict.get("temporal_fingerprints", []):
            fp_bytes = json.dumps(fp_dict, sort_keys=True).encode()
            fingerprint = TemporalFingerprint.deserialize(fp_bytes)
            block.temporal_fingerprints.append(fingerprint)
            
        return block
        
    def verify(self) -> bool:
        """Verify the block's integrity"""
        # Check hash integrity
        calculated_hash = self._calculate_hash()
        if calculated_hash != self.hash:
            return False
            
        # Verify merkle root
        if self._calculate_merkle_root() != self.merkle_root:
            return False
            
        return True

class TemporalBlockchain:
    """
    Implementation of a blockchain using the Temporal Consensus Protocol
    for energy-efficient and secure distributed consensus.
    """
    
    def __init__(self, node_id: str = None):
        self.chain: List[Block] = []
        self.node_id = node_id or str(uuid.uuid4())
        self.pending_transactions: List[Dict] = []
        self.consensus_protocol = TemporalConsensusProtocol(node_id=self.node_id)
        
        # Create genesis block
        self._create_genesis_block()
        
    def _create_genesis_block(self) -> None:
        """Create the genesis block to initialize the chain"""
        genesis_fingerprint = self.consensus_protocol.create_temporal_fingerprint({"type": "genesis"})
        genesis_block = Block(0, time.time(), "0", [{"type": "genesis"}])
        genesis_block.add_temporal_fingerprint(genesis_fingerprint)
        genesis_block.validated = True
        
        self.chain.append(genesis_block)
        
    @property
    def last_block(self) -> Block:
        """Get the last block in the chain"""
        return self.chain[-1]
        
    def add_transaction(self, transaction: Dict) -> str:
        """Add a transaction to pending transactions"""
        # Add to pending transactions
        self.pending_transactions.append(transaction)
        
        # Propose to consensus protocol
        result = self.consensus_protocol.propose_transaction(transaction)
        
        return result["transaction_id"]
        
    def create_block(self) -> Block:
        """
        Create a new block with pending transactions using
        temporal fingerprinting for consensus
        """
        # Validate transactions through consensus protocol
        valid_transactions = []
        for tx in self.pending_transactions[:]:
            # Get validated transactions from consensus protocol
            valid_txs = {
                txid: tx_data for txid, tx_data in 
                self.consensus_protocol.validated_transactions.items()
            }
            
            # Find matching transaction in our pending list
            for txid, tx_data in valid_txs.items():
                if tx == tx_data["data"]:
                    valid_transactions.append(tx)
                    self.pending_transactions.remove(tx)
                    
        # Create new block
        index = len(self.chain)
        timestamp = time.time()
        previous_hash = self.last_block.hash
        
        new_block = Block(index, timestamp, previous_hash, valid_transactions)
        
        # Create temporal fingerprint for the block
        block_fingerprint = self.consensus_protocol.create_temporal_fingerprint(new_block.to_dict())
        new_block.add_temporal_fingerprint(block_fingerprint)
        
        return new_block
        
    def validate_block(self, block: Block, min_validations: int = 3) -> bool:
        """
        Validate a block using temporal consensus
        with multiple node validations
        """
        if not block.verify():
            return False
            
        # Check if block index is valid
        if block.index != len(self.chain):
            return False
            
        # Check if previous hash matches
        if block.previous_hash != self.last_block.hash:
            return False
            
        # Validate temporal fingerprints
        valid_fingerprints = 0
        for fingerprint in block.temporal_fingerprints:
            validation = self.consensus_protocol.validate_fingerprint(fingerprint)
            if validation["valid"]:
                valid_fingerprints += 1
                
        # Block is valid if it has enough valid fingerprints
        block.validated = valid_fingerprints >= min_validations
        
        return block.validated
        
    def add_block(self, block: Block) -> bool:
        """
        Add a validated block to the chain
        Returns True if the block was added successfully
        """
        # Validate block
        if not self.validate_block(block):
            return False
            
        # Add to chain
        self.chain.append(block)
        
        # Update the hash (required if fingerprints were added during validation)
        block.hash = block._calculate_hash()
        
        return True
        
    def fork_resolution(self, competing_chain: List[Block]) -> bool:
        """
        Resolve competing chains by selecting the one with
        higher temporal consensus quality
        Returns True if our chain was updated
        """
        if len(competing_chain) <= len(self.chain):
            # Our chain is longer, no action needed
            return False
            
        # Verify the entire competing chain
        for i in range(len(competing_chain)):
            block = competing_chain[i]
            
            # Skip genesis block validation for competing chain
            if i == 0:
                if block.index != 0:
                    return False
                continue
                
            # For other blocks, validate links and fingerprints
            if block.previous_hash != competing_chain[i-1].hash:
                return False
                
            if not block.verify():
                return False
                
        # Calculate temporal consensus quality for both chains
        our_quality = self._calculate_chain_quality(self.chain)
        competing_quality = self._calculate_chain_quality(competing_chain)
        
        # If competing chain has better quality and is longer, accept it
        if competing_quality >= our_quality and len(competing_chain) > len(self.chain):
            # Replace our chain with the competing one
            self.chain = competing_chain
            return True
            
        return False
        
    def _calculate_chain_quality(self, chain: List[Block]) -> float:
        """
        Calculate the temporal consensus quality of a chain
        based on fingerprint validations
        """
        if not chain:
            return 0.0
            
        total_fingerprints = 0
        total_quality = 0.0
        
        for block in chain:
            # Skip genesis block in quality calculation
            if block.index == 0:
                continue
                
            fingerprints = block.temporal_fingerprints
            
            if not fingerprints:
                continue
                
            for fingerprint in fingerprints:
                validation = self.consensus_protocol.validate_fingerprint(fingerprint)
                total_quality += validation.get("confidence", 0.0)
                total_fingerprints += 1
                
        if total_fingerprints == 0:
            return 0.0
            
        return total_quality / total_fingerprints
        
    def verify_chain(self) -> bool:
        """Verify the integrity of the entire chain"""
        for i in range(1, len(self.chain)):
            current = self.chain[i]
            previous = self.chain[i-1]
            
            # Verify hash integrity
            if not current.verify():
                return False
                
            # Verify chain links
            if current.previous_hash != previous.hash:
                return False
                
        return True
        
    def get_chain_data(self) -> List[Dict]:
        """Get the chain as a list of dictionaries for serialization"""
        return [block.to_dict() for block in self.chain]
        
    def save_chain(self, filename: str) -> bool:
        """Save the blockchain to a file"""
        try:
            chain_data = self.get_chain_data()
            with open(filename, 'w') as file:
                json.dump(chain_data, file, indent=2)
            return True
        except Exception as e:
            print(f"Error saving blockchain: {e}")
            return False
            
    @classmethod
    def load_chain(cls, filename: str, node_id: str = None) -> 'TemporalBlockchain':
        """Load a blockchain from a file"""
        blockchain = cls(node_id=node_id)
        
        try:
            with open(filename, 'r') as file:
                chain_data = json.load(file)
                
            # Clear current chain and load saved one
            blockchain.chain = []
            
            for block_dict in chain_data:
                block = Block.from_dict(block_dict)
                blockchain.chain.append(block)
                
            return blockchain
            
        except Exception as e:
            print(f"Error loading blockchain: {e}")
            # Return a fresh blockchain with genesis block
            return blockchain
