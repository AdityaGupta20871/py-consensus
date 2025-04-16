"""
Temporal Consensus Protocol

This module implements the core consensus protocol using temporal
entropy measurements for secure and energy-efficient consensus.
"""

import time
import hashlib
import json
from typing import Dict, List, Set, Optional, Tuple, Any
import uuid
import math
import numpy as np
from ..entropy.collector import EntropyCollector
from ..entropy.analyzer import EntropyAnalyzer

class TemporalFingerprint:
    """
    Represents a temporal fingerprint used for transaction
    and block validation in the consensus protocol.
    """
    
    def __init__(self, node_id: str, timestamp: float = None, 
               data_hash: bytes = None, entropy_signature: bytes = None):
        self.node_id = node_id
        self.timestamp = timestamp or time.time()
        self.data_hash = data_hash
        self.entropy_signature = entropy_signature
        self.signature_id = str(uuid.uuid4())
        
    def serialize(self) -> bytes:
        """Serialize the fingerprint to bytes"""
        fingerprint_dict = {
            "node_id": self.node_id,
            "timestamp": self.timestamp,
            "data_hash": self.data_hash.hex() if self.data_hash else None,
            "entropy_signature": self.entropy_signature.hex() if self.entropy_signature else None,
            "signature_id": self.signature_id
        }
        
        json_str = json.dumps(fingerprint_dict, sort_keys=True)
        return json_str.encode()
        
    @classmethod
    def deserialize(cls, serialized_data: bytes) -> 'TemporalFingerprint':
        """Deserialize bytes into a TemporalFingerprint object"""
        fingerprint_dict = json.loads(serialized_data.decode())
        
        # Convert hex strings back to bytes
        if fingerprint_dict.get('data_hash'):
            fingerprint_dict['data_hash'] = bytes.fromhex(fingerprint_dict['data_hash'])
        if fingerprint_dict.get('entropy_signature'):
            fingerprint_dict['entropy_signature'] = bytes.fromhex(fingerprint_dict['entropy_signature'])
            
        fingerprint = cls(
            node_id=fingerprint_dict.get('node_id'),
            timestamp=fingerprint_dict.get('timestamp'),
            data_hash=fingerprint_dict.get('data_hash'),
            entropy_signature=fingerprint_dict.get('entropy_signature')
        )
        fingerprint.signature_id = fingerprint_dict.get('signature_id')
        
        return fingerprint
        
    def get_signature(self) -> bytes:
        """
        Get cryptographic signature of the fingerprint
        combining all temporal and entropy elements
        """
        timestamp_bytes = str(self.timestamp).encode()
        node_id_bytes = self.node_id.encode()
        signature_id_bytes = self.signature_id.encode()
        
        elements = [
            timestamp_bytes,
            node_id_bytes,
            self.data_hash or b'',
            self.entropy_signature or b'',
            signature_id_bytes
        ]
        
        # Combine all elements for final signature
        combined = b''.join(elements)
        return hashlib.sha256(combined).digest()

class ConsensusParameters:
    """
    Defines the parameters and thresholds for the
    Temporal Consensus Protocol.
    """
    
    def __init__(self):
        # Validation thresholds
        self.min_valid_signatures = 3
        self.min_validation_confidence = 0.7
        self.max_temporal_deviation = 5.0  # Maximum allowed time difference in seconds
        
        # Network parameters
        self.max_node_response_time = 30.0  # Maximum time to wait for node responses
        self.min_network_participation = 0.51  # Minimum percentage of nodes that must participate
        
        # Temporal fingerprinting parameters
        self.entropy_window_size = 10
        self.signature_freshness_timeout = 60.0  # Seconds before a signature is considered stale
        
        # Anti-gaming measures
        self.manipulation_detection_threshold = 0.65
        self.max_consecutive_blocks = 3  # Max consecutive blocks from same node
        
        # Dynamic difficulty adjustment
        self.difficulty_adjustment_interval = 10  # Blocks
        self.target_block_time = 15.0  # Target seconds between blocks
        self.difficulty_adjustment_factor = 0.25  # How quickly difficulty adjusts
        
    def adjust_for_network_state(self, network_state: Dict):
        """
        Adjust consensus parameters based on current network state
        to optimize for security and performance
        """
        if 'node_count' in network_state:
            # Scale min_valid_signatures based on network size
            self.min_valid_signatures = max(3, int(network_state['node_count'] * 0.1))
            
        if 'entropy_consensus_quality' in network_state:
            quality = network_state['entropy_consensus_quality']
            # Adjust validation confidence based on overall entropy quality
            self.min_validation_confidence = max(0.6, min(0.9, 0.7 + (quality - 0.5) * 0.4))
            
            # Adjust temporal deviation allowance
            if quality > 0.8:
                # High quality network can be stricter
                self.max_temporal_deviation = 3.0
            elif quality < 0.4:
                # Lower quality network needs more allowance
                self.max_temporal_deviation = 8.0
                
        # Return the adjusted parameters
        return {
            'min_valid_signatures': self.min_valid_signatures,
            'min_validation_confidence': self.min_validation_confidence,
            'max_temporal_deviation': self.max_temporal_deviation,
            'min_network_participation': self.min_network_participation
        }

class TemporalConsensusProtocol:
    """
    Implementation of the Temporal Consensus Protocol (TCP)
    using entropy-based validation and temporal fingerprinting.
    """
    
    def __init__(self, node_id: str = None):
        self.node_id = node_id or str(uuid.uuid4())
        self.entropy_collector = EntropyCollector()
        self.entropy_analyzer = EntropyAnalyzer()
        self.consensus_params = ConsensusParameters()
        
        # Track participating nodes
        self.active_nodes: Set[str] = set()
        self.node_last_activity: Dict[str, float] = {}
        self.node_fingerprints: Dict[str, List[TemporalFingerprint]] = {}
        
        # Consensus state
        self.current_validation_round = 0
        self.validation_round_results: Dict[int, Dict] = {}
        self.pending_transactions: Dict[str, Dict] = {}
        self.validated_transactions: Dict[str, Dict] = {}
        
        # Register self in analyzer
        self.entropy_analyzer.register_node(self.node_id, {"is_self": True})
        self.active_nodes.add(self.node_id)
        
        # Start entropy collection
        self.entropy_collector.start_collection(interval=1.0)
        
    def register_node(self, node_id: str, node_info: Dict = None):
        """Register a node in the consensus network"""
        self.active_nodes.add(node_id)
        self.node_last_activity[node_id] = time.time()
        self.entropy_analyzer.register_node(node_id, node_info)
        self.node_fingerprints[node_id] = []
        
    def remove_inactive_nodes(self, timeout: float = 300.0):
        """Remove nodes that have been inactive for longer than timeout"""
        current_time = time.time()
        inactive_nodes = [
            node_id for node_id, last_active in self.node_last_activity.items()
            if current_time - last_active > timeout
        ]
        
        for node_id in inactive_nodes:
            self.active_nodes.discard(node_id)
            self.node_fingerprints.pop(node_id, None)
            
    def create_temporal_fingerprint(self, data: Any = None) -> TemporalFingerprint:
        """
        Create a temporal fingerprint for data using the current
        entropy state and temporal information
        """
        # Generate entropy signature
        entropy_signature = self.entropy_collector.get_temporal_signature(
            time_window=self.consensus_params.entropy_window_size
        )
        
        # Create data hash if data was provided
        data_hash = None
        if data is not None:
            if isinstance(data, bytes):
                data_hash = hashlib.sha256(data).digest()
            elif isinstance(data, str):
                data_hash = hashlib.sha256(data.encode()).digest()
            else:
                # Convert to JSON and hash
                data_str = json.dumps(data, sort_keys=True)
                data_hash = hashlib.sha256(data_str.encode()).digest()
                
        # Create and return the fingerprint
        fingerprint = TemporalFingerprint(
            node_id=self.node_id,
            timestamp=time.time(),
            data_hash=data_hash,
            entropy_signature=entropy_signature
        )
        
        # Store own fingerprint
        if self.node_id not in self.node_fingerprints:
            self.node_fingerprints[self.node_id] = []
        self.node_fingerprints[self.node_id].append(fingerprint)
        
        return fingerprint
        
    def receive_fingerprint(self, fingerprint: TemporalFingerprint) -> bool:
        """
        Process a received fingerprint from another node
        Returns True if the fingerprint is accepted
        """
        # Check if node is known
        if fingerprint.node_id not in self.active_nodes:
            self.register_node(fingerprint.node_id)
            
        # Update node's last activity time
        self.node_last_activity[fingerprint.node_id] = time.time()
        
        # Record the entropy signature
        self.entropy_analyzer.record_entropy_signature(
            fingerprint.node_id, 
            fingerprint.entropy_signature,
            fingerprint.timestamp,
            1.0  # Default weight
        )
        
        # Store the fingerprint
        if fingerprint.node_id not in self.node_fingerprints:
            self.node_fingerprints[fingerprint.node_id] = []
        self.node_fingerprints[fingerprint.node_id].append(fingerprint)
        
        # Only keep recent fingerprints to avoid memory bloat
        max_fingerprints = 100
        if len(self.node_fingerprints[fingerprint.node_id]) > max_fingerprints:
            self.node_fingerprints[fingerprint.node_id] = self.node_fingerprints[fingerprint.node_id][-max_fingerprints:]
            
        return True
        
    def validate_fingerprint(self, fingerprint: TemporalFingerprint) -> Dict:
        """
        Validate a fingerprint against the consensus rules
        Returns validation results with metrics
        """
        validation_results = {
            "valid": False,
            "confidence": 0.0,
            "reasons": []
        }
        
        # Check 1: Temporal validity
        current_time = time.time()
        time_diff = abs(current_time - fingerprint.timestamp)
        
        temporal_valid = time_diff <= self.consensus_params.max_temporal_deviation
        if not temporal_valid:
            validation_results["reasons"].append(
                f"Temporal deviation too high: {time_diff:.2f}s > {self.consensus_params.max_temporal_deviation:.2f}s"
            )
            
        # Check 2: Entropy signature validation
        # Collect reference signatures from other nodes
        reference_signatures = []
        for node_id in self.active_nodes:
            if node_id != fingerprint.node_id and node_id in self.node_fingerprints and self.node_fingerprints[node_id]:
                # Get most recent fingerprint from each node
                ref_fingerprint = self.node_fingerprints[node_id][-1]
                reference_signatures.append((node_id, ref_fingerprint.entropy_signature))
                
        # Validate entropy signature
        entropy_validation = self.entropy_analyzer.validate_signature(
            fingerprint.node_id,
            fingerprint.entropy_signature,
            reference_signatures
        )
        
        entropy_valid = entropy_validation.get("valid", False)
        entropy_confidence = entropy_validation.get("confidence", 0.0)
        
        if not entropy_valid:
            validation_results["reasons"].append(
                f"Entropy validation failed: confidence {entropy_confidence:.2f} < " +
                f"{self.consensus_params.min_validation_confidence:.2f}"
            )
            
        # Check 3: Manipulation detection
        manipulation_check = self.entropy_analyzer.detect_entropy_manipulation(
            fingerprint.node_id,
            fingerprint.entropy_signature
        )
        
        no_manipulation = not manipulation_check.get("manipulation_detected", False)
        if not no_manipulation:
            validation_results["reasons"].append(
                f"Potential entropy manipulation detected: {manipulation_check.get('confidence', 0):.2f}"
            )
            
        # Combine all validation results
        validation_results["valid"] = temporal_valid and entropy_valid and no_manipulation
        
        # Calculate overall confidence
        # Weight the different factors based on importance
        validation_results["confidence"] = (
            (0.3 * (1.0 - min(1.0, time_diff / self.consensus_params.max_temporal_deviation))) +
            (0.5 * entropy_confidence) +
            (0.2 * (1.0 - manipulation_check.get("confidence", 0)))
        )
        
        # Add detailed metrics
        validation_results["metrics"] = {
            "temporal_deviation": time_diff,
            "entropy_confidence": entropy_confidence,
            "manipulation_likelihood": manipulation_check.get("confidence", 0)
        }
        
        return validation_results
        
    def propose_transaction(self, transaction_data: Dict) -> Dict:
        """
        Propose a new transaction to the network by creating
        a temporal fingerprint for it
        """
        # Generate transaction ID
        transaction_id = str(uuid.uuid4())
        
        # Create fingerprint for the transaction
        fingerprint = self.create_temporal_fingerprint(transaction_data)
        
        # Store transaction in pending transactions
        self.pending_transactions[transaction_id] = {
            "data": transaction_data,
            "proposer": self.node_id,
            "timestamp": time.time(),
            "fingerprint": fingerprint,
            "validations": {},
            "status": "pending"
        }
        
        return {
            "transaction_id": transaction_id,
            "fingerprint": fingerprint,
            "status": "proposed"
        }
        
    def validate_transaction(self, transaction_id: str, 
                          validator_fingerprint: TemporalFingerprint) -> Dict:
        """
        Validate a transaction with a temporal fingerprint
        from a validator node
        """
        result = {
            "transaction_id": transaction_id,
            "valid": False,
            "status": "unknown"
        }
        
        # Check if transaction exists
        if transaction_id not in self.pending_transactions:
            result["error"] = "Transaction not found"
            return result
            
        transaction = self.pending_transactions[transaction_id]
        
        # Validate the validator's fingerprint
        validator_validation = self.validate_fingerprint(validator_fingerprint)
        if not validator_validation["valid"]:
            result["error"] = f"Validator fingerprint invalid: {validator_validation['reasons']}"
            return result
            
        # Store the validation
        transaction["validations"][validator_fingerprint.node_id] = {
            "fingerprint": validator_fingerprint,
            "timestamp": time.time(),
            "validation": validator_validation
        }
        
        # Check if we have enough validations
        validations_count = len(transaction["validations"])
        min_required = self.consensus_params.min_valid_signatures
        
        # Calculate average validation confidence
        if validations_count > 0:
            confidence_sum = sum(
                v["validation"]["confidence"] for v in transaction["validations"].values()
            )
            avg_confidence = confidence_sum / validations_count
            
            # Update transaction status based on validations
            if validations_count >= min_required and avg_confidence >= self.consensus_params.min_validation_confidence:
                transaction["status"] = "validated"
                
                # Move to validated transactions if fully validated
                if transaction["status"] == "validated":
                    self.validated_transactions[transaction_id] = transaction
                    self.pending_transactions.pop(transaction_id, None)
        
        # Update result with current status
        result["valid"] = validator_validation["valid"]
        result["status"] = transaction["status"]
        result["validations_count"] = validations_count
        result["required_validations"] = min_required
        
        return result
        
    def get_consensus_metrics(self) -> Dict:
        """
        Get current metrics about the consensus state
        to inform protocol adjustments
        """
        # Get current network entropy state
        network_state = self.entropy_analyzer.get_network_entropy_state(self.active_nodes)
        
        # Collect transaction statistics
        pending_count = len(self.pending_transactions)
        validated_count = len(self.validated_transactions)
        
        # Calculate average validation times for recent transactions
        validation_times = []
        for tx_id, tx in self.validated_transactions.items():
            if "timestamp" in tx and tx.get("status") == "validated":
                first_validation = min(
                    val.get("timestamp", float("inf")) 
                    for val in tx.get("validations", {}).values()
                )
                if first_validation != float("inf"):
                    validation_times.append(first_validation - tx["timestamp"])
                    
        avg_validation_time = sum(validation_times) / len(validation_times) if validation_times else 0
        
        # Get adjusted consensus parameters
        adjusted_params = self.consensus_params.adjust_for_network_state(network_state)
        
        # Combine all metrics
        return {
            "network_entropy_state": network_state,
            "active_nodes": len(self.active_nodes),
            "pending_transactions": pending_count,
            "validated_transactions": validated_count,
            "avg_validation_time": avg_validation_time,
            "consensus_parameters": adjusted_params,
            "timestamp": time.time()
        }
