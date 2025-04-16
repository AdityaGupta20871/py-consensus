"""
Entropy Analyzer Module

This module provides tools to analyze entropy measurements,
detect patterns, and validate entropy signatures for consensus.
"""

import hashlib
import time
import math
import numpy as np
from typing import Dict, List, Tuple, Optional, Set
from .collector import EntropyCollector

class EntropyAnalyzer:
    """
    Analyzes entropy measurements to detect patterns, validate
    signatures, and provide metrics for consensus decisions.
    """
    
    def __init__(self, min_samples: int = 10):
        self.min_samples = min_samples
        self.entropy_history: Dict[str, List[Tuple[bytes, float, float]]] = {}
        self.node_registry: Dict[str, Dict] = {}
        self.confidence_thresholds = {
            "high": 0.85,
            "medium": 0.65,
            "low": 0.50
        }
        
    def register_node(self, node_id: str, public_info: Dict = None):
        """Register a node in the analyzer for entropy tracking"""
        if node_id not in self.node_registry:
            self.node_registry[node_id] = {
                "registration_time": time.time(),
                "public_info": public_info or {},
                "trust_score": 0.5,  # Initial neutral trust score
                "signature_count": 0
            }
            self.entropy_history[node_id] = []
            
    def record_entropy_signature(self, node_id: str, signature: bytes, 
                               timestamp: float, weight: float):
        """Record an entropy signature from a node"""
        if node_id not in self.node_registry:
            # Auto-register unknown nodes with low initial trust
            self.register_node(node_id, {"auto_registered": True})
            
        # Store the signature with timestamp and weight
        self.entropy_history[node_id].append((signature, timestamp, weight))
        
        # Update node's signature count
        self.node_registry[node_id]["signature_count"] += 1
        
        # Limit history size to prevent memory bloat
        max_history = 1000
        if len(self.entropy_history[node_id]) > max_history:
            self.entropy_history[node_id] = self.entropy_history[node_id][-max_history:]
            
    def calculate_entropy_distance(self, sig1: bytes, sig2: bytes) -> float:
        """
        Calculate normalized Hamming distance between two entropy signatures
        to measure their dissimilarity
        """
        if len(sig1) != len(sig2):
            raise ValueError("Signatures must be of the same length")
            
        # Convert to binary strings for bit-by-bit comparison
        bin_sig1 = ''.join(format(b, '08b') for b in sig1)
        bin_sig2 = ''.join(format(b, '08b') for b in sig2)
        
        # Calculate Hamming distance
        distance = sum(b1 != b2 for b1, b2 in zip(bin_sig1, bin_sig2))
        
        # Normalize by total bits
        return distance / len(bin_sig1)
    
    def analyze_temporal_distribution(self, node_id: str, 
                                   window_size: int = 20) -> Dict:
        """
        Analyze the temporal distribution of entropy signatures
        to detect patterns and anomalies
        """
        if node_id not in self.entropy_history:
            return {"error": "Node not found in history"}
            
        history = self.entropy_history[node_id]
        if len(history) < self.min_samples:
            return {"error": f"Insufficient samples, need at least {self.min_samples}"}
            
        # Get most recent window_size samples
        recent_window = history[-window_size:]
        
        # Extract timestamps and convert signatures to distance metrics
        timestamps = [entry[1] for entry in recent_window]
        signatures = [entry[0] for entry in recent_window]
        
        # Calculate temporal regularity through timestamp differences
        time_diffs = [timestamps[i+1] - timestamps[i] for i in range(len(timestamps)-1)]
        time_regularity = {
            "mean": np.mean(time_diffs),
            "std_dev": np.std(time_diffs),
            "min": min(time_diffs),
            "max": max(time_diffs),
            "coefficient_of_variation": np.std(time_diffs) / np.mean(time_diffs) if np.mean(time_diffs) > 0 else 0
        }
        
        # Calculate entropy signature variability through pairwise distances
        distances = []
        for i in range(len(signatures)-1):
            distances.append(self.calculate_entropy_distance(signatures[i], signatures[i+1]))
            
        signature_variability = {
            "mean_distance": np.mean(distances),
            "std_dev_distance": np.std(distances),
            "min_distance": min(distances) if distances else 0,
            "max_distance": max(distances) if distances else 0
        }
        
        # Overall entropy quality metrics
        entropy_quality = {
            "temporal_regularity": time_regularity,
            "signature_variability": signature_variability
        }
        
        return entropy_quality
    
    def validate_signature(self, node_id: str, signature: bytes, 
                         reference_signatures: List[Tuple[str, bytes]] = None) -> Dict:
        """
        Validate an entropy signature against known patterns
        and reference signatures from other nodes
        """
        validation_results = {
            "valid": False,
            "confidence": 0.0,
            "anomaly_score": 0.0,
            "reference_distances": {}
        }
        
        # Check if node has history
        if node_id not in self.entropy_history:
            validation_results["error"] = "Node has no entropy history"
            return validation_results
            
        # If no reference signatures provided, use the node's own history
        if not reference_signatures:
            # Need minimum samples for self-validation
            if len(self.entropy_history[node_id]) < self.min_samples:
                validation_results["error"] = f"Insufficient history for node {node_id}"
                return validation_results
                
            # Use recent signatures from node's history
            history = self.entropy_history[node_id]
            recent_signatures = [entry[0] for entry in history[-self.min_samples:]]
            
            # Calculate distances to historical signatures
            distances = [self.calculate_entropy_distance(signature, hist_sig) 
                        for hist_sig in recent_signatures]
            
            # Calculate statistics on distances
            mean_distance = np.mean(distances)
            std_dev = np.std(distances)
            
            # Determine validity based on deviation from historical patterns
            # Lower distance = more similar to history = more likely valid
            threshold = 0.4  # Maximum acceptable normalized Hamming distance
            validation_results["valid"] = mean_distance < threshold
            validation_results["confidence"] = 1.0 - (mean_distance / 0.5)  # 0.5 is max theoretical distance
            validation_results["anomaly_score"] = (mean_distance - np.mean(distances)) / std_dev if std_dev > 0 else 0
            
        else:
            # Validate against reference signatures from other nodes
            distances = {}
            for ref_node_id, ref_sig in reference_signatures:
                distance = self.calculate_entropy_distance(signature, ref_sig)
                distances[ref_node_id] = distance
                
            # Store all distances
            validation_results["reference_distances"] = distances
            
            # Calculate overall metrics
            mean_distance = np.mean(list(distances.values()))
            validation_results["valid"] = mean_distance < 0.45  # Slightly higher threshold for cross-node validation
            validation_results["confidence"] = 1.0 - (mean_distance / 0.5)
            validation_results["anomaly_score"] = max(list(distances.values())) - min(list(distances.values()))
            
        # Clamp confidence to [0, 1]
        validation_results["confidence"] = max(0.0, min(1.0, validation_results["confidence"]))
        
        return validation_results
    
    def get_network_entropy_state(self, active_nodes: Set[str] = None) -> Dict:
        """
        Calculate the overall entropy state of the network
        based on all or a subset of nodes
        """
        if active_nodes is None:
            active_nodes = set(self.node_registry.keys())
            
        if not active_nodes:
            return {"error": "No active nodes available"}
            
        # Collect recent signatures from each node
        node_signatures = {}
        for node_id in active_nodes:
            if node_id in self.entropy_history and self.entropy_history[node_id]:
                # Get most recent signature
                node_signatures[node_id] = self.entropy_history[node_id][-1][0]
                
        if not node_signatures:
            return {"error": "No signatures available from active nodes"}
            
        # Calculate cross-node entropy distance matrix
        distance_matrix = {}
        for node1 in node_signatures:
            distance_matrix[node1] = {}
            for node2 in node_signatures:
                if node1 != node2:
                    distance = self.calculate_entropy_distance(
                        node_signatures[node1], node_signatures[node2]
                    )
                    distance_matrix[node1][node2] = distance
                    
        # Calculate network entropy metrics
        all_distances = []
        for node1 in distance_matrix:
            for node2 in distance_matrix[node1]:
                all_distances.append(distance_matrix[node1][node2])
                
        # Network entropy state metrics
        network_state = {
            "node_count": len(node_signatures),
            "mean_distance": np.mean(all_distances) if all_distances else 0,
            "std_dev_distance": np.std(all_distances) if all_distances else 0,
            "min_distance": min(all_distances) if all_distances else 0,
            "max_distance": max(all_distances) if all_distances else 0,
            "entropy_consensus_quality": 1.0 - (np.mean(all_distances) / 0.5) if all_distances else 0
        }
        
        return network_state
    
    def detect_entropy_manipulation(self, node_id: str, 
                                 signature: bytes, 
                                 threshold: float = 0.75) -> Dict:
        """
        Detect potential entropy manipulation or generation attacks
        based on patterns and statistical anomalies
        """
        result = {
            "manipulation_detected": False,
            "confidence": 0.0,
            "factors": {}
        }
        
        # Need sufficient history for detection
        if node_id not in self.entropy_history or len(self.entropy_history[node_id]) < self.min_samples:
            result["error"] = "Insufficient history for manipulation detection"
            return result
            
        # Get historical signatures and timestamps
        history = self.entropy_history[node_id]
        historical_signatures = [entry[0] for entry in history]
        
        # Factor 1: Excessive similarity to previous signatures
        # (potential replay or insufficient entropy)
        min_distance = min(self.calculate_entropy_distance(signature, hist_sig) 
                          for hist_sig in historical_signatures)
        
        result["factors"]["excessive_similarity"] = {
            "value": min_distance,
            "suspicious": min_distance < 0.1  # Very similar signatures are suspicious
        }
        
        # Factor 2: Excessively predictable pattern
        # Analyze entropy distribution across bytes
        signature_bytes = list(signature)
        byte_analysis = {
            "variance": np.var(signature_bytes),
            "zero_bytes": sum(1 for b in signature_bytes if b == 0),
            "unique_bytes": len(set(signature_bytes)),
            "entropy": self._shannon_entropy(signature_bytes)
        }
        
        result["factors"]["byte_distribution"] = {
            "analysis": byte_analysis,
            "suspicious": (byte_analysis["entropy"] < 3.5 or  # Low entropy 
                         byte_analysis["zero_bytes"] > len(signature_bytes) * 0.1 or  # Too many zeros
                         byte_analysis["unique_bytes"] < len(signature_bytes) * 0.5)  # Too few unique bytes
        }
        
        # Factor 3: Temporal anomaly detection
        # Check if signature arrives with suspicious timing
        temporal_analysis = self.analyze_temporal_distribution(node_id)
        if "error" not in temporal_analysis:
            regularity = temporal_analysis["temporal_regularity"]
            result["factors"]["temporal_anomaly"] = {
                "analysis": regularity,
                "suspicious": regularity["coefficient_of_variation"] < 0.1  # Too regular
            }
            
        # Combine factors to determine manipulation likelihood
        suspicious_factors = sum(1 for factor in result["factors"].values() 
                               if factor.get("suspicious", False))
        total_factors = len(result["factors"])
        
        result["manipulation_detected"] = suspicious_factors / total_factors > threshold
        result["confidence"] = suspicious_factors / total_factors
        
        return result
        
    def _shannon_entropy(self, data: List[int]) -> float:
        """
        Calculate Shannon entropy of byte sequence
        to measure randomness quality
        """
        # Count byte frequencies
        byte_counts = {}
        for byte in data:
            byte_counts[byte] = byte_counts.get(byte, 0) + 1
            
        # Calculate probabilities and entropy
        entropy = 0
        for count in byte_counts.values():
            probability = count / len(data)
            entropy -= probability * math.log2(probability)
            
        return entropy
