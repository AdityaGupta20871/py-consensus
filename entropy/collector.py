"""
Entropy Collector Module

This module provides mechanisms to collect and measure temporal entropy
from various system sources to establish unique node signatures.
"""

import os
import time
import socket
import random
import hashlib
import platform
import threading
from typing import Dict, List, Optional, Tuple
import uuid
import numpy as np

class EntropySource:
    """Base class for entropy sources"""
    
    def __init__(self, source_id: str, weight: float = 1.0):
        self.source_id = source_id
        self.weight = weight
        self.last_measurement = None
        
    def measure(self) -> bytes:
        """Measure and return entropy bytes"""
        raise NotImplementedError("Subclasses must implement measure()")
    
    def get_entropy(self) -> Tuple[bytes, float]:
        """Get entropy measurement and its weight"""
        self.last_measurement = self.measure()
        return self.last_measurement, self.weight

class SystemTimingEntropy(EntropySource):
    """Collects entropy from system timing variations"""
    
    def __init__(self, samples: int = 100, weight: float = 1.0):
        super().__init__("system_timing", weight)
        self.samples = samples
        
    def measure(self) -> bytes:
        measurements = []
        for _ in range(self.samples):
            start = time.perf_counter_ns()
            # Create timing variations through minimal operations
            _ = hashlib.sha256(os.urandom(4)).digest()
            end = time.perf_counter_ns()
            measurements.append(end - start)
            
        # Use timing differences to create entropy
        measurement_bytes = np.array(measurements, dtype=np.uint64).tobytes()
        return hashlib.sha256(measurement_bytes).digest()

class NetworkLatencyEntropy(EntropySource):
    """Collects entropy from network interface timing patterns"""
    
    def __init__(self, weight: float = 1.0):
        super().__init__("network_latency", weight)
        
    def measure(self) -> bytes:
        # Create a UDP socket and measure tiny packet sending time variations
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        measurements = []
        
        for _ in range(10):
            data = os.urandom(16)
            try:
                # Send to an unreachable address to measure just the interface timing
                # This won't actually send traffic over the internet
                start = time.perf_counter_ns()
                sock.sendto(data, ("240.0.0.1", 12345))
                end = time.perf_counter_ns()
                measurements.append(end - start)
            except:
                measurements.append(random.getrandbits(32))
                
        sock.close()
        measurement_bytes = np.array(measurements, dtype=np.uint64).tobytes()
        return hashlib.sha256(measurement_bytes).digest()

class HardwareEntropy(EntropySource):
    """Collects entropy from hardware-specific characteristics"""
    
    def __init__(self, weight: float = 1.5):
        super().__init__("hardware", weight)
        
    def measure(self) -> bytes:
        # Collect system info for stable hardware fingerprinting
        sys_info = {
            "platform": platform.platform(),
            "machine": platform.machine(),
            "processor": platform.processor(),
            "node": platform.node(),
            "python_build": platform.python_build()[1],
            "system": platform.system(),
            "python_implementation": platform.python_implementation(),
        }
        
        # Create a stable but unique hardware fingerprint
        hw_str = "-".join(f"{k}:{v}" for k, v in sys_info.items())
        hw_fingerprint = hashlib.sha256(hw_str.encode()).digest()
        
        # Add some dynamic element to prevent completely static values
        timestamp = int(time.time()).to_bytes(8, byteorder='big')
        dynamic_element = hashlib.sha256(timestamp + hw_fingerprint).digest()
        
        # Final entropy is a combination of static and dynamic elements
        return hashlib.sha256(hw_fingerprint + dynamic_element).digest()

class EntropyCollector:
    """
    Manages the collection of entropy from multiple sources
    to create temporal signatures for consensus validation.
    """
    
    def __init__(self):
        self.sources: Dict[str, EntropySource] = {}
        self.node_id = str(uuid.uuid4())
        self._setup_default_sources()
        self._collection_thread = None
        self._collecting = False
        self.entropy_history: List[Tuple[bytes, float]] = []
        self.max_history = 100
        
    def _setup_default_sources(self):
        """Configure default entropy sources"""
        self.add_source(SystemTimingEntropy(samples=150, weight=1.2))
        self.add_source(NetworkLatencyEntropy(weight=1.0))
        self.add_source(HardwareEntropy(weight=1.5))
        
    def add_source(self, source: EntropySource):
        """Add an entropy source to the collector"""
        self.sources[source.source_id] = source
        
    def remove_source(self, source_id: str):
        """Remove an entropy source from the collector"""
        if source_id in self.sources:
            del self.sources[source_id]
            
    def collect_entropy(self) -> bytes:
        """
        Collect entropy from all registered sources and
        generate a combined entropy measurement
        """
        combined_entropy = b""
        weights = []
        
        for source_id, source in self.sources.items():
            entropy, weight = source.get_entropy()
            combined_entropy += entropy
            weights.append(weight)
            
        # Create final entropy measurement with a timestamp
        timestamp = int(time.time() * 1000).to_bytes(8, byteorder='big')
        node_id_bytes = self.node_id.encode()
        
        # Combine all entropy sources with weights and timestamps
        final_entropy = hashlib.sha256(
            combined_entropy + timestamp + node_id_bytes
        ).digest()
        
        # Store in history
        total_weight = sum(weights)
        self.entropy_history.append((final_entropy, total_weight))
        if len(self.entropy_history) > self.max_history:
            self.entropy_history.pop(0)
            
        return final_entropy
    
    def start_collection(self, interval: float = 1.0):
        """Start continuous entropy collection in a background thread"""
        if self._collecting:
            return
            
        self._collecting = True
        
        def collection_task():
            while self._collecting:
                self.collect_entropy()
                time.sleep(interval)
                
        self._collection_thread = threading.Thread(
            target=collection_task, daemon=True
        )
        self._collection_thread.start()
        
    def stop_collection(self):
        """Stop continuous entropy collection"""
        self._collecting = False
        if self._collection_thread:
            self._collection_thread.join(timeout=2.0)
            self._collection_thread = None
            
    def get_temporal_signature(self, time_window: int = 10) -> bytes:
        """
        Generate a temporal signature based on entropy collected
        over the specified time window
        """
        # Use most recent entropy measurements within the time window
        history_subset = self.entropy_history[-time_window:] if self.entropy_history else []
        
        if not history_subset:
            # If no history, collect a new measurement
            return self.collect_entropy()
            
        # Combine entropy measurements with weights
        combined = b""
        total_weight = 0
        
        for entropy, weight in history_subset:
            combined += entropy
            total_weight += weight
            
        # Add temporal factors to the signature
        node_id_bytes = self.node_id.encode()
        timestamp = int(time.time() * 1000).to_bytes(8, byteorder='big')
        
        # Create the final temporal signature
        return hashlib.sha256(
            combined + timestamp + node_id_bytes + total_weight.to_bytes(8, byteorder='big')
        ).digest()
