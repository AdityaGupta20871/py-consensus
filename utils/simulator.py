"""
Network Simulator for Temporal Consensus Protocol

This module provides a simulation environment to test the TCP
without requiring actual network connections.
"""

import time
import random
import threading
import uuid
import json
from typing import Dict, List, Set, Any, Optional, Tuple
import matplotlib.pyplot as plt
import numpy as np
from ..consensus.protocol import TemporalConsensusProtocol, TemporalFingerprint
from ..blockchain.blockchain import TemporalBlockchain, Block

class SimulatedNode:
    """Simulated network node for TCP testing"""
    
    def __init__(self, node_id: str = None, entropy_quality: float = 1.0):
        self.node_id = node_id or str(uuid.uuid4())
        self.blockchain = TemporalBlockchain(node_id=self.node_id)
        self.entropy_quality = entropy_quality  # 0.0-1.0 scale, affects entropy quality
        self.online = True
        self.message_queue = []
        self.mined_blocks = 0
        self.processed_transactions = 0
        
    def process_message(self, message: Dict):
        """Process incoming network message"""
        if not self.online:
            return False
            
        message_type = message.get("type")
        sender_id = message.get("sender")
        content = message.get("content", {})
        
        if message_type == "new_block":
            # Process new block
            block_dict = content.get("block")
            if block_dict:
                block = Block.from_dict(block_dict)
                self.blockchain.add_block(block)
                return True
                
        elif message_type == "new_transaction":
            # Process new transaction
            transaction = content.get("transaction")
            if transaction:
                self.blockchain.add_transaction(transaction)
                self.processed_transactions += 1
                return True
                
        elif message_type == "entropy_signature":
            # Process entropy signature
            fingerprint_data = content.get("fingerprint")
            if fingerprint_data:
                # Deserialize fingerprint
                fingerprint_bytes = json.dumps(fingerprint_data).encode()
                fingerprint = TemporalFingerprint.deserialize(fingerprint_bytes)
                
                # Process fingerprint with entropy quality adjustment
                if random.random() <= self.entropy_quality:
                    self.blockchain.consensus_protocol.receive_fingerprint(fingerprint)
                    return True
                    
        return False
        
    def create_block(self):
        """Mine a new block if node is online"""
        if not self.online:
            return None
            
        # Create new block
        block = self.blockchain.create_block()
        
        # Modify entropy quality based on node's characteristics
        if self.entropy_quality < 0.7:
            # Create a less reliable fingerprint for low quality nodes
            # This simulates nodes with poor entropy sources
            current_entropy = block.temporal_fingerprints[0].entropy_signature
            noise_level = 1.0 - self.entropy_quality
            
            # Inject some noise to the entropy signature
            noisy_entropy = bytearray(current_entropy)
            num_bits_to_flip = int(len(noisy_entropy) * noise_level * 0.3)
            
            # Flip random bits
            for _ in range(num_bits_to_flip):
                pos = random.randint(0, len(noisy_entropy) - 1)
                bit_pos = random.randint(0, 7)
                noisy_entropy[pos] = noisy_entropy[pos] ^ (1 << bit_pos)
                
            # Replace entropy signature with noisy version
            block.temporal_fingerprints[0].entropy_signature = bytes(noisy_entropy)
            
        # Validate and add to chain
        if self.blockchain.add_block(block):
            self.mined_blocks += 1
            return block
        else:
            return None
            
    def broadcast_entropy(self):
        """Broadcast entropy signature if node is online"""
        if not self.online:
            return None
            
        # Adjust entropy quality based on node characteristics
        fingerprint = self.blockchain.consensus_protocol.create_temporal_fingerprint()
        
        if self.entropy_quality < 0.8:
            # For lower quality nodes, occasionally degrade the entropy
            if random.random() > self.entropy_quality:
                # Create lower quality entropy by adding patterns
                current_entropy = bytearray(fingerprint.entropy_signature)
                pattern_length = random.randint(2, 4)
                
                # Inject simple pattern
                for i in range(0, len(current_entropy), pattern_length * 2):
                    if i + pattern_length < len(current_entropy):
                        for j in range(pattern_length):
                            if i + j + pattern_length < len(current_entropy):
                                current_entropy[i + j + pattern_length] = current_entropy[i + j]
                                
                fingerprint.entropy_signature = bytes(current_entropy)
                
        return fingerprint

class NetworkSimulator:
    """
    Simulates a network of nodes running the Temporal Consensus Protocol
    to test consensus behavior and entropy validation.
    """
    
    def __init__(self):
        self.nodes: Dict[str, SimulatedNode] = {}
        self.running = False
        self.simulation_thread = None
        self.tick_interval = 1.0  # seconds between simulation ticks
        
        # Statistics
        self.block_creation_times = []
        self.fork_events = 0
        self.validation_failures = 0
        self.successful_validations = 0
        
        # Simulation parameters
        self.transaction_rate = 2.0  # transactions per tick
        self.signature_broadcast_rate = 0.5  # probability per node per tick
        self.block_creation_rate = 0.1  # probability per node per tick
        
        # Configure simulation plots
        plt.ion()  # Interactive plotting mode
        self.figure, self.axes = plt.subplots(2, 2, figsize=(12, 8))
        self.figure.tight_layout(pad=3.0)
        
    def add_node(self, entropy_quality: float = 1.0) -> str:
        """Add a new node to the simulation"""
        node = SimulatedNode(entropy_quality=entropy_quality)
        self.nodes[node.node_id] = node
        return node.node_id
        
    def remove_node(self, node_id: str):
        """Remove a node from the simulation"""
        if node_id in self.nodes:
            del self.nodes[node_id]
            
    def set_node_status(self, node_id: str, online: bool):
        """Set a node's online status"""
        if node_id in self.nodes:
            self.nodes[node_id].online = online
            
    def generate_transaction(self) -> Dict:
        """Generate a random transaction"""
        return {
            "sender": f"user_{uuid.uuid4().hex[:8]}",
            "recipient": f"user_{uuid.uuid4().hex[:8]}",
            "amount": random.uniform(0.1, 100.0),
            "timestamp": time.time()
        }
        
    def broadcast_message(self, sender_id: str, message_type: str, content: Dict):
        """Broadcast a message to all nodes except sender"""
        message = {
            "type": message_type,
            "sender": sender_id,
            "content": content,
            "timestamp": time.time()
        }
        
        for node_id, node in self.nodes.items():
            if node_id != sender_id and node.online:
                node.message_queue.append(message)
                
    def start_simulation(self, duration: int = None):
        """Start the network simulation"""
        if self.running:
            return
            
        self.running = True
        
        def simulation_loop():
            start_time = time.time()
            tick_count = 0
            
            while self.running:
                if duration and (time.time() - start_time > duration):
                    self.running = False
                    break
                    
                # Process message queues
                self._process_all_messages()
                
                # Generate random transactions
                self._generate_transactions()
                
                # Broadcast entropy signatures
                self._broadcast_entropy_signatures()
                
                # Create blocks
                self._create_blocks()
                
                # Update statistics
                if tick_count % 5 == 0:
                    self._update_statistics()
                    
                tick_count += 1
                
                # Wait for next tick
                time.sleep(self.tick_interval)
                
        self.simulation_thread = threading.Thread(target=simulation_loop)
        self.simulation_thread.daemon = True
        self.simulation_thread.start()
        
        print(f"Simulation started with {len(self.nodes)} nodes")
        
    def stop_simulation(self):
        """Stop the network simulation"""
        self.running = False
        if self.simulation_thread:
            self.simulation_thread.join(timeout=2.0)
            self.simulation_thread = None
            
        print("Simulation stopped")
        
    def _process_all_messages(self):
        """Process all queued messages for each node"""
        for node_id, node in self.nodes.items():
            if not node.online:
                continue
                
            # Process queued messages
            for message in list(node.message_queue):
                success = node.process_message(message)
                node.message_queue.remove(message)
                
                if success and message["type"] == "entropy_signature":
                    self.successful_validations += 1
                elif not success and message["type"] == "entropy_signature":
                    self.validation_failures += 1
                    
    def _generate_transactions(self):
        """Generate random transactions at the specified rate"""
        if random.random() < self.transaction_rate:
            transaction = self.generate_transaction()
            
            # Choose a random node to propose the transaction
            online_nodes = [n for n in self.nodes.values() if n.online]
            if online_nodes:
                proposer = random.choice(online_nodes)
                proposer.blockchain.add_transaction(transaction)
                proposer.processed_transactions += 1
                
                # Broadcast to network
                self.broadcast_message(
                    proposer.node_id,
                    "new_transaction",
                    {"transaction": transaction}
                )
                
    def _broadcast_entropy_signatures(self):
        """Have nodes broadcast entropy signatures at the specified rate"""
        for node_id, node in self.nodes.items():
            if node.online and random.random() < self.signature_broadcast_rate:
                fingerprint = node.broadcast_entropy()
                
                if fingerprint:
                    # Serialize fingerprint
                    fp_dict = json.loads(fingerprint.serialize().decode())
                    
                    # Broadcast to network
                    self.broadcast_message(
                        node_id,
                        "entropy_signature",
                        {"fingerprint": fp_dict}
                    )
                    
    def _create_blocks(self):
        """Have nodes create blocks at the specified rate"""
        for node_id, node in self.nodes.items():
            if node.online and random.random() < self.block_creation_rate:
                # Create and broadcast block
                block = node.create_block()
                
                if block:
                    start_time = time.time()
                    
                    # Broadcast to network
                    self.broadcast_message(
                        node_id,
                        "new_block",
                        {"block": block.to_dict()}
                    )
                    
                    # Record block creation time
                    self.block_creation_times.append(time.time() - start_time)
                    
    def _update_statistics(self):
        """Update simulation statistics and plots"""
        # Count forks and chain lengths
        chain_lengths = [len(node.blockchain.chain) for node in self.nodes.values() if node.online]
        
        # Detect potential forks by checking if chains have different lengths
        if len(set(chain_lengths)) > 1:
            self.fork_events += 1
            
        # Update plots
        self._update_plots()
        
    def _update_plots(self):
        """Update simulation plots with current data"""
        # Clear all subplots
        for ax in self.axes.flatten():
            ax.clear()
            
        # Plot 1: Chain lengths for each node
        node_ids = list(self.nodes.keys())
        chain_lengths = [len(node.blockchain.chain) for node in self.nodes.values()]
        
        self.axes[0, 0].bar(range(len(node_ids)), chain_lengths)
        self.axes[0, 0].set_xlabel('Node ID')
        self.axes[0, 0].set_ylabel('Chain Length')
        self.axes[0, 0].set_title('Blockchain Length by Node')
        self.axes[0, 0].set_xticks(range(len(node_ids)))
        self.axes[0, 0].set_xticklabels([node_id[:4] for node_id in node_ids], rotation=45)
        
        # Plot 2: Transaction processing
        node_txs = [node.processed_transactions for node in self.nodes.values()]
        
        self.axes[0, 1].bar(range(len(node_ids)), node_txs)
        self.axes[0, 1].set_xlabel('Node ID')
        self.axes[0, 1].set_ylabel('Processed Transactions')
        self.axes[0, 1].set_title('Transactions Processed by Node')
        self.axes[0, 1].set_xticks(range(len(node_ids)))
        self.axes[0, 1].set_xticklabels([node_id[:4] for node_id in node_ids], rotation=45)
        
        # Plot 3: Mined blocks by node
        node_blocks = [node.mined_blocks for node in self.nodes.values()]
        
        self.axes[1, 0].bar(range(len(node_ids)), node_blocks)
        self.axes[1, 0].set_xlabel('Node ID')
        self.axes[1, 0].set_ylabel('Mined Blocks')
        self.axes[1, 0].set_title('Blocks Mined by Node')
        self.axes[1, 0].set_xticks(range(len(node_ids)))
        self.axes[1, 0].set_xticklabels([node_id[:4] for node_id in node_ids], rotation=45)
        
        # Plot 4: Validation statistics
        validation_stats = [self.successful_validations, self.validation_failures, self.fork_events]
        labels = ['Successful\nValidations', 'Failed\nValidations', 'Fork\nEvents']
        
        self.axes[1, 1].bar(range(len(labels)), validation_stats)
        self.axes[1, 1].set_xlabel('Metric')
        self.axes[1, 1].set_ylabel('Count')
        self.axes[1, 1].set_title('Network Statistics')
        self.axes[1, 1].set_xticks(range(len(labels)))
        self.axes[1, 1].set_xticklabels(labels)
        
        # Update display
        self.figure.canvas.draw()
        self.figure.canvas.flush_events()
        
    def get_simulation_stats(self) -> Dict:
        """Get current simulation statistics"""
        # Collect node statistics
        node_stats = {}
        for node_id, node in self.nodes.items():
            node_stats[node_id] = {
                "chain_length": len(node.blockchain.chain),
                "processed_transactions": node.processed_transactions,
                "mined_blocks": node.mined_blocks,
                "online": node.online,
                "entropy_quality": node.entropy_quality
            }
            
        # Calculate network statistics
        avg_chain_length = np.mean([len(node.blockchain.chain) for node in self.nodes.values()])
        max_chain_length = max([len(node.blockchain.chain) for node in self.nodes.values()])
        
        # Calculate average block time
        avg_block_time = np.mean(self.block_creation_times) if self.block_creation_times else 0
        
        return {
            "node_count": len(self.nodes),
            "online_nodes": sum(1 for node in self.nodes.values() if node.online),
            "fork_events": self.fork_events,
            "successful_validations": self.successful_validations,
            "validation_failures": self.validation_failures,
            "avg_chain_length": avg_chain_length,
            "max_chain_length": max_chain_length,
            "avg_block_time": avg_block_time,
            "node_stats": node_stats
        }
        
    def simulate_attack(self, attack_type: str, target_node_id: str = None):
        """
        Simulate various attack scenarios on the network
        
        Attack types:
        - 'sybil': Add multiple low-quality nodes to attempt consensus manipulation
        - 'entropy_manipulation': Target node attempts to produce predictable entropy
        - 'inconsistent': Target node produces inconsistent temporal signatures
        """
        if attack_type == 'sybil':
            # Add multiple low-quality nodes
            for _ in range(5):
                self.add_node(entropy_quality=0.3)
            print("Sybil attack: Added 5 low-quality nodes to the network")
                
        elif attack_type == 'entropy_manipulation' and target_node_id:
            if target_node_id in self.nodes:
                # Modify target node's entropy quality
                self.nodes[target_node_id].entropy_quality = 0.1
                print(f"Entropy manipulation attack: Node {target_node_id[:8]} now producing manipulated entropy")
                
        elif attack_type == 'inconsistent' and target_node_id:
            # Make target node very inconsistent in entropy production
            if target_node_id in self.nodes:
                self.nodes[target_node_id].entropy_quality = 0.5
                
                # Override node's entropy generation to be highly inconsistent
                original_broadcast = self.nodes[target_node_id].broadcast_entropy
                
                def inconsistent_entropy():
                    # Every other call produces extremely different entropy
                    if getattr(self.nodes[target_node_id], '_inconsistent_toggle', False):
                        # Produce normal entropy
                        self.nodes[target_node_id]._inconsistent_toggle = False
                        return original_broadcast()
                    else:
                        # Produce completely different entropy pattern
                        self.nodes[target_node_id]._inconsistent_toggle = True
                        fp = original_broadcast()
                        # Completely change entropy signature
                        fp.entropy_signature = os.urandom(len(fp.entropy_signature))
                        return fp
                        
                self.nodes[target_node_id].broadcast_entropy = inconsistent_entropy
                print(f"Inconsistency attack: Node {target_node_id[:8]} now producing inconsistent entropy")
                
        else:
            print(f"Unknown attack type: {attack_type}")
            
    def run_demo(self, num_nodes: int = 5, duration: int = 60):
        """Run a complete demonstration simulation"""
        print(f"Starting TCP demo with {num_nodes} nodes for {duration} seconds")
        
        # Add nodes with varying entropy quality
        for i in range(num_nodes):
            # Most nodes have good entropy quality
            quality = 1.0 if i < int(num_nodes * 0.7) else random.uniform(0.5, 0.9)
            self.add_node(entropy_quality=quality)
            
        # Start simulation
        self.start_simulation(duration=duration)
        
        # Wait for simulation to complete
        time.sleep(duration + 2)
        
        # Print final statistics
        stats = self.get_simulation_stats()
        print("\nSimulation Results:")
        print(f"Total Nodes: {stats['node_count']}")
        print(f"Fork Events: {stats['fork_events']}")
        print(f"Successful Validations: {stats['successful_validations']}")
        print(f"Validation Failures: {stats['validation_failures']}")
        print(f"Average Chain Length: {stats['avg_chain_length']:.2f}")
        print(f"Average Block Time: {stats['avg_block_time']:.4f} seconds")
        
        # Show final plots
        plt.ioff()
        plt.show()
        
        return stats
