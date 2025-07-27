# SentinelX Feature Extractor

import pandas as pd
import numpy as np
from typing import Dict, List, Tuple, Any, Optional, Union
import logging
import os
from datetime import datetime

# For packet processing (will be used in live mode)
try:
    import scapy.all as scapy
except ImportError:
    scapy = None

from ..core.config_manager import ConfigManager

class FeatureExtractor:
    """Feature extractor for network traffic data.
    
    This class extracts relevant features from network packets for intrusion detection.
    It can work with both offline datasets and real-time packet captures.
    """
    
    def __init__(self, feature_info: Optional[Dict[str, Any]] = None):
        """Initialize the feature extractor.
        
        Args:
            feature_info: Dictionary containing feature information (optional)
        """
        self.config = ConfigManager()
        self.logger = logging.getLogger(__name__)
        self.feature_info = feature_info
        
        # Initialize packet statistics
        self.packet_stats = {
            'total_packets': 0,
            'start_time': None,
            'end_time': None,
            'protocol_counts': {},
            'src_ips': set(),
            'dst_ips': set(),
            'src_ports': set(),
            'dst_ports': set()
        }
    
    def extract_features_from_dataset(self, df: pd.DataFrame) -> pd.DataFrame:
        """Extract or transform features from a dataset.
        
        This method is used for offline feature extraction from datasets.
        
        Args:
            df: Input DataFrame containing raw data
            
        Returns:
            DataFrame with extracted/transformed features
        """
        self.logger.info(f"Extracting features from dataset with {len(df)} rows")
        
        # Create a copy to avoid modifying the original DataFrame
        result_df = df.copy()
        
        # Feature engineering based on domain knowledge
        # These are examples and should be adapted based on the specific dataset
        
        # 1. Ratio of source to destination bytes
        if 'src_bytes' in result_df.columns and 'dst_bytes' in result_df.columns:
            result_df['bytes_ratio'] = result_df['src_bytes'] / (result_df['dst_bytes'] + 1)  # Add 1 to avoid division by zero
        
        # 2. Total bytes
        if 'src_bytes' in result_df.columns and 'dst_bytes' in result_df.columns:
            result_df['total_bytes'] = result_df['src_bytes'] + result_df['dst_bytes']
        
        # 3. Log transformation for skewed features
        for col in ['src_bytes', 'dst_bytes', 'count', 'srv_count']:
            if col in result_df.columns:
                result_df[f'log_{col}'] = np.log1p(result_df[col])  # log1p to handle zeros
        
        # 4. Interaction features
        if 'serror_rate' in result_df.columns and 'rerror_rate' in result_df.columns:
            result_df['total_error_rate'] = result_df['serror_rate'] + result_df['rerror_rate']
        
        # 5. Flag combinations (if applicable)
        if 'flag' in result_df.columns:
            # Create binary indicators for important flags
            important_flags = ['S0', 'REJ', 'RSTO', 'RSTOS0']
            for flag in important_flags:
                result_df[f'flag_{flag}'] = (result_df['flag'] == flag).astype(int)
        
        self.logger.info(f"Feature extraction complete. DataFrame now has {len(result_df.columns)} columns")
        return result_df
    
    def extract_features_from_packet(self, packet) -> Dict[str, Any]:
        """Extract features from a single network packet.
        
        This method is used for real-time feature extraction from network packets.
        
        Args:
            packet: Network packet (e.g., from scapy)
            
        Returns:
            Dictionary containing extracted features
        """
        if scapy is None:
            self.logger.error("Scapy is not installed. Cannot extract features from packets.")
            return {}
        
        # Initialize feature dictionary
        features = {}
        
        # Update packet statistics
        self.packet_stats['total_packets'] += 1
        current_time = datetime.now()
        
        if self.packet_stats['start_time'] is None:
            self.packet_stats['start_time'] = current_time
        self.packet_stats['end_time'] = current_time
        
        # Basic packet information
        features['timestamp'] = current_time.timestamp()
        features['packet_size'] = len(packet)
        
        # Extract IP layer features if present
        if scapy.IP in packet:
            ip = packet[scapy.IP]
            features['protocol'] = ip.proto
            features['ttl'] = ip.ttl
            features['src_ip'] = ip.src
            features['dst_ip'] = ip.dst
            
            # Update statistics
            protocol_name = {1: 'ICMP', 6: 'TCP', 17: 'UDP'}.get(ip.proto, str(ip.proto))
            self.packet_stats['protocol_counts'][protocol_name] = \
                self.packet_stats['protocol_counts'].get(protocol_name, 0) + 1
            self.packet_stats['src_ips'].add(ip.src)
            self.packet_stats['dst_ips'].add(ip.dst)
        
        # Extract TCP layer features if present
        if scapy.TCP in packet:
            tcp = packet[scapy.TCP]
            features['src_port'] = tcp.sport
            features['dst_port'] = tcp.dport
            features['tcp_flags'] = tcp.flags
            features['tcp_window'] = tcp.window
            
            # TCP flags as individual features
            features['flag_syn'] = 1 if tcp.flags & 0x02 else 0  # SYN flag
            features['flag_ack'] = 1 if tcp.flags & 0x10 else 0  # ACK flag
            features['flag_rst'] = 1 if tcp.flags & 0x04 else 0  # RST flag
            features['flag_fin'] = 1 if tcp.flags & 0x01 else 0  # FIN flag
            
            # Update statistics
            self.packet_stats['src_ports'].add(tcp.sport)
            self.packet_stats['dst_ports'].add(tcp.dport)
        
        # Extract UDP layer features if present
        elif scapy.UDP in packet:
            udp = packet[scapy.UDP]
            features['src_port'] = udp.sport
            features['dst_port'] = udp.dport
            features['udp_len'] = udp.len
            
            # Update statistics
            self.packet_stats['src_ports'].add(udp.sport)
            self.packet_stats['dst_ports'].add(udp.dport)
        
        # Extract ICMP layer features if present
        elif scapy.ICMP in packet:
            icmp = packet[scapy.ICMP]
            features['icmp_type'] = icmp.type
            features['icmp_code'] = icmp.code
        
        return features
    
    def extract_flow_features(self, packets: List[Any], window_size: int = 100) -> Dict[str, Any]:
        """Extract features from a flow of packets.
        
        This method aggregates features from multiple packets to create flow-level features.
        
        Args:
            packets: List of network packets
            window_size: Number of packets to consider for flow features
            
        Returns:
            Dictionary containing extracted flow features
        """
        if not packets:
            return {}
        
        # Extract features from individual packets
        packet_features = [self.extract_features_from_packet(p) for p in packets]
        
        # Initialize flow features
        flow_features = {}
        
        # Basic flow statistics
        flow_features['packet_count'] = len(packets)
        
        # Time-based features
        if packet_features and 'timestamp' in packet_features[0]:
            timestamps = [p['timestamp'] for p in packet_features if 'timestamp' in p]
            if timestamps:
                flow_features['flow_duration'] = max(timestamps) - min(timestamps)
                flow_features['packet_rate'] = len(timestamps) / (flow_features['flow_duration'] + 0.001)
        
        # Size-based features
        if packet_features and 'packet_size' in packet_features[0]:
            sizes = [p['packet_size'] for p in packet_features if 'packet_size' in p]
            if sizes:
                flow_features['avg_packet_size'] = np.mean(sizes)
                flow_features['std_packet_size'] = np.std(sizes)
                flow_features['min_packet_size'] = min(sizes)
                flow_features['max_packet_size'] = max(sizes)
                flow_features['total_bytes'] = sum(sizes)
        
        # Protocol distribution
        if packet_features and 'protocol' in packet_features[0]:
            protocols = [p['protocol'] for p in packet_features if 'protocol' in p]
            protocol_counts = {}
            for p in protocols:
                protocol_counts[p] = protocol_counts.get(p, 0) + 1
            
            for proto, count in protocol_counts.items():
                flow_features[f'protocol_{proto}_ratio'] = count / len(protocols)
        
        # TCP flags distribution (if applicable)
        tcp_packets = [p for p in packet_features if 'tcp_flags' in p]
        if tcp_packets:
            # Count different flag combinations
            flag_counts = {}
            for p in tcp_packets:
                flags = p['tcp_flags']
                flag_counts[flags] = flag_counts.get(flags, 0) + 1
            
            # Calculate ratios for common flags
            for flag_name in ['flag_syn', 'flag_ack', 'flag_rst', 'flag_fin']:
                if flag_name in tcp_packets[0]:
                    flag_values = [p[flag_name] for p in tcp_packets if flag_name in p]
                    flow_features[f'{flag_name}_ratio'] = sum(flag_values) / len(flag_values)
        
        return flow_features
    
    def get_packet_statistics(self) -> Dict[str, Any]:
        """Get statistics about processed packets.
        
        Returns:
            Dictionary containing packet statistics
        """
        stats = self.packet_stats.copy()
        
        # Calculate derived statistics
        if stats['start_time'] and stats['end_time']:
            duration = (stats['end_time'] - stats['start_time']).total_seconds()
            stats['duration_seconds'] = duration
            stats['packets_per_second'] = stats['total_packets'] / max(duration, 0.001)
        
        # Convert sets to counts for easier reporting
        stats['unique_src_ips'] = len(stats['src_ips'])
        stats['unique_dst_ips'] = len(stats['dst_ips'])
        stats['unique_src_ports'] = len(stats['src_ports'])
        stats['unique_dst_ports'] = len(stats['dst_ports'])
        
        # Remove the actual sets from the returned dictionary
        del stats['src_ips']
        del stats['dst_ips']
        del stats['src_ports']
        del stats['dst_ports']
        
        return stats
    
    def reset_statistics(self) -> None:
        """Reset packet statistics."""
        self.packet_stats = {
            'total_packets': 0,
            'start_time': None,
            'end_time': None,
            'protocol_counts': {},
            'src_ips': set(),
            'dst_ips': set(),
            'src_ports': set(),
            'dst_ports': set()
        }
        self.logger.info("Packet statistics reset")