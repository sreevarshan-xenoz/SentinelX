# SentinelX Flow Analyzer Module

import logging
import time
from typing import Dict, List, Any, Optional, Union, Callable, Tuple, Set
import threading
import queue
import os
from datetime import datetime, timedelta
import json
import ipaddress
import collections

# Import scapy for packet processing
try:
    from scapy.all import IP, TCP, UDP, ICMP
    SCAPY_AVAILABLE = True
except ImportError:
    SCAPY_AVAILABLE = False

from ..core.config_manager import ConfigManager
from ..core.logging_manager import LoggingManager
from ..data_layer.feature_extractor import FeatureExtractor


class NetworkFlow:
    """Network flow class for SentinelX.
    
    This class represents a network flow (connection) between two endpoints.
    """
    
    def __init__(self, src_ip: str, dst_ip: str, src_port: Optional[int] = None, 
                dst_port: Optional[int] = None, protocol: Optional[str] = None):
        """Initialize a network flow.
        
        Args:
            src_ip: Source IP address
            dst_ip: Destination IP address
            src_port: Source port (optional)
            dst_port: Destination port (optional)
            protocol: Protocol (TCP, UDP, ICMP, etc.)
        """
        self.src_ip = src_ip
        self.dst_ip = dst_ip
        self.src_port = src_port
        self.dst_port = dst_port
        self.protocol = protocol
        
        # Flow statistics
        self.start_time: Optional[datetime] = None
        self.last_time: Optional[datetime] = None
        self.packet_count = 0
        self.byte_count = 0
        self.forward_packet_count = 0  # src -> dst
        self.backward_packet_count = 0  # dst -> src
        self.forward_byte_count = 0
        self.backward_byte_count = 0
        
        # TCP specific
        self.tcp_flags: Dict[str, int] = {
            'FIN': 0, 'SYN': 0, 'RST': 0, 'PSH': 0, 
            'ACK': 0, 'URG': 0, 'ECE': 0, 'CWR': 0
        }
        
        # Packet inter-arrival times
        self.packet_times: List[datetime] = []
        self.inter_arrival_times: List[float] = []
        
        # Packet sizes
        self.packet_sizes: List[int] = []
        
        # Flow state
        self.state = "NEW"  # NEW, ESTABLISHED, CLOSED
        
        # Additional metadata
        self.metadata: Dict[str, Any] = {}
    
    def add_packet(self, packet: Any, timestamp: Optional[datetime] = None, 
                 size: Optional[int] = None, direction: str = "forward") -> None:
        """Add a packet to the flow.
        
        Args:
            packet: The packet to add (scapy packet or pyshark packet)
            timestamp: Packet timestamp (optional)
            size: Packet size in bytes (optional)
            direction: Packet direction ("forward" or "backward")
        """
        # Set timestamp
        if timestamp is None:
            timestamp = datetime.now()
        
        # Update flow times
        if self.start_time is None:
            self.start_time = timestamp
        self.last_time = timestamp
        
        # Add to packet times list
        self.packet_times.append(timestamp)
        
        # Calculate inter-arrival time if not the first packet
        if len(self.packet_times) > 1:
            delta = (self.packet_times[-1] - self.packet_times[-2]).total_seconds()
            self.inter_arrival_times.append(delta)
        
        # Extract packet size
        packet_size = size
        if packet_size is None:
            if SCAPY_AVAILABLE and hasattr(packet, 'len'):
                packet_size = packet.len
            elif hasattr(packet, 'length'):
                packet_size = int(packet.length)
            else:
                packet_size = 0
        
        # Add to packet sizes list
        self.packet_sizes.append(packet_size)
        
        # Update packet and byte counts
        self.packet_count += 1
        self.byte_count += packet_size
        
        if direction == "forward":
            self.forward_packet_count += 1
            self.forward_byte_count += packet_size
        else:
            self.backward_packet_count += 1
            self.backward_byte_count += packet_size
        
        # Update TCP flags if applicable
        if SCAPY_AVAILABLE and TCP in packet:
            tcp_layer = packet[TCP]
            flags = tcp_layer.flags
            
            if flags & 0x01:  # FIN
                self.tcp_flags['FIN'] += 1
            if flags & 0x02:  # SYN
                self.tcp_flags['SYN'] += 1
            if flags & 0x04:  # RST
                self.tcp_flags['RST'] += 1
            if flags & 0x08:  # PSH
                self.tcp_flags['PSH'] += 1
            if flags & 0x10:  # ACK
                self.tcp_flags['ACK'] += 1
            if flags & 0x20:  # URG
                self.tcp_flags['URG'] += 1
            if flags & 0x40:  # ECE
                self.tcp_flags['ECE'] += 1
            if flags & 0x80:  # CWR
                self.tcp_flags['CWR'] += 1
            
            # Update flow state based on TCP flags
            if self.state == "NEW" and self.tcp_flags['SYN'] > 0 and self.tcp_flags['ACK'] > 0:
                self.state = "ESTABLISHED"
            elif self.state != "CLOSED" and (self.tcp_flags['FIN'] > 0 or self.tcp_flags['RST'] > 0):
                self.state = "CLOSED"
        
        # For non-TCP protocols, update state based on packet count
        elif self.state == "NEW" and self.packet_count > 1:
            self.state = "ESTABLISHED"
    
    def get_flow_id(self) -> str:
        """Get a unique identifier for the flow.
        
        Returns:
            Flow identifier string
        """
        if self.src_port is not None and self.dst_port is not None:
            return f"{self.protocol}_{self.src_ip}:{self.src_port}_{self.dst_ip}:{self.dst_port}"
        else:
            return f"{self.protocol}_{self.src_ip}_{self.dst_ip}"
    
    def get_flow_features(self) -> Dict[str, Any]:
        """Get features extracted from the flow.
        
        Returns:
            Dictionary of flow features
        """
        features = {
            'src_ip': self.src_ip,
            'dst_ip': self.dst_ip,
            'protocol': self.protocol,
            'packet_count': self.packet_count,
            'byte_count': self.byte_count,
            'flow_duration': 0.0,
            'packets_per_second': 0.0,
            'bytes_per_second': 0.0,
            'avg_packet_size': 0.0,
            'std_packet_size': 0.0,
            'min_packet_size': 0.0,
            'max_packet_size': 0.0,
            'avg_inter_arrival_time': 0.0,
            'std_inter_arrival_time': 0.0,
            'min_inter_arrival_time': 0.0,
            'max_inter_arrival_time': 0.0,
            'forward_packet_count': self.forward_packet_count,
            'backward_packet_count': self.backward_packet_count,
            'forward_byte_count': self.forward_byte_count,
            'backward_byte_count': self.backward_byte_count,
            'forward_to_backward_packet_ratio': 0.0,
            'forward_to_backward_byte_ratio': 0.0,
            'state': self.state
        }
        
        # Add port information if available
        if self.src_port is not None:
            features['src_port'] = self.src_port
        if self.dst_port is not None:
            features['dst_port'] = self.dst_port
        
        # Add TCP flags if applicable
        if self.protocol == 'TCP':
            for flag, count in self.tcp_flags.items():
                features[f'tcp_{flag.lower()}_count'] = count
        
        # Calculate time-based features
        if self.start_time and self.last_time and self.packet_count > 0:
            # Flow duration in seconds
            duration = (self.last_time - self.start_time).total_seconds()
            features['flow_duration'] = duration
            
            # Packets and bytes per second
            if duration > 0:
                features['packets_per_second'] = self.packet_count / duration
                features['bytes_per_second'] = self.byte_count / duration
        
        # Calculate packet size statistics
        if self.packet_sizes:
            features['avg_packet_size'] = sum(self.packet_sizes) / len(self.packet_sizes)
            features['min_packet_size'] = min(self.packet_sizes)
            features['max_packet_size'] = max(self.packet_sizes)
            
            # Standard deviation of packet sizes
            if len(self.packet_sizes) > 1:
                mean = features['avg_packet_size']
                variance = sum((x - mean) ** 2 for x in self.packet_sizes) / len(self.packet_sizes)
                features['std_packet_size'] = variance ** 0.5
        
        # Calculate inter-arrival time statistics
        if self.inter_arrival_times:
            features['avg_inter_arrival_time'] = sum(self.inter_arrival_times) / len(self.inter_arrival_times)
            features['min_inter_arrival_time'] = min(self.inter_arrival_times)
            features['max_inter_arrival_time'] = max(self.inter_arrival_times)
            
            # Standard deviation of inter-arrival times
            if len(self.inter_arrival_times) > 1:
                mean = features['avg_inter_arrival_time']
                variance = sum((x - mean) ** 2 for x in self.inter_arrival_times) / len(self.inter_arrival_times)
                features['std_inter_arrival_time'] = variance ** 0.5
        
        # Calculate directional ratios
        if self.backward_packet_count > 0:
            features['forward_to_backward_packet_ratio'] = self.forward_packet_count / self.backward_packet_count
        if self.backward_byte_count > 0:
            features['forward_to_backward_byte_ratio'] = self.forward_byte_count / self.backward_byte_count
        
        return features
    
    def is_expired(self, timeout: int = 300) -> bool:
        """Check if the flow has expired.
        
        Args:
            timeout: Flow timeout in seconds
            
        Returns:
            True if the flow has expired, False otherwise
        """
        if self.state == "CLOSED":
            return True
        
        if self.last_time is None:
            return False
        
        # Check if the flow has been inactive for longer than the timeout
        return (datetime.now() - self.last_time).total_seconds() > timeout


class FlowAnalyzer:
    """Flow analyzer class for SentinelX.
    
    This class is responsible for tracking and analyzing network flows.
    """
    
    def __init__(self, callback: Optional[Callable] = None):
        """Initialize the flow analyzer.
        
        Args:
            callback: Optional callback function to process flows
        """
        self.config = ConfigManager()
        self.logger = logging.getLogger(__name__)
        
        # Get flow configuration
        self.flow_config = self.config.get('network_monitoring', 'flow_analysis', {})
        self.flow_timeout = self.flow_config.get('timeout', 300)  # 5 minutes default
        self.max_flows = self.flow_config.get('max_flows', 10000)
        self.cleanup_interval = self.flow_config.get('cleanup_interval', 60)  # 1 minute default
        
        # Initialize flow storage
        self.flows: Dict[str, NetworkFlow] = {}
        self.flow_lock = threading.Lock()
        
        # Initialize feature extractor
        self.feature_extractor = FeatureExtractor()
        
        # Set callback function
        self.callback = callback
        
        # Initialize cleanup thread
        self.stop_event = threading.Event()
        self.cleanup_thread = threading.Thread(target=self._cleanup_flows)
        self.cleanup_thread.daemon = True
        self.cleanup_thread.start()
        
        # Initialize flow statistics
        self.stats = {
            'total_flows': 0,
            'active_flows': 0,
            'expired_flows': 0,
            'tcp_flows': 0,
            'udp_flows': 0,
            'icmp_flows': 0,
            'other_flows': 0,
            'start_time': datetime.now(),
            'last_update': datetime.now()
        }
        
        self.logger.info("Flow analyzer initialized")
    
    def process_packet(self, packet: Any) -> Optional[Dict[str, Any]]:
        """Process a packet and update flow information.
        
        Args:
            packet: The packet to process (scapy packet or pyshark packet)
            
        Returns:
            Flow features if the flow is new or updated, None otherwise
        """
        # Extract flow information from packet
        flow_info = self._extract_flow_info(packet)
        if not flow_info:
            return None
        
        src_ip, dst_ip, src_port, dst_port, protocol, size, timestamp = flow_info
        
        # Create flow ID
        if src_port is not None and dst_port is not None:
            forward_flow_id = f"{protocol}_{src_ip}:{src_port}_{dst_ip}:{dst_port}"
            backward_flow_id = f"{protocol}_{dst_ip}:{dst_port}_{src_ip}:{src_port}"
        else:
            forward_flow_id = f"{protocol}_{src_ip}_{dst_ip}"
            backward_flow_id = f"{protocol}_{dst_ip}_{src_ip}"
        
        # Lock for thread safety
        with self.flow_lock:
            # Check if we already have this flow
            if forward_flow_id in self.flows:
                flow = self.flows[forward_flow_id]
                flow.add_packet(packet, timestamp, size, "forward")
                direction = "forward"
            elif backward_flow_id in self.flows:
                flow = self.flows[backward_flow_id]
                flow.add_packet(packet, timestamp, size, "backward")
                direction = "backward"
            else:
                # Create new flow
                flow = NetworkFlow(src_ip, dst_ip, src_port, dst_port, protocol)
                flow.add_packet(packet, timestamp, size, "forward")
                self.flows[forward_flow_id] = flow
                direction = "forward"
                
                # Update statistics
                self.stats['total_flows'] += 1
                self.stats['active_flows'] += 1
                
                if protocol == 'TCP':
                    self.stats['tcp_flows'] += 1
                elif protocol == 'UDP':
                    self.stats['udp_flows'] += 1
                elif protocol == 'ICMP':
                    self.stats['icmp_flows'] += 1
                else:
                    self.stats['other_flows'] += 1
            
            # Update last update time
            self.stats['last_update'] = datetime.now()
            
            # Check if we need to clean up flows due to memory constraints
            if len(self.flows) > self.max_flows:
                self._force_cleanup()
        
        # Get flow features
        features = flow.get_flow_features()
        
        # Call callback if provided
        if self.callback:
            self.callback(flow, features)
        
        return features
    
    def _extract_flow_info(self, packet: Any) -> Optional[Tuple]:
        """Extract flow information from a packet.
        
        Args:
            packet: The packet to extract information from
            
        Returns:
            Tuple of (src_ip, dst_ip, src_port, dst_port, protocol, size, timestamp)
            or None if the packet doesn't contain flow information
        """
        try:
            if SCAPY_AVAILABLE and hasattr(packet, 'haslayer'):
                # Scapy packet
                if not packet.haslayer(IP):
                    return None
                
                ip_layer = packet[IP]
                src_ip = ip_layer.src
                dst_ip = ip_layer.dst
                size = len(packet)
                timestamp = datetime.now()
                
                if packet.haslayer(TCP):
                    tcp_layer = packet[TCP]
                    src_port = tcp_layer.sport
                    dst_port = tcp_layer.dport
                    protocol = 'TCP'
                elif packet.haslayer(UDP):
                    udp_layer = packet[UDP]
                    src_port = udp_layer.sport
                    dst_port = udp_layer.dport
                    protocol = 'UDP'
                elif packet.haslayer(ICMP):
                    src_port = None
                    dst_port = None
                    protocol = 'ICMP'
                else:
                    src_port = None
                    dst_port = None
                    protocol = str(ip_layer.proto)
                
                return src_ip, dst_ip, src_port, dst_port, protocol, size, timestamp
            
            elif hasattr(packet, 'ip'):
                # Pyshark packet
                ip_layer = packet.ip
                src_ip = ip_layer.src
                dst_ip = ip_layer.dst
                size = int(packet.length)
                timestamp = datetime.now()
                
                if hasattr(packet, 'tcp'):
                    tcp_layer = packet.tcp
                    src_port = int(tcp_layer.srcport)
                    dst_port = int(tcp_layer.dstport)
                    protocol = 'TCP'
                elif hasattr(packet, 'udp'):
                    udp_layer = packet.udp
                    src_port = int(udp_layer.srcport)
                    dst_port = int(udp_layer.dstport)
                    protocol = 'UDP'
                elif hasattr(packet, 'icmp'):
                    src_port = None
                    dst_port = None
                    protocol = 'ICMP'
                else:
                    src_port = None
                    dst_port = None
                    protocol = ip_layer.proto
                
                return src_ip, dst_ip, src_port, dst_port, protocol, size, timestamp
            
            return None
        
        except Exception as e:
            self.logger.error(f"Error extracting flow information: {str(e)}")
            return None
    
    def _cleanup_flows(self) -> None:
        """Periodically clean up expired flows."""
        while not self.stop_event.is_set():
            # Sleep for the cleanup interval
            time.sleep(self.cleanup_interval)
            
            try:
                expired_flows = []
                
                # Lock for thread safety
                with self.flow_lock:
                    # Find expired flows
                    for flow_id, flow in list(self.flows.items()):
                        if flow.is_expired(self.flow_timeout):
                            expired_flows.append((flow_id, flow))
                            del self.flows[flow_id]
                    
                    # Update statistics
                    self.stats['active_flows'] = len(self.flows)
                    self.stats['expired_flows'] += len(expired_flows)
                
                # Process expired flows outside the lock
                for flow_id, flow in expired_flows:
                    # Get final flow features
                    features = flow.get_flow_features()
                    
                    # Call callback if provided
                    if self.callback:
                        self.callback(flow, features, expired=True)
                
                if expired_flows:
                    self.logger.debug(f"Cleaned up {len(expired_flows)} expired flows")
            
            except Exception as e:
                self.logger.error(f"Error in flow cleanup: {str(e)}")
    
    def _force_cleanup(self) -> None:
        """Force cleanup of oldest flows when memory limit is reached."""
        # Calculate how many flows to remove
        flows_to_remove = len(self.flows) - int(self.max_flows * 0.8)  # Remove 20% of max_flows
        
        if flows_to_remove <= 0:
            return
        
        # Sort flows by last activity time
        sorted_flows = sorted(
            self.flows.items(),
            key=lambda x: x[1].last_time if x[1].last_time else datetime.min
        )
        
        # Remove oldest flows
        for i in range(min(flows_to_remove, len(sorted_flows))):
            flow_id, flow = sorted_flows[i]
            del self.flows[flow_id]
        
        # Update statistics
        self.stats['active_flows'] = len(self.flows)
        self.stats['expired_flows'] += flows_to_remove
        
        self.logger.warning(f"Forced cleanup of {flows_to_remove} flows due to memory constraints")
    
    def stop(self) -> None:
        """Stop the flow analyzer."""
        self.stop_event.set()
        
        if self.cleanup_thread and self.cleanup_thread.is_alive():
            self.cleanup_thread.join(timeout=2.0)
        
        self.logger.info("Flow analyzer stopped")
    
    def get_flow_statistics(self) -> Dict[str, Any]:
        """Get flow statistics.
        
        Returns:
            Dictionary of flow statistics
        """
        with self.flow_lock:
            stats = self.stats.copy()
            stats['active_flows'] = len(self.flows)
            
            # Calculate duration
            duration = (datetime.now() - stats['start_time']).total_seconds()
            stats['duration'] = duration
            
            # Calculate flows per second
            if duration > 0:
                stats['flows_per_second'] = stats['total_flows'] / duration
            
            # Get protocol distribution
            stats['protocol_distribution'] = {
                'TCP': stats['tcp_flows'],
                'UDP': stats['udp_flows'],
                'ICMP': stats['icmp_flows'],
                'Other': stats['other_flows']
            }
            
            return stats
    
    def get_active_flows(self, limit: Optional[int] = None, 
                        filter_func: Optional[Callable] = None) -> List[Dict[str, Any]]:
        """Get active flows with optional filtering.
        
        Args:
            limit: Maximum number of flows to return
            filter_func: Optional filter function
            
        Returns:
            List of flow features
        """
        result = []
        
        with self.flow_lock:
            flows = list(self.flows.values())
        
        # Apply filter if provided
        if filter_func:
            flows = [flow for flow in flows if filter_func(flow)]
        
        # Get features for each flow
        for flow in flows:
            features = flow.get_flow_features()
            result.append(features)
        
        # Sort by packet count (descending)
        result.sort(key=lambda x: x['packet_count'], reverse=True)
        
        # Apply limit if provided
        if limit is not None and limit > 0:
            result = result[:limit]
        
        return result
    
    def get_top_talkers(self, limit: int = 10) -> Dict[str, List[Dict[str, Any]]]:
        """Get top talkers (IPs with most traffic).
        
        Args:
            limit: Maximum number of talkers to return
            
        Returns:
            Dictionary with source and destination top talkers
        """
        src_ip_traffic: Dict[str, int] = collections.defaultdict(int)
        dst_ip_traffic: Dict[str, int] = collections.defaultdict(int)
        
        with self.flow_lock:
            for flow in self.flows.values():
                src_ip_traffic[flow.src_ip] += flow.forward_byte_count
                dst_ip_traffic[flow.dst_ip] += flow.forward_byte_count
        
        # Sort by traffic volume
        src_top_talkers = sorted(
            [{'ip': ip, 'bytes': bytes} for ip, bytes in src_ip_traffic.items()],
            key=lambda x: x['bytes'],
            reverse=True
        )
        
        dst_top_talkers = sorted(
            [{'ip': ip, 'bytes': bytes} for ip, bytes in dst_ip_traffic.items()],
            key=lambda x: x['bytes'],
            reverse=True
        )
        
        # Apply limit
        src_top_talkers = src_top_talkers[:limit]
        dst_top_talkers = dst_top_talkers[:limit]
        
        return {
            'source': src_top_talkers,
            'destination': dst_top_talkers
        }
    
    def get_top_ports(self, limit: int = 10) -> Dict[str, List[Dict[str, Any]]]:
        """Get top ports (ports with most connections).
        
        Args:
            limit: Maximum number of ports to return
            
        Returns:
            Dictionary with source and destination top ports
        """
        src_port_connections: Dict[int, int] = collections.defaultdict(int)
        dst_port_connections: Dict[int, int] = collections.defaultdict(int)
        
        with self.flow_lock:
            for flow in self.flows.values():
                if flow.src_port is not None:
                    src_port_connections[flow.src_port] += 1
                if flow.dst_port is not None:
                    dst_port_connections[flow.dst_port] += 1
        
        # Sort by connection count
        src_top_ports = sorted(
            [{'port': port, 'connections': count} for port, count in src_port_connections.items()],
            key=lambda x: x['connections'],
            reverse=True
        )
        
        dst_top_ports = sorted(
            [{'port': port, 'connections': count} for port, count in dst_port_connections.items()],
            key=lambda x: x['connections'],
            reverse=True
        )
        
        # Apply limit
        src_top_ports = src_top_ports[:limit]
        dst_top_ports = dst_top_ports[:limit]
        
        return {
            'source': src_top_ports,
            'destination': dst_top_ports
        }
    
    def detect_port_scan(self, threshold: int = 10, 
                        time_window: int = 60) -> List[Dict[str, Any]]:
        """Detect potential port scan activity.
        
        Args:
            threshold: Minimum number of unique ports to consider as a scan
            time_window: Time window in seconds to look for port scans
            
        Returns:
            List of potential port scan details
        """
        result = []
        
        # Calculate time threshold
        time_threshold = datetime.now() - timedelta(seconds=time_window)
        
        # Track source IPs and their target ports
        ip_port_map: Dict[str, Set[Tuple[str, int]]] = collections.defaultdict(set)
        
        with self.flow_lock:
            for flow in self.flows.values():
                # Skip flows that started before the time window
                if flow.start_time and flow.start_time < time_threshold:
                    continue
                
                # Skip flows without destination port
                if flow.dst_port is None:
                    continue
                
                # Add destination IP and port to the source IP's set
                ip_port_map[flow.src_ip].add((flow.dst_ip, flow.dst_port))
        
        # Check for IPs that have connected to many ports
        for src_ip, dst_set in ip_port_map.items():
            # Group by destination IP
            ip_ports: Dict[str, Set[int]] = collections.defaultdict(set)
            for dst_ip, dst_port in dst_set:
                ip_ports[dst_ip].add(dst_port)
            
            # Check each destination IP for port scan
            for dst_ip, ports in ip_ports.items():
                if len(ports) >= threshold:
                    result.append({
                        'src_ip': src_ip,
                        'dst_ip': dst_ip,
                        'unique_ports': len(ports),
                        'ports': sorted(list(ports))[:20],  # Limit to first 20 ports
                        'timestamp': datetime.now().isoformat()
                    })
        
        return result
    
    def detect_unusual_protocols(self) -> List[Dict[str, Any]]:
        """Detect unusual protocol usage.
        
        Returns:
            List of unusual protocol details
        """
        result = []
        
        # Define common protocols
        common_protocols = {'TCP', 'UDP', 'ICMP'}
        
        # Track protocols by source IP
        ip_protocols: Dict[str, Set[str]] = collections.defaultdict(set)
        
        with self.flow_lock:
            for flow in self.flows.values():
                if flow.protocol not in common_protocols:
                    ip_protocols[flow.src_ip].add(flow.protocol)
        
        # Report IPs using unusual protocols
        for src_ip, protocols in ip_protocols.items():
            if protocols:  # Only report if there are unusual protocols
                result.append({
                    'src_ip': src_ip,
                    'unusual_protocols': list(protocols),
                    'timestamp': datetime.now().isoformat()
                })
        
        return result