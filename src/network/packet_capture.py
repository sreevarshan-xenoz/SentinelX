# SentinelX Packet Capture Module

import logging
import time
from typing import Dict, List, Any, Optional, Union, Callable, Tuple
import threading
import queue
import os
import sys
from datetime import datetime
import json

# Import scapy for packet capture
try:
    from scapy.all import sniff, IP, TCP, UDP, ICMP, Ether, Raw, wrpcap
    from scapy.layers.http import HTTP, HTTPRequest, HTTPResponse
    from scapy.layers.dns import DNS
    SCAPY_AVAILABLE = True
except ImportError:
    SCAPY_AVAILABLE = False

# Import pyshark as a fallback
try:
    import pyshark
    PYSHARK_AVAILABLE = True
except ImportError:
    PYSHARK_AVAILABLE = False

from ..core.config_manager import ConfigManager
from ..core.logging_manager import LoggingManager
from ..data_layer.feature_extractor import FeatureExtractor


class PacketCapture:
    """Packet capture class for SentinelX.
    
    This class is responsible for capturing network packets from interfaces,
    processing them, and feeding them to the detection models.
    """
    
    def __init__(self, callback: Optional[Callable] = None):
        """Initialize the packet capture module.
        
        Args:
            callback: Optional callback function to process captured packets
        """
        self.config = ConfigManager()
        self.logger = logging.getLogger(__name__)
        
        # Check if we have packet capture libraries available
        if not SCAPY_AVAILABLE and not PYSHARK_AVAILABLE:
            self.logger.error("Neither scapy nor pyshark is available. Packet capture will not work.")
            self.logger.error("Please install scapy or pyshark: pip install scapy pyshark")
            self.capture_available = False
        else:
            self.capture_available = True
            self.logger.info(f"Using {'scapy' if SCAPY_AVAILABLE else 'pyshark'} for packet capture")
        
        # Get network configuration
        self.network_config = self.config.get('network_monitoring', {})
        self.interface = self.network_config.get('interface', None)
        self.capture_filter = self.network_config.get('filter', None)
        self.max_packets = self.network_config.get('max_packets', 0)  # 0 means unlimited
        self.timeout = self.network_config.get('timeout', None)  # None means no timeout
        self.save_pcap = self.network_config.get('save_pcap', False)
        self.pcap_file = self.network_config.get('pcap_file', None)
        
        # Get data directory from config
        data_dir = self.config.get('paths', 'data_dir', '../data')
        
        # Get the directory of the current file
        current_dir = os.path.dirname(os.path.abspath(__file__))
        # Navigate to the data directory
        self.data_dir = os.path.abspath(os.path.join(current_dir, '..', '..', data_dir))
        
        # Create pcap directory if it doesn't exist
        self.pcap_dir = os.path.join(self.data_dir, 'pcap')
        if not os.path.exists(self.pcap_dir):
            os.makedirs(self.pcap_dir)
        
        # If pcap_file is not specified, create a default one
        if self.save_pcap and not self.pcap_file:
            timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
            self.pcap_file = os.path.join(self.pcap_dir, f"capture_{timestamp}.pcap")
        
        # Initialize feature extractor
        self.feature_extractor = FeatureExtractor()
        
        # Initialize packet queue and processing thread
        self.packet_queue = queue.Queue(maxsize=1000)  # Limit queue size to prevent memory issues
        self.processing_thread = None
        self.stop_event = threading.Event()
        
        # Set callback function
        self.callback = callback
        
        # Initialize capture thread
        self.capture_thread = None
        
        # Initialize packet statistics
        self.stats = {
            'total_packets': 0,
            'ip_packets': 0,
            'tcp_packets': 0,
            'udp_packets': 0,
            'icmp_packets': 0,
            'http_packets': 0,
            'dns_packets': 0,
            'other_packets': 0,
            'start_time': None,
            'end_time': None
        }
        
        self.logger.info("Packet capture module initialized")
    
    def start_capture(self, interface: Optional[str] = None, 
                     capture_filter: Optional[str] = None,
                     max_packets: Optional[int] = None,
                     timeout: Optional[int] = None,
                     save_pcap: Optional[bool] = None,
                     pcap_file: Optional[str] = None,
                     async_mode: bool = True) -> bool:
        """Start packet capture.
        
        Args:
            interface: Network interface to capture from (overrides config)
            capture_filter: BPF filter string (overrides config)
            max_packets: Maximum number of packets to capture (overrides config)
            timeout: Capture timeout in seconds (overrides config)
            save_pcap: Whether to save captured packets to a pcap file (overrides config)
            pcap_file: Path to save pcap file (overrides config)
            async_mode: Whether to run capture in a separate thread
            
        Returns:
            True if capture started successfully, False otherwise
        """
        if not self.capture_available:
            self.logger.error("Packet capture is not available. Please install scapy or pyshark.")
            return False
        
        # Override config with provided parameters
        self.interface = interface or self.interface
        self.capture_filter = capture_filter or self.capture_filter
        self.max_packets = max_packets if max_packets is not None else self.max_packets
        self.timeout = timeout if timeout is not None else self.timeout
        self.save_pcap = save_pcap if save_pcap is not None else self.save_pcap
        self.pcap_file = pcap_file or self.pcap_file
        
        # Check if interface is specified
        if not self.interface:
            self.logger.error("No network interface specified for packet capture")
            return False
        
        # Create a new pcap file if save_pcap is enabled but no file is specified
        if self.save_pcap and not self.pcap_file:
            timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
            self.pcap_file = os.path.join(self.pcap_dir, f"capture_{timestamp}.pcap")
        
        # Reset statistics
        self.stats = {
            'total_packets': 0,
            'ip_packets': 0,
            'tcp_packets': 0,
            'udp_packets': 0,
            'icmp_packets': 0,
            'http_packets': 0,
            'dns_packets': 0,
            'other_packets': 0,
            'start_time': datetime.now(),
            'end_time': None
        }
        
        # Start processing thread
        self.stop_event.clear()
        self.processing_thread = threading.Thread(target=self._process_packets)
        self.processing_thread.daemon = True
        self.processing_thread.start()
        
        # Start capture
        if async_mode:
            self.capture_thread = threading.Thread(target=self._capture_packets)
            self.capture_thread.daemon = True
            self.capture_thread.start()
            self.logger.info(f"Started packet capture on interface {self.interface} in async mode")
            return True
        else:
            self.logger.info(f"Started packet capture on interface {self.interface} in sync mode")
            return self._capture_packets()
    
    def stop_capture(self) -> Dict[str, Any]:
        """Stop packet capture.
        
        Returns:
            Capture statistics
        """
        self.stop_event.set()
        
        if self.capture_thread and self.capture_thread.is_alive():
            self.capture_thread.join(timeout=2.0)
        
        if self.processing_thread and self.processing_thread.is_alive():
            self.processing_thread.join(timeout=2.0)
        
        # Update end time
        self.stats['end_time'] = datetime.now()
        
        # Calculate duration
        if self.stats['start_time'] and self.stats['end_time']:
            duration = (self.stats['end_time'] - self.stats['start_time']).total_seconds()
            self.stats['duration'] = duration
            
            # Calculate packets per second
            if duration > 0:
                self.stats['packets_per_second'] = self.stats['total_packets'] / duration
        
        self.logger.info(f"Stopped packet capture. Captured {self.stats['total_packets']} packets")
        return self.stats
    
    def _capture_packets(self) -> bool:
        """Capture packets from the network interface.
        
        Returns:
            True if capture completed successfully, False otherwise
        """
        try:
            if SCAPY_AVAILABLE:
                self.logger.info(f"Starting scapy capture on interface {self.interface}")
                
                # Define packet callback
                def packet_callback(packet):
                    if self.stop_event.is_set():
                        return True  # Stop capture
                    
                    try:
                        self.packet_queue.put(packet, block=False)
                    except queue.Full:
                        self.logger.warning("Packet queue is full, dropping packet")
                    
                    # Update statistics
                    self.stats['total_packets'] += 1
                    
                    # Check if we've reached max_packets
                    if self.max_packets > 0 and self.stats['total_packets'] >= self.max_packets:
                        return True  # Stop capture
                    
                    return False
                
                # Start capture
                sniff(
                    iface=self.interface,
                    filter=self.capture_filter,
                    prn=packet_callback,
                    store=self.save_pcap,
                    timeout=self.timeout,
                    stop_filter=lambda p: self.stop_event.is_set()
                )
                
                # Save pcap if requested
                if self.save_pcap and self.pcap_file:
                    wrpcap(self.pcap_file, [])
                    self.logger.info(f"Saved capture to {self.pcap_file}")
            
            elif PYSHARK_AVAILABLE:
                self.logger.info(f"Starting pyshark capture on interface {self.interface}")
                
                # Create capture object
                capture = pyshark.LiveCapture(
                    interface=self.interface,
                    bpf_filter=self.capture_filter,
                    output_file=self.pcap_file if self.save_pcap else None
                )
                
                # Set timeout
                if self.timeout:
                    capture.set_debug(timeout=self.timeout)
                
                # Start capture
                packet_count = 0
                for packet in capture.sniff_continuously():
                    if self.stop_event.is_set():
                        break
                    
                    try:
                        self.packet_queue.put(packet, block=False)
                    except queue.Full:
                        self.logger.warning("Packet queue is full, dropping packet")
                    
                    # Update statistics
                    self.stats['total_packets'] += 1
                    packet_count += 1
                    
                    # Check if we've reached max_packets
                    if self.max_packets > 0 and packet_count >= self.max_packets:
                        break
                
                # Close capture
                capture.close()
            
            return True
        
        except Exception as e:
            self.logger.error(f"Error during packet capture: {str(e)}")
            return False
    
    def _process_packets(self) -> None:
        """Process captured packets from the queue."""
        while not self.stop_event.is_set() or not self.packet_queue.empty():
            try:
                # Get packet from queue with timeout
                try:
                    packet = self.packet_queue.get(timeout=0.1)
                except queue.Empty:
                    continue
                
                # Process packet
                try:
                    # Extract features
                    features = self.feature_extractor.extract_packet_features(packet)
                    
                    # Update detailed statistics
                    self._update_packet_stats(packet)
                    
                    # Call callback if provided
                    if self.callback and features:
                        self.callback(packet, features)
                
                except Exception as e:
                    self.logger.error(f"Error processing packet: {str(e)}")
                
                finally:
                    # Mark task as done
                    self.packet_queue.task_done()
            
            except Exception as e:
                self.logger.error(f"Error in packet processing thread: {str(e)}")
    
    def _update_packet_stats(self, packet) -> None:
        """Update packet statistics.
        
        Args:
            packet: The packet to update statistics for
        """
        if SCAPY_AVAILABLE and isinstance(packet, (Ether, IP, TCP, UDP, ICMP)):
            # Scapy packet
            if IP in packet:
                self.stats['ip_packets'] += 1
                
                if TCP in packet:
                    self.stats['tcp_packets'] += 1
                    
                    # Check for HTTP
                    if packet.haslayer(HTTPRequest) or packet.haslayer(HTTPResponse) or packet.haslayer(HTTP):
                        self.stats['http_packets'] += 1
                
                elif UDP in packet:
                    self.stats['udp_packets'] += 1
                    
                    # Check for DNS
                    if packet.haslayer(DNS):
                        self.stats['dns_packets'] += 1
                
                elif ICMP in packet:
                    self.stats['icmp_packets'] += 1
                
                else:
                    self.stats['other_packets'] += 1
            else:
                self.stats['other_packets'] += 1
        
        elif PYSHARK_AVAILABLE and hasattr(packet, 'layers'):
            # Pyshark packet
            try:
                if hasattr(packet, 'ip'):
                    self.stats['ip_packets'] += 1
                    
                    if hasattr(packet, 'tcp'):
                        self.stats['tcp_packets'] += 1
                        
                        # Check for HTTP
                        if hasattr(packet, 'http'):
                            self.stats['http_packets'] += 1
                    
                    elif hasattr(packet, 'udp'):
                        self.stats['udp_packets'] += 1
                        
                        # Check for DNS
                        if hasattr(packet, 'dns'):
                            self.stats['dns_packets'] += 1
                    
                    elif hasattr(packet, 'icmp'):
                        self.stats['icmp_packets'] += 1
                    
                    else:
                        self.stats['other_packets'] += 1
                else:
                    self.stats['other_packets'] += 1
            
            except Exception as e:
                self.logger.debug(f"Error updating packet stats: {str(e)}")
                self.stats['other_packets'] += 1
    
    def get_available_interfaces(self) -> List[str]:
        """Get a list of available network interfaces.
        
        Returns:
            List of interface names
        """
        interfaces = []
        
        try:
            if SCAPY_AVAILABLE:
                from scapy.arch import get_if_list
                interfaces = get_if_list()
            
            elif PYSHARK_AVAILABLE:
                import pyshark
                # This is a workaround as pyshark doesn't have a direct method
                # to get interfaces
                if sys.platform == 'win32':
                    # On Windows
                    from winreg import ConnectRegistry, OpenKey, EnumKey, HKEY_LOCAL_MACHINE
                    try:
                        reg = ConnectRegistry(None, HKEY_LOCAL_MACHINE)
                        key = OpenKey(reg, r'SOFTWARE\Microsoft\Windows NT\CurrentVersion\NetworkCards')
                        for i in range(100):  # Arbitrary limit
                            try:
                                interfaces.append(EnumKey(key, i))
                            except OSError:
                                break
                    except Exception as e:
                        self.logger.error(f"Error getting Windows interfaces: {str(e)}")
                else:
                    # On Linux/Mac
                    import os
                    if os.path.exists('/sys/class/net'):
                        interfaces = os.listdir('/sys/class/net')
        
        except Exception as e:
            self.logger.error(f"Error getting network interfaces: {str(e)}")
        
        return interfaces
    
    def capture_to_file(self, output_file: str, duration: int = 60, 
                       interface: Optional[str] = None,
                       capture_filter: Optional[str] = None) -> bool:
        """Capture packets to a pcap file.
        
        Args:
            output_file: Path to save pcap file
            duration: Capture duration in seconds
            interface: Network interface to capture from (overrides config)
            capture_filter: BPF filter string (overrides config)
            
        Returns:
            True if capture completed successfully, False otherwise
        """
        if not self.capture_available:
            self.logger.error("Packet capture is not available. Please install scapy or pyshark.")
            return False
        
        # Override config with provided parameters
        interface = interface or self.interface
        capture_filter = capture_filter or self.capture_filter
        
        # Check if interface is specified
        if not interface:
            self.logger.error("No network interface specified for packet capture")
            return False
        
        try:
            if SCAPY_AVAILABLE:
                self.logger.info(f"Starting scapy capture to file {output_file} for {duration} seconds")
                
                # Start capture
                packets = sniff(
                    iface=interface,
                    filter=capture_filter,
                    timeout=duration
                )
                
                # Save to file
                wrpcap(output_file, packets)
                self.logger.info(f"Saved {len(packets)} packets to {output_file}")
                return True
            
            elif PYSHARK_AVAILABLE:
                self.logger.info(f"Starting pyshark capture to file {output_file} for {duration} seconds")
                
                # Create capture object
                capture = pyshark.LiveCapture(
                    interface=interface,
                    bpf_filter=capture_filter,
                    output_file=output_file
                )
                
                # Start capture
                capture.sniff(timeout=duration)
                
                # Close capture
                capture.close()
                self.logger.info(f"Saved capture to {output_file}")
                return True
            
            return False
        
        except Exception as e:
            self.logger.error(f"Error during packet capture to file: {str(e)}")
            return False
    
    def read_pcap_file(self, pcap_file: str, callback: Optional[Callable] = None) -> List[Dict[str, Any]]:
        """Read packets from a pcap file and extract features.
        
        Args:
            pcap_file: Path to pcap file
            callback: Optional callback function to process packets
            
        Returns:
            List of packet features
        """
        if not os.path.exists(pcap_file):
            self.logger.error(f"PCAP file not found: {pcap_file}")
            return []
        
        features_list = []
        
        try:
            if SCAPY_AVAILABLE:
                from scapy.utils import rdpcap
                self.logger.info(f"Reading pcap file with scapy: {pcap_file}")
                
                # Read packets
                packets = rdpcap(pcap_file)
                
                # Process packets
                for packet in packets:
                    try:
                        # Extract features
                        features = self.feature_extractor.extract_packet_features(packet)
                        
                        if features:
                            features_list.append(features)
                            
                            # Call callback if provided
                            if callback:
                                callback(packet, features)
                    
                    except Exception as e:
                        self.logger.error(f"Error processing packet from pcap: {str(e)}")
            
            elif PYSHARK_AVAILABLE:
                self.logger.info(f"Reading pcap file with pyshark: {pcap_file}")
                
                # Create capture object
                capture = pyshark.FileCapture(pcap_file)
                
                # Process packets
                for packet in capture:
                    try:
                        # Extract features
                        features = self.feature_extractor.extract_packet_features(packet)
                        
                        if features:
                            features_list.append(features)
                            
                            # Call callback if provided
                            if callback:
                                callback(packet, features)
                    
                    except Exception as e:
                        self.logger.error(f"Error processing packet from pcap: {str(e)}")
                
                # Close capture
                capture.close()
        
        except Exception as e:
            self.logger.error(f"Error reading pcap file: {str(e)}")
        
        self.logger.info(f"Extracted features from {len(features_list)} packets in {pcap_file}")
        return features_list