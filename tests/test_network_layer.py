#!/usr/bin/env python
# SentinelX Network Layer Tests

import os
import sys
import unittest
import tempfile
from unittest.mock import patch, MagicMock
import time

# Add parent directory to path to import SentinelX modules
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

from src.network.packet_capture import PacketCapture
from src.network.flow_analyzer import NetworkFlow, FlowAnalyzer


class TestPacketCapture(unittest.TestCase):
    """Test the PacketCapture class."""
    
    def setUp(self):
        """Set up the test environment."""
        # Create a temporary directory for pcap files
        self.temp_dir = tempfile.mkdtemp()
        
        # Create a mock packet
        self.mock_packet = MagicMock()
        self.mock_packet.time = time.time()
        self.mock_packet.len = 100
        
        # Create IP layer
        self.mock_packet.haslayer = lambda x: x in ['IP', 'TCP']
        self.mock_packet['IP'] = MagicMock()
        self.mock_packet['IP'].src = '192.168.1.1'
        self.mock_packet['IP'].dst = '192.168.1.2'
        self.mock_packet['IP'].proto = 6  # TCP
        
        # Create TCP layer
        self.mock_packet['TCP'] = MagicMock()
        self.mock_packet['TCP'].sport = 12345
        self.mock_packet['TCP'].dport = 80
        self.mock_packet['TCP'].flags = 'S'  # SYN flag
        
        # Create a packet capture object
        self.packet_capture = PacketCapture()
    
    def tearDown(self):
        """Clean up the test environment."""
        # Remove temporary files
        for root, dirs, files in os.walk(self.temp_dir):
            for file in files:
                os.unlink(os.path.join(root, file))
        
        os.rmdir(self.temp_dir)
    
    @patch('src.network.packet_capture.get_if_list')
    def test_get_available_interfaces(self, mock_get_if_list):
        """Test getting available interfaces."""
        # Mock the get_if_list function
        mock_get_if_list.return_value = ['eth0', 'lo']
        
        # Get available interfaces
        interfaces = self.packet_capture.get_available_interfaces()
        
        # Check that the interfaces were returned correctly
        self.assertEqual(interfaces, ['eth0', 'lo'])
    
    @patch('src.network.packet_capture.sniff')
    def test_start_stop_capture(self, mock_sniff):
        """Test starting and stopping packet capture."""
        # Mock the sniff function
        mock_sniff.return_value = [self.mock_packet]
        
        # Start capture
        self.packet_capture.start_capture('eth0')
        
        # Check that the capture is running
        self.assertTrue(self.packet_capture.is_running)
        
        # Stop capture
        self.packet_capture.stop_capture()
        
        # Check that the capture is stopped
        self.assertFalse(self.packet_capture.is_running)
    
    def test_process_packet(self):
        """Test processing a packet."""
        # Process a packet
        self.packet_capture.process_packet(self.mock_packet)
        
        # Check that the packet was processed correctly
        self.assertEqual(self.packet_capture.packet_count, 1)
        self.assertEqual(self.packet_capture.byte_count, 100)
        
        # Check that the packet was added to the packet list
        self.assertEqual(len(self.packet_capture.packets), 1)
        
        # Check that the packet statistics were updated
        self.assertEqual(self.packet_capture.protocol_stats['TCP'], 1)
        self.assertEqual(self.packet_capture.port_stats[80], 1)
    
    @patch('src.network.packet_capture.rdpcap')
    def test_read_pcap(self, mock_rdpcap):
        """Test reading a pcap file."""
        # Mock the rdpcap function
        mock_rdpcap.return_value = [self.mock_packet]
        
        # Read a pcap file
        packets = self.packet_capture.read_pcap('test.pcap')
        
        # Check that the packets were read correctly
        self.assertEqual(len(packets), 1)
    
    def test_get_stats(self):
        """Test getting packet capture statistics."""
        # Process a packet
        self.packet_capture.process_packet(self.mock_packet)
        
        # Get statistics
        stats = self.packet_capture.get_stats()
        
        # Check that the statistics are correct
        self.assertEqual(stats['total_packets'], 1)
        self.assertEqual(stats['total_bytes'], 100)
        self.assertEqual(stats['protocol_stats']['TCP'], 1)
        self.assertEqual(stats['port_stats'][80], 1)


class TestNetworkFlow(unittest.TestCase):
    """Test the NetworkFlow class."""
    
    def setUp(self):
        """Set up the test environment."""
        # Create a flow
        self.flow = NetworkFlow('192.168.1.1', '192.168.1.2', 12345, 80, 'TCP')
        
        # Create a mock packet
        self.mock_packet = MagicMock()
        self.mock_packet.time = time.time()
        self.mock_packet.len = 100
        
        # Create IP layer
        self.mock_packet.haslayer = lambda x: x in ['IP', 'TCP']
        self.mock_packet['IP'] = MagicMock()
        self.mock_packet['IP'].src = '192.168.1.1'
        self.mock_packet['IP'].dst = '192.168.1.2'
        self.mock_packet['IP'].proto = 6  # TCP
        
        # Create TCP layer
        self.mock_packet['TCP'] = MagicMock()
        self.mock_packet['TCP'].sport = 12345
        self.mock_packet['TCP'].dport = 80
        self.mock_packet['TCP'].flags = 'S'  # SYN flag
    
    def test_add_packet(self):
        """Test adding a packet to a flow."""
        # Add a packet
        self.flow.add_packet(self.mock_packet)
        
        # Check that the packet was added correctly
        self.assertEqual(self.flow.packet_count, 1)
        self.assertEqual(self.flow.byte_count, 100)
        self.assertEqual(self.flow.tcp_flags, {'S'})
    
    def test_is_expired(self):
        """Test checking if a flow is expired."""
        # Add a packet
        self.flow.add_packet(self.mock_packet)
        
        # Check that the flow is not expired
        self.assertFalse(self.flow.is_expired(timeout=60))
        
        # Set the last update time to 61 seconds ago
        self.flow.last_update_time = time.time() - 61
        
        # Check that the flow is expired
        self.assertTrue(self.flow.is_expired(timeout=60))
    
    def test_get_stats(self):
        """Test getting flow statistics."""
        # Add a packet
        self.flow.add_packet(self.mock_packet)
        
        # Get statistics
        stats = self.flow.get_stats()
        
        # Check that the statistics are correct
        self.assertEqual(stats['src_ip'], '192.168.1.1')
        self.assertEqual(stats['dst_ip'], '192.168.1.2')
        self.assertEqual(stats['src_port'], 12345)
        self.assertEqual(stats['dst_port'], 80)
        self.assertEqual(stats['protocol'], 'TCP')
        self.assertEqual(stats['packet_count'], 1)
        self.assertEqual(stats['byte_count'], 100)
        self.assertEqual(stats['tcp_flags'], ['S'])


class TestFlowAnalyzer(unittest.TestCase):
    """Test the FlowAnalyzer class."""
    
    def setUp(self):
        """Set up the test environment."""
        # Create a flow analyzer
        self.flow_analyzer = FlowAnalyzer()
        
        # Create a mock packet
        self.mock_packet = MagicMock()
        self.mock_packet.time = time.time()
        self.mock_packet.len = 100
        
        # Create IP layer
        self.mock_packet.haslayer = lambda x: x in ['IP', 'TCP']
        self.mock_packet['IP'] = MagicMock()
        self.mock_packet['IP'].src = '192.168.1.1'
        self.mock_packet['IP'].dst = '192.168.1.2'
        self.mock_packet['IP'].proto = 6  # TCP
        
        # Create TCP layer
        self.mock_packet['TCP'] = MagicMock()
        self.mock_packet['TCP'].sport = 12345
        self.mock_packet['TCP'].dport = 80
        self.mock_packet['TCP'].flags = 'S'  # SYN flag
    
    def test_process_packet(self):
        """Test processing a packet."""
        # Process a packet
        self.flow_analyzer.process_packet(self.mock_packet)
        
        # Check that a flow was created
        self.assertEqual(len(self.flow_analyzer.flows), 1)
        
        # Get the flow key
        flow_key = ('192.168.1.1', '192.168.1.2', 12345, 80, 'TCP')
        
        # Check that the flow exists
        self.assertIn(flow_key, self.flow_analyzer.flows)
        
        # Check that the flow has the correct statistics
        flow = self.flow_analyzer.flows[flow_key]
        self.assertEqual(flow.packet_count, 1)
        self.assertEqual(flow.byte_count, 100)
    
    def test_cleanup_flows(self):
        """Test cleaning up expired flows."""
        # Process a packet
        self.flow_analyzer.process_packet(self.mock_packet)
        
        # Get the flow key
        flow_key = ('192.168.1.1', '192.168.1.2', 12345, 80, 'TCP')
        
        # Set the flow's last update time to 61 seconds ago
        self.flow_analyzer.flows[flow_key].last_update_time = time.time() - 61
        
        # Clean up flows with a timeout of 60 seconds
        expired_flows = self.flow_analyzer.cleanup_flows(timeout=60)
        
        # Check that the flow was expired
        self.assertEqual(len(expired_flows), 1)
        self.assertEqual(expired_flows[0].src_ip, '192.168.1.1')
        self.assertEqual(expired_flows[0].dst_ip, '192.168.1.2')
        
        # Check that the flow was removed from the flow analyzer
        self.assertEqual(len(self.flow_analyzer.flows), 0)
    
    def test_get_flow_stats(self):
        """Test getting flow statistics."""
        # Process a packet
        self.flow_analyzer.process_packet(self.mock_packet)
        
        # Get flow statistics
        stats = self.flow_analyzer.get_flow_stats()
        
        # Check that the statistics are correct
        self.assertEqual(stats['active_flows'], 1)
        self.assertEqual(stats['total_flows'], 1)
        self.assertEqual(stats['expired_flows'], 0)
    
    def test_get_top_talkers(self):
        """Test getting top talkers."""
        # Process a packet
        self.flow_analyzer.process_packet(self.mock_packet)
        
        # Get top talkers
        top_talkers = self.flow_analyzer.get_top_talkers(limit=10)
        
        # Check that the top talkers are correct
        self.assertEqual(len(top_talkers), 1)
        self.assertEqual(top_talkers[0]['src_ip'], '192.168.1.1')
        self.assertEqual(top_talkers[0]['dst_ip'], '192.168.1.2')
        self.assertEqual(top_talkers[0]['protocol'], 'TCP')
        self.assertEqual(top_talkers[0]['packets'], 1)
        self.assertEqual(top_talkers[0]['bytes'], 100)
    
    def test_detect_port_scan(self):
        """Test detecting port scans."""
        # Create multiple packets to different ports
        for port in range(80, 85):
            mock_packet = MagicMock()
            mock_packet.time = time.time()
            mock_packet.len = 100
            
            # Create IP layer
            mock_packet.haslayer = lambda x: x in ['IP', 'TCP']
            mock_packet['IP'] = MagicMock()
            mock_packet['IP'].src = '192.168.1.1'
            mock_packet['IP'].dst = '192.168.1.2'
            mock_packet['IP'].proto = 6  # TCP
            
            # Create TCP layer
            mock_packet['TCP'] = MagicMock()
            mock_packet['TCP'].sport = 12345
            mock_packet['TCP'].dport = port
            mock_packet['TCP'].flags = 'S'  # SYN flag
            
            # Process the packet
            self.flow_analyzer.process_packet(mock_packet)
        
        # Detect port scans
        port_scans = self.flow_analyzer.detect_port_scan(threshold=5)
        
        # Check that a port scan was detected
        self.assertEqual(len(port_scans), 1)
        self.assertEqual(port_scans[0]['src_ip'], '192.168.1.1')
        self.assertEqual(port_scans[0]['dst_ip'], '192.168.1.2')
        self.assertEqual(port_scans[0]['port_count'], 5)


if __name__ == '__main__':
    unittest.main()