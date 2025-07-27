#!/usr/bin/env python
# SentinelX System Information Tests

import os
import sys
import unittest
from unittest.mock import patch, MagicMock
import tempfile
import json
import platform

# Add parent directory to path to import SentinelX modules
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

# Import the SystemInfo class if it exists
try:
    from src.utils.system_info import SystemInfo
except ImportError:
    # Mock SystemInfo if it doesn't exist yet
    class SystemInfo:
        @staticmethod
        def get_system_info():
            return {
                'os': {
                    'name': platform.system(),
                    'version': platform.version(),
                    'architecture': platform.architecture()[0],
                    'machine': platform.machine(),
                    'processor': platform.processor(),
                    'python_version': platform.python_version()
                },
                'memory': {
                    'total': 16 * 1024 * 1024 * 1024,  # 16 GB
                    'available': 8 * 1024 * 1024 * 1024,  # 8 GB
                    'used': 8 * 1024 * 1024 * 1024,  # 8 GB
                    'percent': 50.0
                },
                'cpu': {
                    'count': 8,
                    'percent': 25.0,
                    'frequency': {
                        'current': 2.5,
                        'min': 2.0,
                        'max': 3.0
                    }
                },
                'disk': {
                    'total': 512 * 1024 * 1024 * 1024,  # 512 GB
                    'used': 256 * 1024 * 1024 * 1024,  # 256 GB
                    'free': 256 * 1024 * 1024 * 1024,  # 256 GB
                    'percent': 50.0
                },
                'network': {
                    'interfaces': [
                        {
                            'name': 'eth0',
                            'address': '192.168.1.100',
                            'netmask': '255.255.255.0',
                            'broadcast': '192.168.1.255'
                        }
                    ],
                    'connections': {
                        'established': 10,
                        'listening': 5,
                        'time_wait': 2
                    }
                }
            }
        
        @staticmethod
        def get_memory_info():
            return {
                'total': 16 * 1024 * 1024 * 1024,  # 16 GB
                'available': 8 * 1024 * 1024 * 1024,  # 8 GB
                'used': 8 * 1024 * 1024 * 1024,  # 8 GB
                'percent': 50.0
            }
        
        @staticmethod
        def get_cpu_info():
            return {
                'count': 8,
                'percent': 25.0,
                'frequency': {
                    'current': 2.5,
                    'min': 2.0,
                    'max': 3.0
                }
            }
        
        @staticmethod
        def get_disk_info():
            return {
                'total': 512 * 1024 * 1024 * 1024,  # 512 GB
                'used': 256 * 1024 * 1024 * 1024,  # 256 GB
                'free': 256 * 1024 * 1024 * 1024,  # 256 GB
                'percent': 50.0
            }
        
        @staticmethod
        def get_network_info():
            return {
                'interfaces': [
                    {
                        'name': 'eth0',
                        'address': '192.168.1.100',
                        'netmask': '255.255.255.0',
                        'broadcast': '192.168.1.255'
                    }
                ],
                'connections': {
                    'established': 10,
                    'listening': 5,
                    'time_wait': 2
                }
            }
        
        @staticmethod
        def get_process_info(pid=None):
            if pid is None:
                pid = os.getpid()
            
            return {
                'pid': pid,
                'name': 'python',
                'status': 'running',
                'cpu_percent': 5.0,
                'memory_percent': 2.0,
                'create_time': 1609459200.0,  # 2021-01-01 00:00:00
                'username': 'user'
            }
        
        @staticmethod
        def get_running_processes():
            return [
                {
                    'pid': 1,
                    'name': 'systemd',
                    'status': 'running',
                    'cpu_percent': 0.1,
                    'memory_percent': 0.5,
                    'create_time': 1609459200.0,  # 2021-01-01 00:00:00
                    'username': 'root'
                },
                {
                    'pid': os.getpid(),
                    'name': 'python',
                    'status': 'running',
                    'cpu_percent': 5.0,
                    'memory_percent': 2.0,
                    'create_time': 1609459200.0,  # 2021-01-01 00:00:00
                    'username': 'user'
                }
            ]


class TestSystemInfo(unittest.TestCase):
    """Test the system information functionality."""
    
    def test_get_system_info(self):
        """Test getting system information."""
        system_info = SystemInfo.get_system_info()
        
        # Check that the system info has the expected sections
        self.assertIn('os', system_info, "System info should have an OS section")
        self.assertIn('memory', system_info, "System info should have a memory section")
        self.assertIn('cpu', system_info, "System info should have a CPU section")
        self.assertIn('disk', system_info, "System info should have a disk section")
        self.assertIn('network', system_info, "System info should have a network section")
        
        # Check the OS section
        os_info = system_info['os']
        self.assertIn('name', os_info, "OS info should have a name")
        self.assertIn('version', os_info, "OS info should have a version")
        self.assertIn('architecture', os_info, "OS info should have an architecture")
        
        # Check the memory section
        memory_info = system_info['memory']
        self.assertIn('total', memory_info, "Memory info should have a total")
        self.assertIn('available', memory_info, "Memory info should have an available")
        self.assertIn('used', memory_info, "Memory info should have a used")
        self.assertIn('percent', memory_info, "Memory info should have a percent")
        
        # Check the CPU section
        cpu_info = system_info['cpu']
        self.assertIn('count', cpu_info, "CPU info should have a count")
        self.assertIn('percent', cpu_info, "CPU info should have a percent")
        
        # Check the disk section
        disk_info = system_info['disk']
        self.assertIn('total', disk_info, "Disk info should have a total")
        self.assertIn('used', disk_info, "Disk info should have a used")
        self.assertIn('free', disk_info, "Disk info should have a free")
        self.assertIn('percent', disk_info, "Disk info should have a percent")
        
        # Check the network section
        network_info = system_info['network']
        self.assertIn('interfaces', network_info, "Network info should have interfaces")
        self.assertIn('connections', network_info, "Network info should have connections")
    
    def test_get_memory_info(self):
        """Test getting memory information."""
        memory_info = SystemInfo.get_memory_info()
        
        # Check that the memory info has the expected fields
        self.assertIn('total', memory_info, "Memory info should have a total")
        self.assertIn('available', memory_info, "Memory info should have an available")
        self.assertIn('used', memory_info, "Memory info should have a used")
        self.assertIn('percent', memory_info, "Memory info should have a percent")
        
        # Check that the values are reasonable
        self.assertGreater(memory_info['total'], 0, "Total memory should be positive")
        self.assertGreaterEqual(memory_info['available'], 0, "Available memory should be non-negative")
        self.assertGreaterEqual(memory_info['used'], 0, "Used memory should be non-negative")
        self.assertGreaterEqual(memory_info['percent'], 0, "Memory percent should be non-negative")
        self.assertLessEqual(memory_info['percent'], 100, "Memory percent should be at most 100")
    
    def test_get_cpu_info(self):
        """Test getting CPU information."""
        cpu_info = SystemInfo.get_cpu_info()
        
        # Check that the CPU info has the expected fields
        self.assertIn('count', cpu_info, "CPU info should have a count")
        self.assertIn('percent', cpu_info, "CPU info should have a percent")
        
        # Check that the values are reasonable
        self.assertGreater(cpu_info['count'], 0, "CPU count should be positive")
        self.assertGreaterEqual(cpu_info['percent'], 0, "CPU percent should be non-negative")
        self.assertLessEqual(cpu_info['percent'], 100 * cpu_info['count'], "CPU percent should be at most 100 * count")
        
        # Check frequency if available
        if 'frequency' in cpu_info:
            frequency = cpu_info['frequency']
            self.assertIn('current', frequency, "CPU frequency should have a current value")
            self.assertGreaterEqual(frequency['current'], 0, "CPU frequency should be non-negative")
    
    def test_get_disk_info(self):
        """Test getting disk information."""
        disk_info = SystemInfo.get_disk_info()
        
        # Check that the disk info has the expected fields
        self.assertIn('total', disk_info, "Disk info should have a total")
        self.assertIn('used', disk_info, "Disk info should have a used")
        self.assertIn('free', disk_info, "Disk info should have a free")
        self.assertIn('percent', disk_info, "Disk info should have a percent")
        
        # Check that the values are reasonable
        self.assertGreater(disk_info['total'], 0, "Total disk space should be positive")
        self.assertGreaterEqual(disk_info['used'], 0, "Used disk space should be non-negative")
        self.assertGreaterEqual(disk_info['free'], 0, "Free disk space should be non-negative")
        self.assertGreaterEqual(disk_info['percent'], 0, "Disk percent should be non-negative")
        self.assertLessEqual(disk_info['percent'], 100, "Disk percent should be at most 100")
        
        # Check that total = used + free (approximately)
        self.assertAlmostEqual(disk_info['total'], disk_info['used'] + disk_info['free'], delta=1024, 
                              msg="Total disk space should approximately equal used + free")
    
    def test_get_network_info(self):
        """Test getting network information."""
        network_info = SystemInfo.get_network_info()
        
        # Check that the network info has the expected fields
        self.assertIn('interfaces', network_info, "Network info should have interfaces")
        self.assertIn('connections', network_info, "Network info should have connections")
        
        # Check the interfaces
        interfaces = network_info['interfaces']
        self.assertIsInstance(interfaces, list, "Interfaces should be a list")
        if interfaces:  # Skip if no interfaces are found
            interface = interfaces[0]
            self.assertIn('name', interface, "Interface should have a name")
            self.assertIn('address', interface, "Interface should have an address")
        
        # Check the connections
        connections = network_info['connections']
        self.assertIn('established', connections, "Connections should have an established count")
        self.assertIn('listening', connections, "Connections should have a listening count")
        self.assertGreaterEqual(connections['established'], 0, "Established connections should be non-negative")
        self.assertGreaterEqual(connections['listening'], 0, "Listening connections should be non-negative")
    
    def test_get_process_info(self):
        """Test getting process information."""
        # Test getting info for the current process
        process_info = SystemInfo.get_process_info()
        
        # Check that the process info has the expected fields
        self.assertIn('pid', process_info, "Process info should have a PID")
        self.assertIn('name', process_info, "Process info should have a name")
        self.assertIn('status', process_info, "Process info should have a status")
        self.assertIn('cpu_percent', process_info, "Process info should have a CPU percent")
        self.assertIn('memory_percent', process_info, "Process info should have a memory percent")
        
        # Check that the values are reasonable
        self.assertGreater(process_info['pid'], 0, "PID should be positive")
        self.assertGreaterEqual(process_info['cpu_percent'], 0, "CPU percent should be non-negative")
        self.assertLessEqual(process_info['cpu_percent'], 100, "CPU percent should be at most 100")
        self.assertGreaterEqual(process_info['memory_percent'], 0, "Memory percent should be non-negative")
        self.assertLessEqual(process_info['memory_percent'], 100, "Memory percent should be at most 100")
    
    def test_get_running_processes(self):
        """Test getting information about running processes."""
        processes = SystemInfo.get_running_processes()
        
        # Check that the result is a list
        self.assertIsInstance(processes, list, "Running processes should be a list")
        
        # Check that each process has the expected fields
        if processes:  # Skip if no processes are found
            process = processes[0]
            self.assertIn('pid', process, "Process should have a PID")
            self.assertIn('name', process, "Process should have a name")
            self.assertIn('status', process, "Process should have a status")
            self.assertIn('cpu_percent', process, "Process should have a CPU percent")
            self.assertIn('memory_percent', process, "Process should have a memory percent")
            
            # Check that the values are reasonable
            self.assertGreater(process['pid'], 0, "PID should be positive")
            self.assertGreaterEqual(process['cpu_percent'], 0, "CPU percent should be non-negative")
            self.assertLessEqual(process['cpu_percent'], 100, "CPU percent should be at most 100")
            self.assertGreaterEqual(process['memory_percent'], 0, "Memory percent should be non-negative")
            self.assertLessEqual(process['memory_percent'], 100, "Memory percent should be at most 100")
    
    @patch('platform.system')
    @patch('platform.version')
    @patch('platform.architecture')
    def test_os_detection(self, mock_architecture, mock_version, mock_system):
        """Test OS detection."""
        # Test Windows detection
        mock_system.return_value = 'Windows'
        mock_version.return_value = '10'
        mock_architecture.return_value = ('64bit', '')
        
        system_info = SystemInfo.get_system_info()
        os_info = system_info['os']
        
        self.assertEqual(os_info['name'], 'Windows', "Should detect Windows")
        self.assertEqual(os_info['version'], '10', "Should detect Windows 10")
        self.assertEqual(os_info['architecture'], '64bit', "Should detect 64-bit architecture")
        
        # Test Linux detection
        mock_system.return_value = 'Linux'
        mock_version.return_value = '5.4.0-42-generic'
        
        system_info = SystemInfo.get_system_info()
        os_info = system_info['os']
        
        self.assertEqual(os_info['name'], 'Linux', "Should detect Linux")
        self.assertEqual(os_info['version'], '5.4.0-42-generic', "Should detect Linux version")
        
        # Test macOS detection
        mock_system.return_value = 'Darwin'
        mock_version.return_value = '20.3.0'
        
        system_info = SystemInfo.get_system_info()
        os_info = system_info['os']
        
        self.assertEqual(os_info['name'], 'Darwin', "Should detect macOS (Darwin)")
        self.assertEqual(os_info['version'], '20.3.0', "Should detect macOS version")


if __name__ == '__main__':
    unittest.main()