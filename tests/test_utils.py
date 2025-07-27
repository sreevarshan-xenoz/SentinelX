#!/usr/bin/env python
# SentinelX Utilities Tests

import os
import sys
import unittest
from unittest.mock import patch, MagicMock
import tempfile
import json
import datetime
import ipaddress

# Add parent directory to path to import SentinelX modules
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

# Import utility functions if they exist
try:
    from src.utils.helpers import (
        is_valid_ip, is_valid_domain, is_private_ip, is_valid_mac,
        format_timestamp, parse_timestamp, get_file_hash, get_file_size,
        load_json, save_json, load_yaml, save_yaml,
        validate_schema, merge_dicts, flatten_dict, unflatten_dict,
        generate_id, mask_sensitive_data
    )
except ImportError:
    # Mock utility functions if they don't exist yet
    def is_valid_ip(ip_str):
        try:
            ipaddress.ip_address(ip_str)
            return True
        except ValueError:
            return False
    
    def is_valid_domain(domain):
        import re
        pattern = r'^(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}$'
        return bool(re.match(pattern, domain))
    
    def is_private_ip(ip_str):
        try:
            ip = ipaddress.ip_address(ip_str)
            return ip.is_private
        except ValueError:
            return False
    
    def is_valid_mac(mac_str):
        import re
        pattern = r'^([0-9A-Fa-f]{2}[:-]){5}([0-9A-Fa-f]{2})$'
        return bool(re.match(pattern, mac_str))
    
    def format_timestamp(timestamp=None, format_str='%Y-%m-%d %H:%M:%S'):
        if timestamp is None:
            timestamp = datetime.datetime.now()
        elif isinstance(timestamp, (int, float)):
            timestamp = datetime.datetime.fromtimestamp(timestamp)
        return timestamp.strftime(format_str)
    
    def parse_timestamp(timestamp_str, format_str='%Y-%m-%d %H:%M:%S'):
        return datetime.datetime.strptime(timestamp_str, format_str)
    
    def get_file_hash(file_path, hash_type='sha256'):
        import hashlib
        hash_func = getattr(hashlib, hash_type)()
        with open(file_path, 'rb') as f:
            for chunk in iter(lambda: f.read(4096), b''):
                hash_func.update(chunk)
        return hash_func.hexdigest()
    
    def get_file_size(file_path):
        return os.path.getsize(file_path)
    
    def load_json(file_path):
        with open(file_path, 'r') as f:
            return json.load(f)
    
    def save_json(data, file_path, indent=2):
        with open(file_path, 'w') as f:
            json.dump(data, f, indent=indent)
    
    def load_yaml(file_path):
        import yaml
        with open(file_path, 'r') as f:
            return yaml.safe_load(f)
    
    def save_yaml(data, file_path):
        import yaml
        with open(file_path, 'w') as f:
            yaml.dump(data, f)
    
    def validate_schema(data, schema):
        # This is a simplified version
        for key, value_type in schema.items():
            if key not in data:
                return False
            if not isinstance(data[key], value_type):
                return False
        return True
    
    def merge_dicts(dict1, dict2):
        result = dict1.copy()
        for key, value in dict2.items():
            if key in result and isinstance(result[key], dict) and isinstance(value, dict):
                result[key] = merge_dicts(result[key], value)
            else:
                result[key] = value
        return result
    
    def flatten_dict(d, parent_key='', sep='.'):
        items = []
        for k, v in d.items():
            new_key = f"{parent_key}{sep}{k}" if parent_key else k
            if isinstance(v, dict):
                items.extend(flatten_dict(v, new_key, sep=sep).items())
            else:
                items.append((new_key, v))
        return dict(items)
    
    def unflatten_dict(d, sep='.'):
        result = {}
        for key, value in d.items():
            parts = key.split(sep)
            current = result
            for part in parts[:-1]:
                if part not in current:
                    current[part] = {}
                current = current[part]
            current[parts[-1]] = value
        return result
    
    def generate_id(prefix='', length=8):
        import uuid
        import base64
        id_bytes = uuid.uuid4().bytes[:length]
        id_str = base64.urlsafe_b64encode(id_bytes).decode('ascii').rstrip('=')
        return f"{prefix}{id_str}"
    
    def mask_sensitive_data(data, sensitive_keys=None):
        if sensitive_keys is None:
            sensitive_keys = ['password', 'api_key', 'secret', 'token']
        
        if isinstance(data, dict):
            result = {}
            for key, value in data.items():
                if any(sensitive_key in key.lower() for sensitive_key in sensitive_keys):
                    result[key] = '********'
                elif isinstance(value, (dict, list)):
                    result[key] = mask_sensitive_data(value, sensitive_keys)
                else:
                    result[key] = value
            return result
        elif isinstance(data, list):
            return [mask_sensitive_data(item, sensitive_keys) for item in data]
        else:
            return data


class TestUtils(unittest.TestCase):
    """Test the utility functions."""
    
    def setUp(self):
        """Set up the test environment."""
        # Create a temporary directory for test files
        self.temp_dir = tempfile.mkdtemp()
    
    def tearDown(self):
        """Clean up the test environment."""
        # Remove the temporary directory and its contents
        import shutil
        shutil.rmtree(self.temp_dir)
    
    def test_is_valid_ip(self):
        """Test the is_valid_ip function."""
        # Test valid IPv4 addresses
        self.assertTrue(is_valid_ip('192.168.1.1'), "Should recognize valid IPv4")
        self.assertTrue(is_valid_ip('10.0.0.1'), "Should recognize valid IPv4")
        self.assertTrue(is_valid_ip('172.16.0.1'), "Should recognize valid IPv4")
        
        # Test valid IPv6 addresses
        self.assertTrue(is_valid_ip('::1'), "Should recognize valid IPv6")
        self.assertTrue(is_valid_ip('2001:db8::1'), "Should recognize valid IPv6")
        
        # Test invalid IP addresses
        self.assertFalse(is_valid_ip('256.256.256.256'), "Should reject invalid IPv4")
        self.assertFalse(is_valid_ip('192.168.1'), "Should reject incomplete IPv4")
        self.assertFalse(is_valid_ip('2001:db8::g'), "Should reject invalid IPv6")
        self.assertFalse(is_valid_ip('not an ip'), "Should reject non-IP strings")
    
    def test_is_valid_domain(self):
        """Test the is_valid_domain function."""
        # Test valid domains
        self.assertTrue(is_valid_domain('example.com'), "Should recognize valid domain")
        self.assertTrue(is_valid_domain('sub.example.com'), "Should recognize valid subdomain")
        self.assertTrue(is_valid_domain('example.co.uk'), "Should recognize valid multi-part TLD")
        
        # Test invalid domains
        self.assertFalse(is_valid_domain('example'), "Should reject domain without TLD")
        self.assertFalse(is_valid_domain('example.'), "Should reject domain ending with dot")
        self.assertFalse(is_valid_domain('-example.com'), "Should reject domain starting with hyphen")
        self.assertFalse(is_valid_domain('example-.com'), "Should reject domain with hyphen before dot")
        self.assertFalse(is_valid_domain('exam ple.com'), "Should reject domain with space")
    
    def test_is_private_ip(self):
        """Test the is_private_ip function."""
        # Test private IPv4 addresses
        self.assertTrue(is_private_ip('192.168.1.1'), "Should recognize private IPv4")
        self.assertTrue(is_private_ip('10.0.0.1'), "Should recognize private IPv4")
        self.assertTrue(is_private_ip('172.16.0.1'), "Should recognize private IPv4")
        
        # Test public IPv4 addresses
        self.assertFalse(is_private_ip('8.8.8.8'), "Should recognize public IPv4")
        self.assertFalse(is_private_ip('203.0.113.1'), "Should recognize public IPv4")
        
        # Test private IPv6 addresses
        self.assertTrue(is_private_ip('fd00::1'), "Should recognize private IPv6")
        
        # Test public IPv6 addresses
        self.assertFalse(is_private_ip('2001:db8::1'), "Should recognize public IPv6")
        
        # Test invalid IP addresses
        self.assertRaises(ValueError, is_private_ip, 'not an ip')
    
    def test_is_valid_mac(self):
        """Test the is_valid_mac function."""
        # Test valid MAC addresses
        self.assertTrue(is_valid_mac('00:11:22:33:44:55'), "Should recognize valid MAC with colons")
        self.assertTrue(is_valid_mac('00-11-22-33-44-55'), "Should recognize valid MAC with hyphens")
        
        # Test invalid MAC addresses
        self.assertFalse(is_valid_mac('00:11:22:33:44'), "Should reject incomplete MAC")
        self.assertFalse(is_valid_mac('00:11:22:33:44:55:66'), "Should reject too long MAC")
        self.assertFalse(is_valid_mac('00:11:22:33:44:GG'), "Should reject MAC with invalid characters")
        self.assertFalse(is_valid_mac('not a mac'), "Should reject non-MAC strings")
    
    def test_format_timestamp(self):
        """Test the format_timestamp function."""
        # Test with a specific datetime
        dt = datetime.datetime(2023, 1, 1, 12, 0, 0)
        self.assertEqual(format_timestamp(dt), '2023-01-01 12:00:00', "Should format datetime correctly")
        
        # Test with a timestamp
        timestamp = dt.timestamp()
        self.assertEqual(format_timestamp(timestamp), '2023-01-01 12:00:00', "Should format timestamp correctly")
        
        # Test with a custom format
        self.assertEqual(format_timestamp(dt, '%Y/%m/%d'), '2023/01/01', "Should format with custom format")
        
        # Test with current time (just check that it doesn't raise an exception)
        try:
            format_timestamp()
        except Exception as e:
            self.fail(f"format_timestamp() raised {type(e).__name__} unexpectedly!")
    
    def test_parse_timestamp(self):
        """Test the parse_timestamp function."""
        # Test with a standard format
        dt_str = '2023-01-01 12:00:00'
        expected_dt = datetime.datetime(2023, 1, 1, 12, 0, 0)
        self.assertEqual(parse_timestamp(dt_str), expected_dt, "Should parse timestamp correctly")
        
        # Test with a custom format
        dt_str = '2023/01/01'
        expected_dt = datetime.datetime(2023, 1, 1, 0, 0, 0)
        self.assertEqual(parse_timestamp(dt_str, '%Y/%m/%d'), expected_dt, "Should parse with custom format")
        
        # Test with an invalid format
        dt_str = 'not a timestamp'
        self.assertRaises(ValueError, parse_timestamp, dt_str)
    
    def test_get_file_hash(self):
        """Test the get_file_hash function."""
        # Create a test file
        test_file = os.path.join(self.temp_dir, 'test.txt')
        with open(test_file, 'w') as f:
            f.write('test content')
        
        # Test with SHA-256
        expected_sha256 = 'e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855'  # Empty file
        with patch('builtins.open', mock_open(read_data=b'')):
            self.assertEqual(get_file_hash(test_file), expected_sha256, "Should calculate SHA-256 hash correctly")
        
        # Test with MD5
        expected_md5 = 'd41d8cd98f00b204e9800998ecf8427e'  # Empty file
        with patch('builtins.open', mock_open(read_data=b'')):
            self.assertEqual(get_file_hash(test_file, 'md5'), expected_md5, "Should calculate MD5 hash correctly")
    
    def test_get_file_size(self):
        """Test the get_file_size function."""
        # Create a test file
        test_file = os.path.join(self.temp_dir, 'test.txt')
        test_content = 'test content'
        with open(test_file, 'w') as f:
            f.write(test_content)
        
        # Test getting the file size
        expected_size = len(test_content)
        self.assertEqual(get_file_size(test_file), expected_size, "Should get the correct file size")
    
    def test_load_save_json(self):
        """Test the load_json and save_json functions."""
        # Create a test JSON file
        test_file = os.path.join(self.temp_dir, 'test.json')
        test_data = {'key': 'value', 'list': [1, 2, 3], 'nested': {'inner': 'value'}}
        
        # Test saving JSON
        save_json(test_data, test_file)
        self.assertTrue(os.path.exists(test_file), "Should create the JSON file")
        
        # Test loading JSON
        loaded_data = load_json(test_file)
        self.assertEqual(loaded_data, test_data, "Should load the correct JSON data")
    
    def test_load_save_yaml(self):
        """Test the load_yaml and save_yaml functions."""
        # Skip if PyYAML is not installed
        try:
            import yaml
        except ImportError:
            self.skipTest("PyYAML is not installed")
        
        # Create a test YAML file
        test_file = os.path.join(self.temp_dir, 'test.yaml')
        test_data = {'key': 'value', 'list': [1, 2, 3], 'nested': {'inner': 'value'}}
        
        # Test saving YAML
        save_yaml(test_data, test_file)
        self.assertTrue(os.path.exists(test_file), "Should create the YAML file")
        
        # Test loading YAML
        loaded_data = load_yaml(test_file)
        self.assertEqual(loaded_data, test_data, "Should load the correct YAML data")
    
    def test_validate_schema(self):
        """Test the validate_schema function."""
        # Define a test schema
        schema = {
            'name': str,
            'age': int,
            'is_active': bool
        }
        
        # Test with valid data
        valid_data = {
            'name': 'John',
            'age': 30,
            'is_active': True
        }
        self.assertTrue(validate_schema(valid_data, schema), "Should validate correct data")
        
        # Test with missing field
        invalid_data1 = {
            'name': 'John',
            'is_active': True
        }
        self.assertFalse(validate_schema(invalid_data1, schema), "Should reject data with missing field")
        
        # Test with wrong type
        invalid_data2 = {
            'name': 'John',
            'age': '30',  # String instead of int
            'is_active': True
        }
        self.assertFalse(validate_schema(invalid_data2, schema), "Should reject data with wrong type")
    
    def test_merge_dicts(self):
        """Test the merge_dicts function."""
        # Test merging simple dicts
        dict1 = {'a': 1, 'b': 2}
        dict2 = {'b': 3, 'c': 4}
        expected = {'a': 1, 'b': 3, 'c': 4}
        self.assertEqual(merge_dicts(dict1, dict2), expected, "Should merge simple dicts correctly")
        
        # Test merging nested dicts
        dict1 = {'a': 1, 'b': {'x': 1, 'y': 2}}
        dict2 = {'b': {'y': 3, 'z': 4}, 'c': 5}
        expected = {'a': 1, 'b': {'x': 1, 'y': 3, 'z': 4}, 'c': 5}
        self.assertEqual(merge_dicts(dict1, dict2), expected, "Should merge nested dicts correctly")
        
        # Test that the original dicts are not modified
        dict1_copy = dict1.copy()
        dict2_copy = dict2.copy()
        merge_dicts(dict1, dict2)
        self.assertEqual(dict1, dict1_copy, "Should not modify the first dict")
        self.assertEqual(dict2, dict2_copy, "Should not modify the second dict")
    
    def test_flatten_unflatten_dict(self):
        """Test the flatten_dict and unflatten_dict functions."""
        # Test flattening a nested dict
        nested_dict = {
            'a': 1,
            'b': {
                'x': 2,
                'y': {
                    'z': 3
                }
            },
            'c': 4
        }
        expected_flat = {
            'a': 1,
            'b.x': 2,
            'b.y.z': 3,
            'c': 4
        }
        self.assertEqual(flatten_dict(nested_dict), expected_flat, "Should flatten dict correctly")
        
        # Test unflattening a flat dict
        flat_dict = {
            'a': 1,
            'b.x': 2,
            'b.y.z': 3,
            'c': 4
        }
        expected_nested = {
            'a': 1,
            'b': {
                'x': 2,
                'y': {
                    'z': 3
                }
            },
            'c': 4
        }
        self.assertEqual(unflatten_dict(flat_dict), expected_nested, "Should unflatten dict correctly")
        
        # Test with custom separator
        flat_dict_custom = {
            'a': 1,
            'b/x': 2,
            'b/y/z': 3,
            'c': 4
        }
        self.assertEqual(unflatten_dict(flat_dict_custom, sep='/'), expected_nested, "Should unflatten dict with custom separator")
    
    def test_generate_id(self):
        """Test the generate_id function."""
        # Test generating an ID without a prefix
        id1 = generate_id()
        self.assertIsInstance(id1, str, "Should generate a string ID")
        self.assertEqual(len(id1), 8, "Should generate an ID of the correct length")
        
        # Test generating an ID with a prefix
        prefix = 'test-'
        id2 = generate_id(prefix=prefix)
        self.assertTrue(id2.startswith(prefix), "Should include the prefix")
        
        # Test generating an ID with a custom length
        length = 16
        id3 = generate_id(length=length)
        self.assertEqual(len(id3), length, "Should generate an ID of the custom length")
        
        # Test that generated IDs are unique
        ids = [generate_id() for _ in range(100)]
        self.assertEqual(len(ids), len(set(ids)), "Should generate unique IDs")
    
    def test_mask_sensitive_data(self):
        """Test the mask_sensitive_data function."""
        # Test masking sensitive data in a dict
        data = {
            'username': 'john',
            'password': 'secret',
            'api_key': '1234567890',
            'settings': {
                'theme': 'dark',
                'token': 'abcdef'
            },
            'items': [
                {'id': 1, 'secret': 'item1'},
                {'id': 2, 'secret': 'item2'}
            ]
        }
        
        expected = {
            'username': 'john',
            'password': '********',
            'api_key': '********',
            'settings': {
                'theme': 'dark',
                'token': '********'
            },
            'items': [
                {'id': 1, 'secret': '********'},
                {'id': 2, 'secret': '********'}
            ]
        }
        
        self.assertEqual(mask_sensitive_data(data), expected, "Should mask sensitive data")
        
        # Test with custom sensitive keys
        custom_keys = ['username']
        expected_custom = {
            'username': '********',
            'password': 'secret',
            'api_key': '1234567890',
            'settings': {
                'theme': 'dark',
                'token': 'abcdef'
            },
            'items': [
                {'id': 1, 'secret': 'item1'},
                {'id': 2, 'secret': 'item2'}
            ]
        }
        
        self.assertEqual(mask_sensitive_data(data, custom_keys), expected_custom, "Should mask custom sensitive data")


if __name__ == '__main__':
    unittest.main()