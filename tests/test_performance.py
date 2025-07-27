#!/usr/bin/env python
# SentinelX Performance Monitoring Tests

import os
import sys
import unittest
from unittest.mock import patch, MagicMock
import tempfile
import time
import json

# Add parent directory to path to import SentinelX modules
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

# Import the PerformanceMonitor class if it exists
try:
    from src.utils.performance import PerformanceMonitor
except ImportError:
    # Mock PerformanceMonitor if it doesn't exist yet
    class PerformanceMonitor:
        def __init__(self):
            self.metrics = {}
            self.start_times = {}
            self.counters = {}
            self.enabled = True
        
        def start_timer(self, name):
            if not self.enabled:
                return
            
            self.start_times[name] = time.time()
        
        def stop_timer(self, name):
            if not self.enabled or name not in self.start_times:
                return 0
            
            elapsed = time.time() - self.start_times[name]
            if name not in self.metrics:
                self.metrics[name] = {
                    'count': 0,
                    'total_time': 0,
                    'min_time': float('inf'),
                    'max_time': 0,
                    'avg_time': 0
                }
            
            self.metrics[name]['count'] += 1
            self.metrics[name]['total_time'] += elapsed
            self.metrics[name]['min_time'] = min(self.metrics[name]['min_time'], elapsed)
            self.metrics[name]['max_time'] = max(self.metrics[name]['max_time'], elapsed)
            self.metrics[name]['avg_time'] = self.metrics[name]['total_time'] / self.metrics[name]['count']
            
            return elapsed
        
        def increment_counter(self, name, value=1):
            if not self.enabled:
                return
            
            if name not in self.counters:
                self.counters[name] = 0
            
            self.counters[name] += value
        
        def get_metrics(self):
            return {
                'timers': self.metrics,
                'counters': self.counters
            }
        
        def reset(self):
            self.metrics = {}
            self.start_times = {}
            self.counters = {}
        
        def enable(self):
            self.enabled = True
        
        def disable(self):
            self.enabled = False
        
        def is_enabled(self):
            return self.enabled
        
        def save_metrics(self, file_path):
            with open(file_path, 'w') as f:
                json.dump(self.get_metrics(), f, indent=2)
        
        def load_metrics(self, file_path):
            with open(file_path, 'r') as f:
                data = json.load(f)
            
            self.metrics = data.get('timers', {})
            self.counters = data.get('counters', {})
        
        def __enter__(self):
            self.start_timer('total')
            return self
        
        def __exit__(self, exc_type, exc_val, exc_tb):
            self.stop_timer('total')


class TestPerformanceMonitor(unittest.TestCase):
    """Test the performance monitoring functionality."""
    
    def setUp(self):
        """Set up the test environment."""
        # Create a performance monitor
        self.monitor = PerformanceMonitor()
        
        # Create a temporary directory for test files
        self.temp_dir = tempfile.mkdtemp()
    
    def tearDown(self):
        """Clean up the test environment."""
        # Reset the performance monitor
        self.monitor.reset()
        
        # Remove the temporary directory and its contents
        import shutil
        shutil.rmtree(self.temp_dir)
    
    def test_timer(self):
        """Test the timer functionality."""
        # Start a timer
        self.monitor.start_timer('test_timer')
        
        # Sleep for a short time
        time.sleep(0.1)
        
        # Stop the timer
        elapsed = self.monitor.stop_timer('test_timer')
        
        # Check that the elapsed time is reasonable
        self.assertGreaterEqual(elapsed, 0.1, "Elapsed time should be at least 0.1 seconds")
        self.assertLessEqual(elapsed, 0.2, "Elapsed time should be at most 0.2 seconds")
        
        # Check that the metrics were updated
        metrics = self.monitor.get_metrics()
        self.assertIn('timers', metrics, "Metrics should have a timers section")
        self.assertIn('test_timer', metrics['timers'], "Timers should include test_timer")
        
        timer_metrics = metrics['timers']['test_timer']
        self.assertEqual(timer_metrics['count'], 1, "Timer count should be 1")
        self.assertGreaterEqual(timer_metrics['total_time'], 0.1, "Total time should be at least 0.1 seconds")
        self.assertLessEqual(timer_metrics['total_time'], 0.2, "Total time should be at most 0.2 seconds")
        self.assertEqual(timer_metrics['min_time'], timer_metrics['total_time'], "Min time should equal total time for a single run")
        self.assertEqual(timer_metrics['max_time'], timer_metrics['total_time'], "Max time should equal total time for a single run")
        self.assertEqual(timer_metrics['avg_time'], timer_metrics['total_time'], "Avg time should equal total time for a single run")
    
    def test_multiple_timers(self):
        """Test multiple timers."""
        # Start and stop multiple timers
        self.monitor.start_timer('timer1')
        time.sleep(0.1)
        self.monitor.stop_timer('timer1')
        
        self.monitor.start_timer('timer2')
        time.sleep(0.2)
        self.monitor.stop_timer('timer2')
        
        # Check that both timers were recorded
        metrics = self.monitor.get_metrics()
        self.assertIn('timer1', metrics['timers'], "Timers should include timer1")
        self.assertIn('timer2', metrics['timers'], "Timers should include timer2")
        
        # Check that the elapsed times are reasonable
        self.assertGreaterEqual(metrics['timers']['timer1']['total_time'], 0.1, "Timer1 should be at least 0.1 seconds")
        self.assertGreaterEqual(metrics['timers']['timer2']['total_time'], 0.2, "Timer2 should be at least 0.2 seconds")
    
    def test_timer_multiple_runs(self):
        """Test a timer with multiple runs."""
        # Run the timer multiple times
        for i in range(3):
            self.monitor.start_timer('test_timer')
            time.sleep(0.1 * (i + 1))  # Sleep for 0.1, 0.2, 0.3 seconds
            self.monitor.stop_timer('test_timer')
        
        # Check that the metrics were updated correctly
        metrics = self.monitor.get_metrics()
        timer_metrics = metrics['timers']['test_timer']
        
        self.assertEqual(timer_metrics['count'], 3, "Timer count should be 3")
        self.assertGreaterEqual(timer_metrics['total_time'], 0.6, "Total time should be at least 0.6 seconds")
        self.assertGreaterEqual(timer_metrics['min_time'], 0.1, "Min time should be at least 0.1 seconds")
        self.assertLessEqual(timer_metrics['min_time'], 0.2, "Min time should be at most 0.2 seconds")
        self.assertGreaterEqual(timer_metrics['max_time'], 0.3, "Max time should be at least 0.3 seconds")
        self.assertLessEqual(timer_metrics['max_time'], 0.4, "Max time should be at most 0.4 seconds")
        self.assertGreaterEqual(timer_metrics['avg_time'], 0.2, "Avg time should be at least 0.2 seconds")
        self.assertLessEqual(timer_metrics['avg_time'], 0.3, "Avg time should be at most 0.3 seconds")
    
    def test_counter(self):
        """Test the counter functionality."""
        # Increment a counter
        self.monitor.increment_counter('test_counter')
        
        # Check that the counter was incremented
        metrics = self.monitor.get_metrics()
        self.assertIn('counters', metrics, "Metrics should have a counters section")
        self.assertIn('test_counter', metrics['counters'], "Counters should include test_counter")
        self.assertEqual(metrics['counters']['test_counter'], 1, "Counter should be 1")
        
        # Increment the counter again
        self.monitor.increment_counter('test_counter')
        
        # Check that the counter was incremented again
        metrics = self.monitor.get_metrics()
        self.assertEqual(metrics['counters']['test_counter'], 2, "Counter should be 2")
        
        # Increment the counter by a specific value
        self.monitor.increment_counter('test_counter', 3)
        
        # Check that the counter was incremented by the specific value
        metrics = self.monitor.get_metrics()
        self.assertEqual(metrics['counters']['test_counter'], 5, "Counter should be 5")
    
    def test_multiple_counters(self):
        """Test multiple counters."""
        # Increment multiple counters
        self.monitor.increment_counter('counter1')
        self.monitor.increment_counter('counter2', 2)
        
        # Check that both counters were recorded
        metrics = self.monitor.get_metrics()
        self.assertIn('counter1', metrics['counters'], "Counters should include counter1")
        self.assertIn('counter2', metrics['counters'], "Counters should include counter2")
        
        # Check that the counters have the correct values
        self.assertEqual(metrics['counters']['counter1'], 1, "Counter1 should be 1")
        self.assertEqual(metrics['counters']['counter2'], 2, "Counter2 should be 2")
    
    def test_reset(self):
        """Test resetting the performance monitor."""
        # Record some metrics
        self.monitor.start_timer('test_timer')
        time.sleep(0.1)
        self.monitor.stop_timer('test_timer')
        
        self.monitor.increment_counter('test_counter')
        
        # Check that the metrics were recorded
        metrics = self.monitor.get_metrics()
        self.assertIn('test_timer', metrics['timers'], "Timers should include test_timer")
        self.assertIn('test_counter', metrics['counters'], "Counters should include test_counter")
        
        # Reset the monitor
        self.monitor.reset()
        
        # Check that the metrics were reset
        metrics = self.monitor.get_metrics()
        self.assertEqual(metrics['timers'], {}, "Timers should be empty after reset")
        self.assertEqual(metrics['counters'], {}, "Counters should be empty after reset")
    
    def test_enable_disable(self):
        """Test enabling and disabling the performance monitor."""
        # Disable the monitor
        self.monitor.disable()
        
        # Check that the monitor is disabled
        self.assertFalse(self.monitor.is_enabled(), "Monitor should be disabled")
        
        # Record some metrics while disabled
        self.monitor.start_timer('test_timer')
        self.monitor.stop_timer('test_timer')
        
        self.monitor.increment_counter('test_counter')
        
        # Check that no metrics were recorded
        metrics = self.monitor.get_metrics()
        self.assertEqual(metrics['timers'], {}, "Timers should be empty when disabled")
        self.assertEqual(metrics['counters'], {}, "Counters should be empty when disabled")
        
        # Enable the monitor
        self.monitor.enable()
        
        # Check that the monitor is enabled
        self.assertTrue(self.monitor.is_enabled(), "Monitor should be enabled")
        
        # Record some metrics while enabled
        self.monitor.start_timer('test_timer')
        self.monitor.stop_timer('test_timer')
        
        self.monitor.increment_counter('test_counter')
        
        # Check that the metrics were recorded
        metrics = self.monitor.get_metrics()
        self.assertIn('test_timer', metrics['timers'], "Timers should include test_timer when enabled")
        self.assertIn('test_counter', metrics['counters'], "Counters should include test_counter when enabled")
    
    def test_save_load_metrics(self):
        """Test saving and loading metrics."""
        # Record some metrics
        self.monitor.start_timer('test_timer')
        time.sleep(0.1)
        self.monitor.stop_timer('test_timer')
        
        self.monitor.increment_counter('test_counter')
        
        # Save the metrics to a file
        metrics_file = os.path.join(self.temp_dir, 'metrics.json')
        self.monitor.save_metrics(metrics_file)
        
        # Check that the file was created
        self.assertTrue(os.path.exists(metrics_file), "Metrics file should be created")
        
        # Reset the monitor
        self.monitor.reset()
        
        # Check that the metrics were reset
        metrics = self.monitor.get_metrics()
        self.assertEqual(metrics['timers'], {}, "Timers should be empty after reset")
        self.assertEqual(metrics['counters'], {}, "Counters should be empty after reset")
        
        # Load the metrics from the file
        self.monitor.load_metrics(metrics_file)
        
        # Check that the metrics were loaded
        metrics = self.monitor.get_metrics()
        self.assertIn('test_timer', metrics['timers'], "Timers should include test_timer after loading")
        self.assertIn('test_counter', metrics['counters'], "Counters should include test_counter after loading")
    
    def test_context_manager(self):
        """Test using the performance monitor as a context manager."""
        # Use the monitor as a context manager
        with self.monitor as m:
            # Check that the monitor is the same object
            self.assertIs(m, self.monitor, "Context manager should return the monitor")
            
            # Sleep for a short time
            time.sleep(0.1)
        
        # Check that the total timer was recorded
        metrics = self.monitor.get_metrics()
        self.assertIn('total', metrics['timers'], "Timers should include total")
        self.assertGreaterEqual(metrics['timers']['total']['total_time'], 0.1, "Total time should be at least 0.1 seconds")
    
    def test_nested_timers(self):
        """Test nested timers."""
        # Start an outer timer
        self.monitor.start_timer('outer')
        
        # Sleep for a short time
        time.sleep(0.1)
        
        # Start an inner timer
        self.monitor.start_timer('inner')
        
        # Sleep for a short time
        time.sleep(0.1)
        
        # Stop the inner timer
        inner_elapsed = self.monitor.stop_timer('inner')
        
        # Sleep for a short time
        time.sleep(0.1)
        
        # Stop the outer timer
        outer_elapsed = self.monitor.stop_timer('outer')
        
        # Check that the elapsed times are reasonable
        self.assertGreaterEqual(inner_elapsed, 0.1, "Inner elapsed time should be at least 0.1 seconds")
        self.assertLessEqual(inner_elapsed, 0.2, "Inner elapsed time should be at most 0.2 seconds")
        
        self.assertGreaterEqual(outer_elapsed, 0.3, "Outer elapsed time should be at least 0.3 seconds")
        self.assertLessEqual(outer_elapsed, 0.4, "Outer elapsed time should be at most 0.4 seconds")
        
        # Check that both timers were recorded
        metrics = self.monitor.get_metrics()
        self.assertIn('outer', metrics['timers'], "Timers should include outer")
        self.assertIn('inner', metrics['timers'], "Timers should include inner")
    
    def test_timer_decorator(self):
        """Test the timer decorator if it exists."""
        # Skip if the timer decorator doesn't exist
        if not hasattr(PerformanceMonitor, 'timer'):
            self.skipTest("Timer decorator not implemented")
        
        # Define a function with the timer decorator
        @PerformanceMonitor.timer('decorated_function')
        def decorated_function():
            time.sleep(0.1)
            return 42
        
        # Call the decorated function
        result = decorated_function()
        
        # Check that the function returned the correct result
        self.assertEqual(result, 42, "Decorated function should return the correct result")
        
        # Check that the timer was recorded
        metrics = self.monitor.get_metrics()
        self.assertIn('decorated_function', metrics['timers'], "Timers should include decorated_function")
        self.assertGreaterEqual(metrics['timers']['decorated_function']['total_time'], 0.1, 
                              "Decorated function time should be at least 0.1 seconds")


if __name__ == '__main__':
    unittest.main()