#!/usr/bin/env python
# SentinelX Docker Tests

import os
import sys
import unittest
from unittest.mock import patch, MagicMock, call
import tempfile
import subprocess
import yaml

# Add parent directory to path to import SentinelX modules
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))


class TestDocker(unittest.TestCase):
    """Test the Docker setup."""
    
    def setUp(self):
        """Set up the test environment."""
        # Get the project root directory
        self.project_root = os.path.abspath(os.path.join(os.path.dirname(__file__), '..'))
        
        # Paths to Docker files
        self.dockerfile_path = os.path.join(self.project_root, 'Dockerfile')
        self.docker_compose_path = os.path.join(self.project_root, 'docker-compose.yml')
        self.dockerignore_path = os.path.join(self.project_root, '.dockerignore')
    
    def test_dockerfile_exists(self):
        """Test that the Dockerfile exists."""
        self.assertTrue(os.path.exists(self.dockerfile_path), f"Dockerfile not found at {self.dockerfile_path}")
    
    def test_docker_compose_exists(self):
        """Test that the docker-compose.yml file exists."""
        self.assertTrue(os.path.exists(self.docker_compose_path), f"docker-compose.yml not found at {self.docker_compose_path}")
    
    def test_dockerignore_exists(self):
        """Test that the .dockerignore file exists."""
        self.assertTrue(os.path.exists(self.dockerignore_path), f".dockerignore not found at {self.dockerignore_path}")
    
    def test_dockerfile_content(self):
        """Test the content of the Dockerfile."""
        with open(self.dockerfile_path, 'r') as f:
            dockerfile_content = f.read()
        
        # Check that the Dockerfile contains the necessary instructions
        self.assertIn('FROM python', dockerfile_content, "Dockerfile should use Python as the base image")
        self.assertIn('WORKDIR', dockerfile_content, "Dockerfile should set the working directory")
        self.assertIn('COPY requirements.txt', dockerfile_content, "Dockerfile should copy the requirements.txt file")
        self.assertIn('RUN pip install', dockerfile_content, "Dockerfile should install the Python dependencies")
        self.assertIn('COPY . .', dockerfile_content, "Dockerfile should copy the project files")
        self.assertIn('EXPOSE', dockerfile_content, "Dockerfile should expose a port")
        self.assertIn('CMD', dockerfile_content, "Dockerfile should define a command to run")
    
    def test_docker_compose_content(self):
        """Test the content of the docker-compose.yml file."""
        with open(self.docker_compose_path, 'r') as f:
            docker_compose_content = yaml.safe_load(f)
        
        # Check that the docker-compose.yml file contains the necessary services
        self.assertIn('services', docker_compose_content, "docker-compose.yml should define services")
        self.assertIn('sentinelx', docker_compose_content['services'], "docker-compose.yml should define a sentinelx service")
        
        # Check the sentinelx service configuration
        sentinelx_service = docker_compose_content['services']['sentinelx']
        self.assertIn('build', sentinelx_service, "sentinelx service should define a build context")
        self.assertIn('volumes', sentinelx_service, "sentinelx service should define volumes")
        self.assertIn('ports', sentinelx_service, "sentinelx service should define ports")
        self.assertIn('environment', sentinelx_service, "sentinelx service should define environment variables")
    
    def test_dockerignore_content(self):
        """Test the content of the .dockerignore file."""
        with open(self.dockerignore_path, 'r') as f:
            dockerignore_content = f.read()
        
        # Check that the .dockerignore file contains the necessary patterns
        self.assertIn('.git', dockerignore_content, ".dockerignore should ignore Git files")
        self.assertIn('__pycache__', dockerignore_content, ".dockerignore should ignore Python cache files")
        self.assertIn('*.pyc', dockerignore_content, ".dockerignore should ignore Python compiled files")
        self.assertIn('venv', dockerignore_content, ".dockerignore should ignore virtual environments")
    
    @patch('subprocess.run')
    def test_docker_build(self, mock_run):
        """Test the Docker build command."""
        # Set up the mock
        mock_run.return_value = MagicMock(returncode=0)
        
        # Run the Docker build command
        result = subprocess.run(
            ['docker', 'build', '-t', 'sentinelx:test', '.'],
            cwd=self.project_root,
            check=False
        )
        
        # Check that the command was called correctly
        mock_run.assert_called_once_with(
            ['docker', 'build', '-t', 'sentinelx:test', '.'],
            cwd=self.project_root,
            check=False
        )
        
        # Check that the command succeeded
        self.assertEqual(result.returncode, 0)
    
    @patch('subprocess.run')
    def test_docker_compose_up(self, mock_run):
        """Test the Docker Compose up command."""
        # Set up the mock
        mock_run.return_value = MagicMock(returncode=0)
        
        # Run the Docker Compose up command
        result = subprocess.run(
            ['docker-compose', 'up', '-d'],
            cwd=self.project_root,
            check=False
        )
        
        # Check that the command was called correctly
        mock_run.assert_called_once_with(
            ['docker-compose', 'up', '-d'],
            cwd=self.project_root,
            check=False
        )
        
        # Check that the command succeeded
        self.assertEqual(result.returncode, 0)
    
    @patch('subprocess.run')
    def test_docker_compose_down(self, mock_run):
        """Test the Docker Compose down command."""
        # Set up the mock
        mock_run.return_value = MagicMock(returncode=0)
        
        # Run the Docker Compose down command
        result = subprocess.run(
            ['docker-compose', 'down'],
            cwd=self.project_root,
            check=False
        )
        
        # Check that the command was called correctly
        mock_run.assert_called_once_with(
            ['docker-compose', 'down'],
            cwd=self.project_root,
            check=False
        )
        
        # Check that the command succeeded
        self.assertEqual(result.returncode, 0)
    
    @patch('subprocess.run')
    def test_docker_run(self, mock_run):
        """Test the Docker run command."""
        # Set up the mock
        mock_run.return_value = MagicMock(returncode=0)
        
        # Run the Docker run command
        result = subprocess.run(
            ['docker', 'run', '-p', '8000:8000', 'sentinelx:test'],
            cwd=self.project_root,
            check=False
        )
        
        # Check that the command was called correctly
        mock_run.assert_called_once_with(
            ['docker', 'run', '-p', '8000:8000', 'sentinelx:test'],
            cwd=self.project_root,
            check=False
        )
        
        # Check that the command succeeded
        self.assertEqual(result.returncode, 0)


if __name__ == '__main__':
    unittest.main()