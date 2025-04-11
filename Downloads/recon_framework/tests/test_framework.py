#!/usr/bin/env python3
"""
Test script for the Automated Reconnaissance and Vulnerability Scanning Framework.
This script tests the functionality of each module with mock data.
"""

import os
import sys
import logging
import json
from datetime import datetime
from pymongo import MongoClient
import unittest
from unittest.mock import patch, MagicMock

# Add parent directory to path to import modules
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

# Import modules to test
from recon_framework.utils import config_loader, config_validator, db_handler
from recon_framework.subdomain_enum import subdomain_enumeration
from recon_framework.host_discovery import host_discovery
from recon_framework.scan import vulnerability_scan
from recon_framework.notification import notification_handler

# Setup logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler(f"test_framework_{datetime.now().strftime('%Y%m%d_%H%M%S')}.log"),
        logging.StreamHandler()
    ]
)
logger = logging.getLogger(__name__)

class TestReconFramework(unittest.TestCase):
    """Test cases for the Reconnaissance Framework."""
    
    def setUp(self):
        """Set up test environment."""
        # Create mock configuration
        self.config = {
            'mongodb': {
                'host': 'localhost',
                'port': '27017',
                'database': 'recon_framework_test'
            },
            'targets': {
                'domains': ['example.com', 'example.org']
            },
            'tools': {
                'subfinder': '/usr/bin/subfinder',
                'assetfinder': '/usr/bin/assetfinder',
                'naabu': '/usr/bin/naabu',
                'nuclei': '/usr/bin/nuclei'
            },
            'virustotal': {
                'api_key': ['test_api_key']
            },
            'gmail': {
                'username': 'test@example.com',
                'password': 'test_password'
            },
            'discord': {
                'webhook_url': 'https://discord.com/api/webhooks/test'
            },
            'acunetix': {
                'servers': [
                    {'url': 'https://acunetix_server1', 'api_key': 'test_api_key1'}
                ]
            }
        }
        
        # Create mock database client
        self.db_client = MagicMock()
        self.db = MagicMock()
        self.db_client.__getitem__.return_value = self.db
        
        # Create mock collections
        self.subdomains_monitor = MagicMock()
        self.new_discovered_subdomains = MagicMock()
        self.new_hosts_discovered = MagicMock()
        self.notifications = MagicMock()
        
        # Set up mock collections in mock database
        self.db.subdomains_monitor = self.subdomains_monitor
        self.db.new_discovered_subdomains = self.new_discovered_subdomains
        self.db.new_hosts_discovered = self.new_hosts_discovered
        self.db.notifications = self.notifications
        
        logger.info("Test environment set up")
    
    def test_config_validator(self):
        """Test configuration validator."""
        logger.info("Testing configuration validator")
        
        # Test valid configuration
        is_valid, missing_settings = config_validator.validate_config(self.config)
        self.assertTrue(is_valid)
        self.assertEqual(len(missing_settings), 0)
        
        # Test invalid configuration
        invalid_config = {
            'mongodb': {
                'host': 'localhost'
                # Missing port and database
            }
        }
        is_valid, missing_settings = config_validator.validate_config(invalid_config)
        self.assertFalse(is_valid)
        self.assertGreater(len(missing_settings), 0)
        
        logger.info("Configuration validator test completed")
    
    @patch('subprocess.check_output')
    def test_subdomain_enumeration(self, mock_subprocess):
        """Test subdomain enumeration module."""
        logger.info("Testing subdomain enumeration module")
        
        # Mock subprocess output for subfinder and assetfinder
        mock_subprocess.side_effect = [
            "sub1.example.com\nsub2.example.com",  # subfinder output
            "sub2.example.com\nsub3.example.com"   # assetfinder output
        ]
        
        # Mock find_one to return None (no existing domain record)
        self.subdomains_monitor.find_one.return_value = None
        
        # Run subdomain enumeration
        with patch('os.path.exists', return_value=True):  # Mock tool existence
            results = subdomain_enumeration.run(self.config, self.db_client)
        
        # Verify results
        self.assertIn('new_subdomains', results)
        self.assertGreater(len(results['new_subdomains']), 0)
        
        # Verify database operations
        self.subdomains_monitor.find_one.assert_called()
        self.subdomains_monitor.insert_one.assert_called()
        self.new_discovered_subdomains.insert_one.assert_called()
        
        logger.info("Subdomain enumeration test completed")
    
    @patch('subprocess.check_output')
    def test_host_discovery(self, mock_subprocess):
        """Test host discovery module."""
        logger.info("Testing host discovery module")
        
        # Mock subprocess output for naabu
        mock_subprocess.return_value = "example.com:80\nexample.com:443"
        
        # Mock find to return test subdomains
        self.new_discovered_subdomains.find.return_value.sort.return_value.limit.return_value = [
            {'subdomain': 'example.com'},
            {'subdomain': 'sub.example.com'}
        ]
        
        # Mock find_one to return None (no existing host record)
        self.new_hosts_discovered.find_one.return_value = None
        
        # Run host discovery
        with patch('os.path.exists', return_value=True):  # Mock tool existence
            results = host_discovery.run(self.config, self.db_client)
        
        # Verify results
        self.assertIn('new_hosts', results)
        self.assertGreater(len(results['new_hosts']), 0)
        
        # Verify database operations
        self.new_discovered_subdomains.find.assert_called()
        self.new_hosts_discovered.find_one.assert_called()
        self.new_hosts_discovered.insert_one.assert_called()
        
        logger.info("Host discovery test completed")
    
    def test_vulnerability_scan(self):
        """Test vulnerability scan module."""
        logger.info("Testing vulnerability scan module")
        
        # Mock find to return test hosts
        self.new_hosts_discovered.find.return_value.sort.return_value.limit.return_value = [
            {
                '_id': 'host1',
                'subdomain': 'example.com',
                'port': 80,
                'acunetix_scanned': False,
                'nuclei_scanned': False
            },
            {
                '_id': 'host2',
                'subdomain': 'sub.example.com',
                'port': 443,
                'acunetix_scanned': False,
                'nuclei_scanned': False
            }
        ]
        
        # Run vulnerability scan with mocked subprocess and requests
        with patch('subprocess.run'), \
             patch('subprocess.check_output'), \
             patch('requests.post'), \
             patch('os.path.exists', return_value=True), \
             patch('json.loads', return_value={}):
            
            # Force the acunetix scan to update the database
            with patch.object(vulnerability_scan, 'run_acunetix_scans', return_value=[{'test': 'vulnerability'}]):
                results = vulnerability_scan.run(self.config, self.db_client)
        
        # Verify results
        self.assertIn('vulnerabilities', results)
        
        # Verify database operations
        self.new_hosts_discovered.find.assert_called()
        self.new_hosts_discovered.update_one.assert_called()
        
        logger.info("Vulnerability scan test completed")
    
    def test_notification_handler(self):
        """Test notification handler module."""
        logger.info("Testing notification handler module")
        
        # Create mock scan results
        scan_results = {
            'vulnerabilities': [
                {
                    'host': 'example.com:80',
                    'vulnerability_type': 'XSS',
                    'severity': 'high',
                    'description': 'Cross-site scripting vulnerability',
                    'source': 'acunetix'
                },
                {
                    'host': 'sub.example.com:443',
                    'vulnerability_type': 'SQL Injection',
                    'severity': 'critical',
                    'description': 'SQL injection vulnerability',
                    'source': 'nuclei'
                }
            ]
        }
        
        # Run notification handler with mocked smtplib and discord_webhook
        with patch('smtplib.SMTP'), \
             patch('discord_webhook.DiscordWebhook.execute'):
            results = notification_handler.send_notifications(self.config, self.db_client, scan_results)
        
        # Verify results
        self.assertIn('notifications_sent', results)
        self.assertGreater(results['notifications_sent'], 0)
        
        # Verify database operations
        self.db.notifications.insert_one.assert_called()
        
        logger.info("Notification handler test completed")
    
    def test_integration(self):
        """Test integration of all modules."""
        logger.info("Testing integration of all modules")
        
        # Mock all necessary functions and methods
        with patch('recon_framework.subdomain_enum.subdomain_enumeration.run') as mock_subdomain, \
             patch('recon_framework.host_discovery.host_discovery.run') as mock_host, \
             patch('recon_framework.scan.vulnerability_scan.run') as mock_scan, \
             patch('recon_framework.notification.notification_handler.send_notifications') as mock_notify:
            
            # Set up mock return values
            mock_subdomain.return_value = {'new_subdomains': ['sub1.example.com', 'sub2.example.com']}
            mock_host.return_value = {'new_hosts': ['sub1.example.com:80', 'sub2.example.com:443']}
            mock_scan.return_value = {'vulnerabilities': [{'host': 'sub1.example.com:80', 'severity': 'high'}]}
            mock_notify.return_value = {'notifications_sent': 2}
            
            # Import main module
            from recon_framework.main import main
            
            # Mock command line arguments
            with patch('sys.argv', ['main.py', '--verbose']), \
                 patch('recon_framework.utils.config_loader.load_config', return_value=self.config), \
                 patch('recon_framework.utils.db_handler.initialize_db', return_value=self.db_client), \
                 patch('sys.exit'):
                
                # Run main function
                main()
            
            # Verify all modules were called
            mock_subdomain.assert_called_once()
            mock_host.assert_called_once()
            mock_scan.assert_called_once()
            mock_notify.assert_called_once()
        
        logger.info("Integration test completed")

if __name__ == '__main__':
    unittest.main()
