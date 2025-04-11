"""
Configuration validator utility for the reconnaissance framework.
Validates configuration settings to ensure all required values are present.
"""

import logging

logger = logging.getLogger(__name__)

def validate_config(config):
    """
    Validate configuration settings.
    
    Args:
        config (dict): Configuration dictionary
        
    Returns:
        tuple: (is_valid, missing_settings)
    """
    logger.info("Validating configuration settings")
    
    missing_settings = []
    
    # Check MongoDB configuration
    mongodb_config = config.get('mongodb', {})
    if not mongodb_config.get('host'):
        missing_settings.append('mongodb.host')
    if not mongodb_config.get('port'):
        missing_settings.append('mongodb.port')
    if not mongodb_config.get('database'):
        missing_settings.append('mongodb.database')
    
    # Check target domains
    targets_config = config.get('targets', {})
    if not targets_config.get('domains') or len(targets_config.get('domains', [])) == 0:
        missing_settings.append('targets.domains')
    
    # Check tool paths
    tools_config = config.get('tools', {})
    if not tools_config.get('subfinder') and not tools_config.get('assetfinder'):
        missing_settings.append('tools.subfinder or tools.assetfinder')
    if not tools_config.get('naabu'):
        missing_settings.append('tools.naabu')
    if not tools_config.get('nuclei'):
        missing_settings.append('tools.nuclei')
    
    # Check notification settings
    gmail_config = config.get('gmail', {})
    discord_config = config.get('discord', {})
    
    if not gmail_config.get('username') or not gmail_config.get('password'):
        logger.warning("Gmail credentials not configured. Urgent email notifications will not be sent.")
    
    if not discord_config.get('webhook_url'):
        logger.warning("Discord webhook URL not configured. Discord notifications will not be sent.")
    
    # Check if any notification method is configured
    if (not gmail_config.get('username') or not gmail_config.get('password')) and not discord_config.get('webhook_url'):
        missing_settings.append('gmail credentials or discord.webhook_url')
    
    # Log validation results
    if missing_settings:
        logger.error(f"Configuration validation failed. Missing settings: {', '.join(missing_settings)}")
        return False, missing_settings
    else:
        logger.info("Configuration validation successful")
        return True, []

def get_minimal_config_example():
    """
    Get a minimal configuration example.
    
    Returns:
        str: Minimal configuration example
    """
    return """[mongodb]
host = localhost
port = 27017
database = recon_framework

[targets]
domains = ["example.com", "example.org"]

[tools]
subfinder = /usr/bin/subfinder
naabu = /usr/bin/naabu
nuclei = /usr/bin/nuclei

[discord]
webhook_url = https://discord.com/api/webhooks/your_webhook_url
"""

def get_full_config_example():
    """
    Get a full configuration example.
    
    Returns:
        str: Full configuration example
    """
    return """[mongodb]
host = localhost
port = 27017
database = recon_framework
username = your_mongodb_username
password = your_mongodb_password

[virustotal]
api_key = ["your_virustotal_api_key1", "your_virustotal_api_key2"]

[gmail]
username = your_gmail_username
password = your_gmail_password

[discord]
webhook_url = https://discord.com/api/webhooks/your_webhook_url

[acunetix]
servers = [
    {"url": "https://acunetix_server1", "api_key": "your_acunetix_api_key1"},
    {"url": "https://acunetix_server2", "api_key": "your_acunetix_api_key2"}
]

[nuclei]
templates_path = /path/to/your/nuclei-templates/

[tools]
subfinder = /usr/bin/subfinder
assetfinder = /usr/bin/assetfinder
naabu = /usr/bin/naabu
nuclei = /usr/bin/nuclei

[targets]
domains = ["example.com", "example.org"]
"""
